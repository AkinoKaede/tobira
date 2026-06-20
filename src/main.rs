/// Tobira — VMess relay daemon.
///
/// Startup flow:
///   1. Parse CLI args (--config)
///   2. Load TOML config
///   3. Fetch subscriptions, build Validator
///   4. Start relay listener
///   5. Start HTTP subscription server
///   6. Hot-reload on SIGUSR1 or config-file change (full: config + subscriptions)
///   7. Periodic subscription refresh on timer (subscriptions only, config unchanged)
mod buf;
mod config;
mod error;
mod http;
mod relay;
mod subscription;
mod vmess;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use clap::Parser;
use tokio::sync::RwLock;
use tracing_subscriber::EnvFilter;

use crate::config::{Config, RelayConfig};
use crate::http::server::{HttpState, SharedState};
use crate::relay::inbound::InboundContext;
use crate::relay::runtime::RelayRuntime;
use crate::relay::transport::grpc::GrpcPool;
use crate::subscription::manager::SubscriptionManager;
use crate::vmess::validator::Validator;

// ──────────────────────────────────────────────────────────────────────────────
// CLI
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(name = "tobira", about = "VMess relay daemon")]
struct Cli {
    /// Path to the TOML configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

// ──────────────────────────────────────────────────────────────────────────────
// Entry point
// ──────────────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let config_path = cli.config.clone();

    let cfg = config::load(&config_path)?;

    // RUST_LOG env var takes precedence over the config file setting.
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(&cfg.log_level)),
        )
        .init();

    tracing::info!("loaded config from {:?}", config_path);

    let (validator_rw, http_state_rw) = build_state(&cfg).await?;

    let relay_idle_timeout = relay_idle_timeout(cfg.relay.idle_timeout);

    // Keep current config accessible so the subscription timer can re-fetch
    // without re-reading the config file.
    let shared_cfg: Arc<RwLock<Config>> = Arc::new(RwLock::new(cfg));

    // Shared gRPC pool
    let grpc_pool = Arc::new(GrpcPool::new()?);
    let runtime = RelayRuntime::new(validator_rw.clone(), grpc_pool, relay_idle_timeout);
    {
        let grpc_pool = runtime.grpc_pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                grpc_pool.prune_idle().await;
            }
        });
    }

    // Start relay listener
    let (relay_addr, inbound) = {
        let c = shared_cfg.read().await;
        (
            format!("{}:{}", c.relay.listen, c.relay.port).parse()?,
            relay::inbound::from_config(&c.relay),
        )
    };
    {
        let ctx = InboundContext {
            addr: relay_addr,
            runtime: runtime.clone(),
        };
        tokio::spawn(async move {
            let result = inbound.run(ctx).await;

            if let Err(e) = result {
                tracing::error!("relay listener error: {}", e);
            }
        });
    }

    // Start HTTP server
    let http_addr: SocketAddr = {
        let c = shared_cfg.read().await;
        format!("{}:{}", c.http.listen, c.http.port).parse()?
    };
    {
        let state = http_state_rw.clone();
        tokio::spawn(async move {
            if let Err(e) = http::server::run(http_addr, state).await {
                tracing::error!("HTTP server error: {}", e);
            }
        });
    }

    // ── Reload channels ───────────────────────────────────────────────────────
    //
    // full_reload_tx  — re-reads config file + re-fetches subscriptions
    //                   triggered by: SIGUSR1, config file change
    //
    // subs_reload_tx  — re-fetches subscriptions using the current in-memory config
    //                   triggered by: periodic timer (subscription.reload_interval)
    //
    let (full_reload_tx, mut full_reload_rx) = tokio::sync::mpsc::channel::<()>(4);
    let (subs_reload_tx, mut subs_reload_rx) = tokio::sync::mpsc::channel::<()>(4);

    // SIGUSR1 → full reload
    {
        let tx = full_reload_tx.clone();
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                use tokio::signal::unix::{signal, SignalKind};
                if let Ok(mut sig) = signal(SignalKind::user_defined1()) {
                    loop {
                        sig.recv().await;
                        tracing::info!("SIGUSR1 received — triggering full reload");
                        let _ = tx.send(()).await;
                    }
                }
            }
        });
    }

    // Config file change → full reload
    let (watch_quit_tx, watch_quit_rx) = std::sync::mpsc::channel::<()>();
    {
        let tx = full_reload_tx.clone();
        let path = config_path.clone();
        tokio::task::spawn_blocking(move || {
            watch_file(path, tx, watch_quit_rx);
        });
    }

    // Periodic timer → subscription-only reload
    {
        let reload_interval = shared_cfg.read().await.subscription.update_interval;
        if reload_interval > 0 {
            let interval = std::time::Duration::from_secs(reload_interval);
            let tx = subs_reload_tx.clone();
            tracing::info!("subscription auto-reload every {}s", reload_interval);
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(interval).await;
                    tracing::debug!("subscription timer fired");
                    let _ = tx.send(()).await;
                }
            });
        }
    }

    // Graceful shutdown
    let (quit_tx, mut quit_rx) = tokio::sync::mpsc::channel::<()>(1);
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{signal, SignalKind};
            let mut sigterm = signal(SignalKind::terminate()).unwrap();
            let mut sigint = signal(SignalKind::interrupt()).unwrap();
            tokio::select! {
                _ = sigterm.recv() => {},
                _ = sigint.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        let _ = quit_tx.send(()).await;
    });

    // Main event loop
    'main: loop {
        tokio::select! {
            biased;
            _ = quit_rx.recv() => {
                tracing::info!("shutdown signal received");
                break;
            }
            Some(()) = full_reload_rx.recv() => {
                tracing::info!("reloading configuration and subscriptions…");
                tokio::select! {
                    biased;
                    _ = quit_rx.recv() => {
                        tracing::info!("shutdown signal received");
                        break 'main;
                    }
                    result = reload_full(&config_path, &shared_cfg, &validator_rw, &http_state_rw, &runtime) => {
                        match result {
                            Ok(n) => tracing::info!("full reload complete: {} nodes", n),
                            Err(e) => tracing::error!("full reload failed: {}", e),
                        }
                    }
                }
            }
            Some(()) = subs_reload_rx.recv() => {
                tracing::info!("reloading subscriptions…");
                tokio::select! {
                    biased;
                    _ = quit_rx.recv() => {
                        tracing::info!("shutdown signal received");
                        break 'main;
                    }
                    result = reload_subs(&shared_cfg, &validator_rw, &http_state_rw, &runtime.grpc_pool) => {
                        match result {
                            Ok(n) => tracing::info!("subscription reload complete: {} nodes", n),
                            Err(e) => tracing::error!("subscription reload failed: {}", e),
                        }
                    }
                }
            }
        }
    }

    tracing::info!("tobira exiting");
    let _ = watch_quit_tx.send(());
    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// State building
// ──────────────────────────────────────────────────────────────────────────────

type ValidatorRw = Arc<RwLock<Validator>>;

async fn build_state(cfg: &Config) -> Result<(ValidatorRw, SharedState)> {
    let manager = SubscriptionManager::new(cfg.subscription.clone());
    manager.reload().await?;

    let validator = manager.build_validator().await?;
    let nodes = manager.all_nodes().await;

    let validator_rw = Arc::new(RwLock::new(validator));
    let http_state = HttpState::new(
        cfg.http.users.clone(),
        cfg.http.outputs.clone(),
        &nodes,
        cfg.relay.network,
        &cfg.relay.service_name,
    );
    let http_state_rw = Arc::new(RwLock::new(http_state));

    Ok((validator_rw, http_state_rw))
}

// ──────────────────────────────────────────────────────────────────────────────
// Full reload — re-reads config file + re-fetches subscriptions
// Updates: validator, nodes, HTTP users, HTTP outputs, stored config
// ──────────────────────────────────────────────────────────────────────────────

async fn reload_full(
    config_path: &str,
    shared_cfg: &Arc<RwLock<Config>>,
    validator_rw: &ValidatorRw,
    http_state_rw: &SharedState,
    runtime: &RelayRuntime,
) -> Result<usize> {
    let cfg = load_config_with_retry(config_path).await?;
    let manager = SubscriptionManager::new(cfg.subscription.clone());
    manager.reload().await?;

    let new_validator = manager.build_validator().await?;
    let nodes = manager.all_nodes().await;
    let n = nodes.len();

    let running_relay = shared_cfg.read().await.relay.clone();
    let (effective_cfg, relay_changed) = preserve_running_relay(cfg, &running_relay);
    if relay_changed {
        tracing::warn!(
            current = ?running_relay,
            "relay listener settings changed in config; keeping current listener until process restart"
        );
    }

    *shared_cfg.write().await = effective_cfg.clone();
    runtime
        .set_relay_idle_timeout(relay_idle_timeout(effective_cfg.relay.idle_timeout))
        .await;
    let grpc_endpoints = new_validator.grpc_endpoints();
    *validator_rw.write().await = new_validator;
    runtime.grpc_pool.prune_to_endpoints(&grpc_endpoints).await;
    {
        let effective_relay = effective_cfg.relay.clone();
        *http_state_rw.write().await = HttpState::new(
            effective_cfg.http.users,
            effective_cfg.http.outputs,
            &nodes,
            effective_relay.network,
            &effective_relay.service_name,
        );
    }

    Ok(n)
}

fn preserve_running_relay(mut cfg: Config, running_relay: &RelayConfig) -> (Config, bool) {
    let listener_changed = cfg.relay.listen != running_relay.listen
        || cfg.relay.port != running_relay.port
        || cfg.relay.network != running_relay.network
        || cfg.relay.service_name != running_relay.service_name;
    if !listener_changed {
        return (cfg, false);
    }

    cfg.relay.listen = running_relay.listen.clone();
    cfg.relay.port = running_relay.port;
    cfg.relay.network = running_relay.network;
    cfg.relay.service_name = running_relay.service_name.clone();
    (cfg, true)
}

fn relay_idle_timeout(seconds: u64) -> Option<std::time::Duration> {
    if seconds == 0 {
        None
    } else {
        Some(std::time::Duration::from_secs(seconds))
    }
}

async fn load_config_with_retry(config_path: &str) -> Result<Config> {
    let max_attempts = 6usize;
    let retry_delay = std::time::Duration::from_millis(80);

    for attempt in 1..=max_attempts {
        match config::load(config_path) {
            Ok(cfg) => return Ok(cfg),
            Err(e) => {
                let not_found = e
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|ioe| ioe.kind() == std::io::ErrorKind::NotFound);

                if not_found && attempt < max_attempts {
                    tracing::warn!(
                        "config file temporarily unavailable, retrying ({}/{})",
                        attempt,
                        max_attempts
                    );
                    tokio::time::sleep(retry_delay).await;
                    continue;
                }

                return Err(e);
            }
        }
    }

    unreachable!()
}

// ──────────────────────────────────────────────────────────────────────────────
// Subscription reload — uses current in-memory config, only re-fetches sources
// Updates: validator, nodes only — does NOT touch HTTP users/outputs or config
// ──────────────────────────────────────────────────────────────────────────────

async fn reload_subs(
    shared_cfg: &Arc<RwLock<Config>>,
    validator_rw: &ValidatorRw,
    http_state_rw: &SharedState,
    grpc_pool: &Arc<GrpcPool>,
) -> Result<usize> {
    let sub_cfg = shared_cfg.read().await.subscription.clone();
    let manager = SubscriptionManager::new(sub_cfg);
    manager.reload().await?;

    let new_validator = manager.build_validator().await?;
    let nodes = manager.all_nodes().await;
    let n = nodes.len();

    let grpc_endpoints = new_validator.grpc_endpoints();
    *validator_rw.write().await = new_validator;
    grpc_pool.prune_to_endpoints(&grpc_endpoints).await;
    {
        let cfg = shared_cfg.read().await;
        let mut s = http_state_rw.write().await;
        *s = HttpState::new(
            s.users.clone(),
            cfg.http.outputs.clone(),
            &nodes,
            cfg.relay.network,
            &cfg.relay.service_name,
        );
    }

    Ok(n)
}

// ──────────────────────────────────────────────────────────────────────────────
// File watcher (blocking, runs in spawn_blocking)
// ──────────────────────────────────────────────────────────────────────────────

fn watch_file(
    path: String,
    tx: tokio::sync::mpsc::Sender<()>,
    quit_rx: std::sync::mpsc::Receiver<()>,
) {
    use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
    use std::path::{Path, PathBuf};

    let requested_path = PathBuf::from(&path);
    let target = if requested_path.is_absolute() {
        requested_path
    } else {
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(requested_path),
            Err(_) => PathBuf::from(path.clone()),
        }
    };
    let watch_dir = target
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));

    let (ntx, nrx) = std::sync::mpsc::channel();
    let mut watcher = match RecommendedWatcher::new(ntx, Config::default()) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("file watcher init failed: {}", e);
            return;
        }
    };

    if let Err(e) = watcher.watch(&watch_dir, RecursiveMode::NonRecursive) {
        tracing::warn!("file watcher watch failed: {}", e);
        return;
    }

    tracing::debug!(
        "watching {:?} for changes to {:?}",
        watch_dir,
        target.file_name()
    );

    loop {
        match nrx.recv_timeout(std::time::Duration::from_millis(200)) {
            Ok(Ok(ev)) => {
                let touches_target = ev.paths.iter().any(|p| {
                    let abs_path = if p.is_absolute() {
                        p.clone()
                    } else {
                        watch_dir.join(p)
                    };
                    abs_path == target
                });

                if touches_target
                    && matches!(
                        ev.kind,
                        EventKind::Modify(_)
                            | EventKind::Create(_)
                            | EventKind::Remove(_)
                            | EventKind::Any
                    )
                {
                    tracing::info!("config file changed — triggering full reload");
                    let _ = tx.blocking_send(());
                }
            }
            Ok(Err(e)) => tracing::warn!("file watch error: {}", e),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                if quit_rx.try_recv().is_ok() {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    tracing::debug!("file watcher stopped");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::RelayNetwork;

    fn config_with_relay(relay: RelayConfig) -> Config {
        Config {
            log_level: "info".to_string(),
            relay,
            http: Default::default(),
            subscription: Default::default(),
        }
    }

    #[test]
    fn preserve_running_relay_keeps_changed_listener_settings() {
        let running_relay = RelayConfig::default();
        let mut reloaded_relay = running_relay.clone();
        reloaded_relay.network = RelayNetwork::Grpc;
        reloaded_relay.service_name = "OtherService".to_string();
        reloaded_relay.idle_timeout = 300;

        let (cfg, changed) =
            preserve_running_relay(config_with_relay(reloaded_relay), &running_relay);

        assert!(changed);
        assert_eq!(cfg.relay.listen, running_relay.listen);
        assert_eq!(cfg.relay.port, running_relay.port);
        assert_eq!(cfg.relay.network, running_relay.network);
        assert_eq!(cfg.relay.service_name, running_relay.service_name);
        assert_eq!(cfg.relay.idle_timeout, 300);
    }

    #[test]
    fn preserve_running_relay_allows_unchanged_listener_settings() {
        let running_relay = RelayConfig::default();
        let (cfg, changed) =
            preserve_running_relay(config_with_relay(running_relay.clone()), &running_relay);

        assert!(!changed);
        assert_eq!(cfg.relay, running_relay);
    }

    #[test]
    fn preserve_running_relay_allows_idle_timeout_changes() {
        let running_relay = RelayConfig::default();
        let mut reloaded_relay = running_relay.clone();
        reloaded_relay.idle_timeout = 120;

        let (cfg, changed) =
            preserve_running_relay(config_with_relay(reloaded_relay), &running_relay);

        assert!(!changed);
        assert_eq!(cfg.relay.idle_timeout, 120);
    }
}
