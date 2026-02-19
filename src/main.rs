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

use crate::config::Config;
use crate::http::server::{HttpState, SharedState};
use crate::relay::outbound_grpc::GrpcPool;
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
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new(&cfg.log_level)),
        )
        .init();

    tracing::info!("loaded config from {:?}", config_path);

    let (validator_rw, http_state_rw) = build_state(&cfg).await?;

    // Keep current config accessible so the subscription timer can re-fetch
    // without re-reading the config file.
    let shared_cfg: Arc<RwLock<Config>> = Arc::new(RwLock::new(cfg));

    // Shared gRPC pool
    let grpc_pool = Arc::new(GrpcPool::new()?);

    // Start relay listener
    let relay_addr: SocketAddr = {
        let c = shared_cfg.read().await;
        format!("{}:{}", c.relay.listen, c.relay.port).parse()?
    };
    {
        let validator = validator_rw.clone();
        let pool = grpc_pool.clone();
        tokio::spawn(async move {
            if let Err(e) = relay::listener::run(relay_addr, validator, pool).await {
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
    {
        let tx = full_reload_tx.clone();
        let path = config_path.clone();
        tokio::task::spawn_blocking(move || {
            watch_file(path, tx);
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
    loop {
        tokio::select! {
            _ = quit_rx.recv() => {
                tracing::info!("shutdown signal received");
                break;
            }
            Some(()) = full_reload_rx.recv() => {
                tracing::info!("reloading configuration and subscriptions…");
                match reload_full(&config_path, &shared_cfg, &validator_rw, &http_state_rw).await {
                    Ok(n) => tracing::info!("full reload complete: {} nodes", n),
                    Err(e) => tracing::error!("full reload failed: {}", e),
                }
            }
            Some(()) = subs_reload_rx.recv() => {
                tracing::info!("reloading subscriptions…");
                match reload_subs(&shared_cfg, &validator_rw, &http_state_rw).await {
                    Ok(n) => tracing::info!("subscription reload complete: {} nodes", n),
                    Err(e) => tracing::error!("subscription reload failed: {}", e),
                }
            }
        }
    }

    tracing::info!("tobira exiting");
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
    let http_state = HttpState {
        users: cfg.http.users.clone(),
        outputs: cfg.http.outputs.clone(),
        nodes,
    };
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
) -> Result<usize> {
    let cfg = config::load(config_path)?;
    let manager = SubscriptionManager::new(cfg.subscription.clone());
    manager.reload().await?;

    let new_validator = manager.build_validator().await?;
    let nodes = manager.all_nodes().await;
    let n = nodes.len();

    *shared_cfg.write().await = cfg.clone();
    *validator_rw.write().await = new_validator;
    {
        let mut s = http_state_rw.write().await;
        s.users = cfg.http.users;
        s.outputs = cfg.http.outputs;
        s.nodes = nodes;
    }

    Ok(n)
}

// ──────────────────────────────────────────────────────────────────────────────
// Subscription reload — uses current in-memory config, only re-fetches sources
// Updates: validator, nodes only — does NOT touch HTTP users/outputs or config
// ──────────────────────────────────────────────────────────────────────────────

async fn reload_subs(
    shared_cfg: &Arc<RwLock<Config>>,
    validator_rw: &ValidatorRw,
    http_state_rw: &SharedState,
) -> Result<usize> {
    let sub_cfg = shared_cfg.read().await.subscription.clone();
    let manager = SubscriptionManager::new(sub_cfg);
    manager.reload().await?;

    let new_validator = manager.build_validator().await?;
    let nodes = manager.all_nodes().await;
    let n = nodes.len();

    *validator_rw.write().await = new_validator;
    http_state_rw.write().await.nodes = nodes;

    Ok(n)
}

// ──────────────────────────────────────────────────────────────────────────────
// File watcher (blocking, runs in spawn_blocking)
// ──────────────────────────────────────────────────────────────────────────────

fn watch_file(path: String, tx: tokio::sync::mpsc::Sender<()>) {
    use notify::{Config, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

    let (ntx, nrx) = std::sync::mpsc::channel();
    let mut watcher = match RecommendedWatcher::new(ntx, Config::default()) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("file watcher init failed: {}", e);
            return;
        }
    };

    if let Err(e) = watcher.watch(std::path::Path::new(&path), RecursiveMode::NonRecursive) {
        tracing::warn!("file watcher watch failed: {}", e);
        return;
    }

    tracing::debug!("watching {:?} for changes", path);

    for event in nrx {
        match event {
            Ok(ev) => {
                if matches!(ev.kind, EventKind::Modify(_) | EventKind::Create(_)) {
                    tracing::info!("config file changed — triggering full reload");
                    let _ = tx.blocking_send(());
                }
            }
            Err(e) => tracing::warn!("file watch error: {}", e),
        }
    }
}
