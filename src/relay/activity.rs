use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone)]
pub(crate) struct RelayActivity {
    last_activity: Arc<Mutex<Instant>>,
}

impl RelayActivity {
    pub(crate) fn new() -> Self {
        Self {
            last_activity: Arc::new(Mutex::new(Instant::now())),
        }
    }

    pub(crate) fn mark(&self) {
        if let Ok(mut last_activity) = self.last_activity.lock() {
            *last_activity = Instant::now();
        }
    }

    pub(crate) fn idle_for(&self) -> Duration {
        let last_activity = *self
            .last_activity
            .lock()
            .expect("relay activity mutex poisoned");
        last_activity.elapsed()
    }
}

pub(crate) fn idle_check_interval(idle_timeout: Duration) -> Duration {
    idle_timeout
        .div_f64(4.0)
        .clamp(Duration::from_secs(1), Duration::from_secs(5))
}

pub(crate) async fn copy_bidirectional_with_idle_timeout<A, B>(
    a: &mut A,
    b: &mut B,
    idle_timeout: Duration,
) -> Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let activity = RelayActivity::new();
    let mut tracked_a = ActivityStream {
        inner: a,
        activity: activity.clone(),
    };
    let mut tracked_b = ActivityStream {
        inner: b,
        activity: activity.clone(),
    };
    let copy = tokio::io::copy_bidirectional(&mut tracked_a, &mut tracked_b);
    tokio::pin!(copy);

    let mut interval = tokio::time::interval(idle_check_interval(idle_timeout));

    loop {
        tokio::select! {
            result = &mut copy => return result.map_err(Into::into),
            _ = interval.tick() => {
                let idle_for = activity.idle_for();
                if idle_for >= idle_timeout {
                    return Err(anyhow::anyhow!(
                        "relay idle timeout after {:.2}s",
                        idle_for.as_secs_f64()
                    ));
                }
            }
        }
    }
}

struct ActivityStream<'a, T> {
    inner: &'a mut T,
    activity: RelayActivity,
}

impl<T> AsyncRead for ActivityStream<'_, T>
where
    T: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut *self.inner).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.activity.mark();
        }
        result
    }
}

impl<T> AsyncWrite for ActivityStream<'_, T>
where
    T: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = std::pin::Pin::new(&mut *self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            if n > 0 {
                self.activity.mark();
            }
        }
        result
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}
