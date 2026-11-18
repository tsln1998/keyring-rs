//! Connection acceptance and orderly agent shutdown.

use crate::platform::{Listener, Signal};
use anyhow::Result;
use keyring_protocol::agent::Agent;
use std::{sync::Arc, time::Duration};
use tokio::{task::JoinSet, time::timeout};
use tokio_util::sync::CancellationToken;

/// Accepts clients until shutdown, then drains connections and clears the agent's stores.
pub async fn serve(path: &str, agent: Arc<Agent>) -> Result<()> {
    let mut listener = Listener::bind(path).await?;
    let mut signal = Signal::new()?;
    let mut jobs = JoinSet::new();

    let shutdown = CancellationToken::new();
    let result = loop {
        tokio::select! {
            biased;
            _ = signal.recv() => break Ok(()),
            _ = jobs.join_next(), if !jobs.is_empty() => {},
            stream = listener.accept() => {
                let stream = match stream {
                    Ok(stream) => stream,
                    Err(error) => break Err(error.into()),
                };
                let agent = Arc::clone(&agent);
                let shutdown = shutdown.clone();
                jobs.spawn(async move {
                    if agent.serve(stream, shutdown).await.is_err() {
                        tracing::debug!("client connection closed after request or transport failure");
                    }
                });
            }
        }
    };
    shutdown.cancel();
    // Let active requests finish before aborting any remaining connections.
    let _ = timeout(Duration::from_secs(30), async {
        while jobs.join_next().await.is_some() {}
    })
    .await;
    jobs.shutdown().await;
    // Wait for rollback and backend cleanup before returning the listener result.
    timeout(Duration::from_secs(30), agent.clear()).await??;
    result
}
