// src/server/sse.rs
use axum::{
    extract::State,
    response::sse::{self, Sse},
};
use futures_util::Stream;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

use crate::server::routes::AppState;

/// Wrap the broadcast sender so that each SSE client gets its own receiver.
pub async fn sse_handler(
    State(state): State<AppState>,
) -> Sse<impl Stream<Item = Result<sse::Event, std::io::Error>>> {
    let mut rx = state.sse_tx.subscribe();

    let stream = async_stream::stream! {
        // Keep-alive comment every 15 s in case the client is idle.
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        loop {
            tokio::select! {
                result = rx.recv() => {
                    match result {
                        Ok(event) => {
                            let payload = serde_json::to_string(&event).unwrap_or_default();
                            yield Ok(sse::Event::default().data(payload));
                        }
                        Err(RecvError::Lagged(skipped)) => {
                            tracing::warn!("SSE client lagged; skipped {} events.", skipped);
                        }
                        Err(RecvError::Closed) => break,
                    }
                }
                _ = interval.tick() => {
                    yield Ok(sse::Event::default().comment("keep-alive"));
                }
            }
        }
    };

    Sse::new(stream).keep_alive(sse::KeepAlive::new().interval(Duration::from_secs(15)))
}
