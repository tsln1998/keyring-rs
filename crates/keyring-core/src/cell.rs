//! Minimal async cache primitives shared across the workspace.
//!
//! `CacheCell` stores at most one value together with the instant when that value was produced.
//! Callers provide a time-to-live and an async initializer; once the cached entry expires, the
//! next caller refreshes it lazily.

use std::future::Future;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

/// A read-mostly async cache for one clonable value.
///
/// The common case is a shared-lock read of a still-fresh value. When the entry is missing or has
/// expired, one caller upgrades to the write path and repopulates the cache.
///
/// # Examples
///
/// ```
/// use std::sync::Arc;
/// use std::sync::atomic::{AtomicUsize, Ordering};
/// use std::time::Duration;
///
/// use keyring_core::cell::CacheCell;
///
/// tokio::runtime::Runtime::new().unwrap().block_on(async {
///     let cache = CacheCell::default();
///     let calls = Arc::new(AtomicUsize::new(0));
///
///     let first = cache
///         .get_or_init(Duration::from_secs(60), {
///             let calls = Arc::clone(&calls);
///             move || async move {
///                 calls.fetch_add(1, Ordering::SeqCst);
///                 "value".to_owned()
///             }
///         })
///         .await;
///
///     let second = cache
///         .get_or_init(Duration::from_secs(60), {
///             let calls = Arc::clone(&calls);
///             move || async move {
///                 calls.fetch_add(1, Ordering::SeqCst);
///                 "fresh-value".to_owned()
///             }
///         })
///         .await;
///
///     assert_eq!(first, "value");
///     assert_eq!(second, "value");
///     assert_eq!(calls.load(Ordering::SeqCst), 1);
/// });
/// ```
#[derive(Debug, Default)]
pub struct CacheCell<T> {
    /// Cached value plus the timestamp recorded when that value was last refreshed.
    inner: Arc<RwLock<Option<(T, Instant)>>>,
}

impl<T: Clone> CacheCell<T> {
    /// Returns the cached value when it is still fresh, otherwise refreshes it with a fallible
    /// async initializer.
    ///
    /// Refresh failures are returned to the caller and do not overwrite an existing cached value.
    /// That behavior is useful for transient failures such as network or decryption errors.
    ///
    /// # Errors
    ///
    /// Returns the error produced by `f` when the cache is missing or stale and the refresh fails.
    pub async fn get_or_try_init<F, Fut, E>(&self, ttl: Duration, f: F) -> Result<T, E>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<T, E>>,
        T: Clone,
    {
        // Fast path: reuse a fresh cached value under a shared lock.
        {
            let guard = self.inner.read().await;

            if let Some((value, ts)) = &*guard
                && ts.elapsed() < ttl
            {
                return Ok(value.clone());
            }
        }

        // Slow path: recompute under an exclusive lock so only one task performs the refresh.
        let mut guard = self.inner.write().await;

        // Double-check after taking the write lock because another waiter may have refreshed the
        // entry while this task was waiting to enter the slow path.
        if let Some((value, ts)) = &*guard
            && ts.elapsed() < ttl
        {
            return Ok(value.clone());
        }

        let value = f().await?;

        // Store the new value together with the time it became authoritative.
        *guard = Some((value.clone(), Instant::now()));

        Ok(value)
    }
}
