use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use log::warn;

fn current_minute_bucket(now: SystemTime) -> u64 {
    now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs() / 60
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RateLimitWindow {
    minute_bucket: u64,
    request_count: u32,
}

#[derive(Debug, Default)]
pub(crate) struct FixedWindowRateLimiter {
    state: Mutex<FixedWindowRateLimiterState>,
}

#[derive(Debug, Default)]
struct FixedWindowRateLimiterState {
    last_cleanup_bucket: Option<u64>,
    windows: HashMap<IpAddr, RateLimitWindow>,
}

impl FixedWindowRateLimiter {
    fn lock_state(&self) -> MutexGuard<'_, FixedWindowRateLimiterState> {
        self.state.lock().unwrap_or_else(|poisoned| {
            warn!("edge_proxy rate limiter mutex poisoned; recovering inner state");
            poisoned.into_inner()
        })
    }

    pub(crate) fn allow(&self, client_ip: IpAddr, limit: u32, now: SystemTime) -> bool {
        let current_bucket = current_minute_bucket(now);
        let mut state = self.lock_state();

        if state.last_cleanup_bucket != Some(current_bucket) {
            state
                .windows
                .retain(|_, window| window.minute_bucket == current_bucket);
            state.last_cleanup_bucket = Some(current_bucket);
        }

        let window = state.windows.entry(client_ip).or_insert(RateLimitWindow {
            minute_bucket: current_bucket,
            request_count: 0,
        });

        if window.minute_bucket != current_bucket {
            window.minute_bucket = current_bucket;
            window.request_count = 0;
        }

        if window.request_count >= limit {
            return false;
        }

        window.request_count += 1;
        true
    }

    #[cfg(test)]
    fn tracked_clients_len(&self) -> usize {
        self.lock_state().windows.len()
    }
}

#[cfg(test)]
#[path = "rate_limit/tests.rs"]
mod tests;
