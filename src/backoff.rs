//! Exponential backoff with jitter for reconnect logic.

use std::time::Duration;

use rand::Rng;

#[derive(Clone, Debug)]
pub struct Backoff {
    initial: Duration,
    max: Duration,
    jitter: bool,
    attempt: u32,
}

impl Backoff {
    pub fn new(initial: Duration, max: Duration, jitter: bool) -> Self {
        Self {
            initial,
            max,
            jitter,
            attempt: 0,
        }
    }

    /// Returns the next delay; bumps the attempt counter.
    pub fn next_delay(&mut self) -> Duration {
        let exp = self.attempt.min(20); // cap to avoid u128 explosion
        let raw = self.initial.saturating_mul(1u32 << exp);
        let bounded = raw.min(self.max);
        let with_jitter = if self.jitter {
            let factor: f64 = rand::thread_rng().gen_range(0.75..=1.25);
            Duration::from_secs_f64(bounded.as_secs_f64() * factor)
        } else {
            bounded
        };
        self.attempt = self.attempt.saturating_add(1);
        with_jitter
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_attempt_uses_initial() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60), false);
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }

    #[test]
    fn doubles_until_max() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(8), false);
        // 1, 2, 4, 8, 8, 8, ...
        assert_eq!(b.next_delay(), Duration::from_secs(1));
        assert_eq!(b.next_delay(), Duration::from_secs(2));
        assert_eq!(b.next_delay(), Duration::from_secs(4));
        assert_eq!(b.next_delay(), Duration::from_secs(8));
        assert_eq!(b.next_delay(), Duration::from_secs(8));
    }

    #[test]
    fn reset_returns_to_initial() {
        let mut b = Backoff::new(Duration::from_secs(1), Duration::from_secs(60), false);
        b.next_delay();
        b.next_delay();
        b.reset();
        assert_eq!(b.next_delay(), Duration::from_secs(1));
    }
}
