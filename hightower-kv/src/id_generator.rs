use std::sync::atomic::{AtomicU64, Ordering};

/// Thread-safe monotonic ID generator
#[derive(Debug)]
pub struct IdGenerator {
    counter: AtomicU64,
}

impl IdGenerator {
    /// Creates a new ID generator starting from the given value
    pub fn new(start: u64) -> Self {
        Self {
            counter: AtomicU64::new(start),
        }
    }

    /// Returns the next ID and increments the counter
    pub fn next(&self) -> u64 {
        self.counter.fetch_add(1, Ordering::Relaxed)
    }
}

impl Default for IdGenerator {
    fn default() -> Self {
        Self::new(1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_monotonic_ids() {
        let generator = IdGenerator::new(5);
        assert_eq!(generator.next(), 5);
        assert_eq!(generator.next(), 6);
    }
}
