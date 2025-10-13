/// Replay protection using a sliding window
///
/// WireGuard uses a sliding window of approximately 2000 prior counter values
/// to detect and reject replayed packets while allowing out-of-order delivery.
///
/// Implementation follows RFC 6479 principles with a bitmap-based approach.
const WINDOW_SIZE: usize = 2048;

#[derive(Debug, Clone)]
pub struct ReplayWindow {
    /// Highest counter value seen so far
    highest_counter: u64,
    /// Bitmap tracking received counters within the window
    /// Bit 0 represents (highest - 1), bit 1 represents (highest - 2), etc.
    /// Each u64 holds 64 bits, so we need WINDOW_SIZE/64 elements
    bitmap: [u64; WINDOW_SIZE / 64],
    /// Whether any packets have been received yet
    initialized: bool,
}

impl ReplayWindow {
    /// Create a new replay window
    pub fn new() -> Self {
        Self {
            highest_counter: 0,
            bitmap: [0; WINDOW_SIZE / 64],
            initialized: false,
        }
    }

    /// Check if a counter value should be accepted
    ///
    /// Returns true if the counter is valid and not a replay
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        // Special case: First packet (window is uninitialized)
        if !self.initialized {
            self.highest_counter = counter;
            self.initialized = true;
            return true;
        }

        // Case 1: Counter is higher than anything we've seen
        if counter > self.highest_counter {
            let delta = counter - self.highest_counter;

            // If the jump is larger than our window, reset the bitmap
            if delta >= WINDOW_SIZE as u64 {
                self.bitmap = [0; WINDOW_SIZE / 64];
            } else {
                // Shift the bitmap to make room for new counters
                // After shifting, we need to set the bit for highest_counter
                self.shift_bitmap_and_mark(delta as usize);
            }

            self.highest_counter = counter;
            return true;
        }

        // Case 2: Counter is equal to highest (replay)
        if counter == self.highest_counter {
            return false;
        }

        // Case 3: Counter is within the window
        let delta = self.highest_counter - counter;

        if delta > WINDOW_SIZE as u64 {
            // Counter is too old, reject
            return false;
        }

        // The window tracks counters [highest_counter - WINDOW_SIZE, highest_counter - 1]
        // Position in bitmap: bit 0 = highest - 1, bit 1 = highest - 2, etc.
        // So counter at delta d from highest is at bit position (d - 1)
        let bit_pos = (delta - 1) as usize;
        let block_idx = bit_pos / 64;
        let bit_idx = bit_pos % 64;

        if self.bitmap[block_idx] & (1u64 << bit_idx) != 0 {
            // Already seen this counter, reject replay
            return false;
        }

        // Mark this counter as seen
        self.bitmap[block_idx] |= 1u64 << bit_idx;
        true
    }

    /// Shift the bitmap left by delta positions and mark the old highest counter
    fn shift_bitmap_and_mark(&mut self, delta: usize) {
        if delta == 0 {
            return;
        }

        if delta >= WINDOW_SIZE {
            self.bitmap = [0; WINDOW_SIZE / 64];
            // Mark bit 0 for the previous highest counter
            self.bitmap[0] |= 1;
            return;
        }

        // Shift left by delta bits
        let block_shift = delta / 64;
        let bit_shift = delta % 64;

        if bit_shift == 0 {
            // Block-aligned shift
            for i in (block_shift..self.bitmap.len()).rev() {
                self.bitmap[i] = self.bitmap[i - block_shift];
            }
            for i in 0..block_shift {
                self.bitmap[i] = 0;
            }
        } else {
            // Shift with bit offset
            for i in (block_shift + 1..self.bitmap.len()).rev() {
                self.bitmap[i] = (self.bitmap[i - block_shift] << bit_shift)
                    | (self.bitmap[i - block_shift - 1] >> (64 - bit_shift));
            }
            if block_shift < self.bitmap.len() {
                self.bitmap[block_shift] = self.bitmap[0] << bit_shift;
            }
            for i in 0..block_shift {
                self.bitmap[i] = 0;
            }
        }

        // After shifting, mark bit (delta - 1) as seen (representing the old highest counter)
        // This counter is now at position (delta - 1) in the bitmap
        let mark_pos = delta - 1;
        let block_idx = mark_pos / 64;
        let bit_idx = mark_pos % 64;
        self.bitmap[block_idx] |= 1u64 << bit_idx;
    }

    /// Get the highest counter seen
    pub fn highest_counter(&self) -> u64 {
        self.highest_counter
    }
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_window() {
        let window = ReplayWindow::new();
        assert_eq!(window.highest_counter(), 0);
    }

    #[test]
    fn test_accept_zero_counter() {
        let mut window = ReplayWindow::new();
        // Counter 0 is the first valid counter
        assert!(window.check_and_update(0));
        assert_eq!(window.highest_counter(), 0);

        // Replay of counter 0 should be rejected
        assert!(!window.check_and_update(0));
    }

    #[test]
    fn test_sequential_counters() {
        let mut window = ReplayWindow::new();

        // Accept sequential counters
        assert!(window.check_and_update(1));
        assert_eq!(window.highest_counter(), 1);

        assert!(window.check_and_update(2));
        assert_eq!(window.highest_counter(), 2);

        assert!(window.check_and_update(3));
        assert_eq!(window.highest_counter(), 3);
    }

    #[test]
    fn test_reject_replay() {
        let mut window = ReplayWindow::new();

        assert!(window.check_and_update(1));
        assert!(window.check_and_update(2));
        assert!(window.check_and_update(3));

        // Try to replay counter 2
        assert!(!window.check_and_update(2));

        // Try to replay counter 1
        assert!(!window.check_and_update(1));

        // Try to replay counter 3
        assert!(!window.check_and_update(3));
    }

    #[test]
    fn test_out_of_order_within_window() {
        let mut window = ReplayWindow::new();

        assert!(window.check_and_update(10));
        assert_eq!(window.highest_counter(), 10);

        // Accept out-of-order within window
        assert!(window.check_and_update(5));
        assert!(window.check_and_update(8));
        assert!(window.check_and_update(3));

        // Reject replays
        assert!(!window.check_and_update(5));
        assert!(!window.check_and_update(8));
        assert!(!window.check_and_update(10));
    }

    #[test]
    fn test_counter_too_old() {
        let mut window = ReplayWindow::new();

        // Advance window significantly
        assert!(window.check_and_update(3000));

        // Counter way outside window should be rejected
        assert!(!window.check_and_update(500));
    }

    #[test]
    fn test_large_jump() {
        let mut window = ReplayWindow::new();

        assert!(window.check_and_update(100));

        // Jump larger than window size should reset
        assert!(window.check_and_update(100 + WINDOW_SIZE as u64 + 100));

        // Old counter now outside window
        assert!(!window.check_and_update(100));
    }

    #[test]
    fn test_window_edges() {
        let mut window = ReplayWindow::new();

        assert!(window.check_and_update(WINDOW_SIZE as u64));

        // At the edge of the window
        assert!(window.check_and_update(1));

        // Move window forward
        assert!(window.check_and_update(WINDOW_SIZE as u64 + 1));

        // Now 1 should still be at the edge (within window)
        assert!(!window.check_and_update(1)); // Already received

        // Counter 2 is outside the window now (WINDOW_SIZE + 1 - 2 = WINDOW_SIZE - 1, barely inside)
        assert!(window.check_and_update(2));
    }

    #[test]
    fn test_full_window() {
        let mut window = ReplayWindow::new();

        // Fill the entire window
        assert!(window.check_and_update(WINDOW_SIZE as u64));

        for i in 1..WINDOW_SIZE as u64 {
            assert!(window.check_and_update(i));
        }

        // All should be marked as seen now
        for i in 1..=WINDOW_SIZE as u64 {
            assert!(!window.check_and_update(i));
        }
    }

    #[test]
    fn test_wrapping_behavior() {
        let mut window = ReplayWindow::new();

        // Test behavior near u64 max (though unlikely in practice)
        let start = u64::MAX - 100;

        assert!(window.check_and_update(start));
        assert!(window.check_and_update(start + 1));
        assert!(window.check_and_update(start + 2));

        // Replay detection should still work
        assert!(!window.check_and_update(start));
        assert!(!window.check_and_update(start + 1));
    }
}
