/// No-op metrics implementation for future extension
#[derive(Debug, Default)]
pub struct Metrics;

impl Metrics {
    /// Records a counter metric (currently no-op)
    pub fn counter(&self, _name: &str, _value: u64) {}

    /// Records a gauge metric (currently no-op)
    pub fn gauge(&self, _name: &str, _value: u64) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_metrics_accepts_calls() {
        let metrics = Metrics::default();
        metrics.counter("writes", 1);
        metrics.gauge("size", 42);
    }
}
