use tracing::subscriber::DefaultGuard;
use tracing_subscriber::{EnvFilter, fmt};

pub fn init() -> DefaultGuard {
    init_with(build_subscriber, tracing::subscriber::set_default)
}

fn build_subscriber() -> impl tracing::Subscriber + Send + Sync + 'static {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_target(false)
        .finish()
}

fn init_with<B, S, Sub, Guard>(builder: B, setter: S) -> Guard
where
    B: FnOnce() -> Sub,
    S: FnOnce(Sub) -> Guard,
{
    let subscriber = builder();
    setter(subscriber)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq)]
    struct DummySubscriber;

    #[test]
    fn init_returns_guard() {
        let guard = init();
        tracing::info!("logging guard acquired");
        drop(guard);
    }

    #[test]
    fn build_subscriber_produces_working_subscriber() {
        let subscriber = build_subscriber();
        let guard = tracing::subscriber::set_default(subscriber);
        tracing::info!("subscriber set for test");
        drop(guard);
    }

    #[test]
    fn init_with_invokes_setter_with_subscriber() {
        let guard = init_with(
            || DummySubscriber,
            |sub| {
                assert_eq!(sub, DummySubscriber);
                42
            },
        );

        assert_eq!(guard, 42);
    }
}
