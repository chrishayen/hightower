use crate::common::CommonContext;
use tracing::info;

pub fn run(_context: &CommonContext) {
    info!("Running in root mode");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kv;
    use tempfile::TempDir;

    #[test]
    fn run_logs_message() {
        let temp = TempDir::new().expect("tempdir");
        let kv = kv::initialize(Some(temp.path())).expect("kv init");
        let ctx = CommonContext::new(kv);
        run(&ctx);
    }
}
