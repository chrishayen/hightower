use hightower_context::CommonContext;

pub fn start(context: &CommonContext) {
    hightower_root_api::start(context);
}

pub use hightower_root_api::{WaitForRootError, wait_until_ready};
