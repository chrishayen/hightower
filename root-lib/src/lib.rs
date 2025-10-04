use hightower_context::CommonContext;

pub fn start(context: &CommonContext) {
    hightower_root_web::start(context);
}

pub use hightower_root_web::{WaitForRootError, wait_until_ready};
