pub(crate) mod acme;
pub(crate) mod auth_keys;
pub(crate) mod console;
pub(crate) mod dashboard;
pub(crate) mod endpoints;
pub(crate) mod health;
pub(crate) mod sessions;

pub(crate) use acme::acme_challenge;
pub(crate) use auth_keys::{generate_auth_key, list_auth_keys, revoke_auth_key, store_legacy_key};
pub(crate) use console::{console_dashboard, console_endpoints, console_root, console_settings};
pub(crate) use dashboard::dashboard_endpoints;
pub(crate) use endpoints::{deregister_endpoint, register_endpoint};
pub(crate) use health::root_health;
pub(crate) use sessions::{change_password, create_session, delete_session};
