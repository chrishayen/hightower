// Debug logging macros with role prefix
macro_rules! debug_init {
    ($($arg:tt)*) => {
        debug!("INITIATOR ---- {}", format!($($arg)*));
    };
}

macro_rules! debug_resp {
    ($($arg:tt)*) => {
        debug!("RESPONDER ---- {}", format!($($arg)*));
    };
}

macro_rules! info_init {
    ($($arg:tt)*) => {
        info!("INITIATOR ---- {}", format!($($arg)*));
    };
}

#[allow(unused_macros)]
macro_rules! info_resp {
    ($($arg:tt)*) => {
        info!("RESPONDER ---- {}", format!($($arg)*));
    };
}

macro_rules! error_init {
    ($($arg:tt)*) => {
        error!("INITIATOR ---- {}", format!($($arg)*));
    };
}

macro_rules! error_resp {
    ($($arg:tt)*) => {
        error!("RESPONDER ---- {}", format!($($arg)*));
    };
}

// For session-aware logging
macro_rules! debug_session {
    ($is_init:expr, $($arg:tt)*) => {
        if $is_init {
            debug_init!($($arg)*);
        } else {
            debug_resp!($($arg)*);
        }
    };
}

#[allow(unused_macros)]
macro_rules! info_session {
    ($is_init:expr, $($arg:tt)*) => {
        if $is_init {
            info_init!($($arg)*);
        } else {
            info_resp!($($arg)*);
        }
    };
}

macro_rules! error_session {
    ($is_init:expr, $($arg:tt)*) => {
        if $is_init {
            error_init!($($arg)*);
        } else {
            error_resp!($($arg)*);
        }
    };
}

#[allow(unused_imports)]
pub(crate) use {
    debug_init, debug_resp, debug_session,
    info_init, info_resp, info_session,
    error_init, error_resp, error_session,
};
