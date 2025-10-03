use std::env::VarError;
use std::fmt;

#[derive(Debug, PartialEq, Eq)]
pub enum TokenError {
    Missing,
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::Missing => write!(f, "HT_TOKEN environment variable must be set."),
        }
    }
}

impl std::error::Error for TokenError {}

pub fn fetch<F>(mut lookup: F) -> Result<String, TokenError>
where
    F: FnMut(&str) -> Result<String, VarError>,
{
    lookup("HT_TOKEN").map_err(|_| TokenError::Missing)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fetch_returns_token_when_present() {
        let token = fetch(|_| Ok(String::from("123"))).expect("token should be present");

        assert_eq!(token, "123");
    }

    #[test]
    fn fetch_reports_missing_token() {
        let error = fetch(|_| Err(VarError::NotPresent)).expect_err("token should be missing");

        assert_eq!(error, TokenError::Missing);
    }
}
