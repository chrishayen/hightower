use hightower_naming::generate_random_name_with_prefix;

const PREFIX: &str = "ht";
const SUFFIX_LEN: usize = 5;

pub fn generate() -> String {
    generate_random_name_with_prefix(Some(PREFIX), Some(SUFFIX_LEN))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_prefixed_name_with_suffix() {
        let name = generate();
        assert!(name.starts_with("ht-"), "name `{}` missing ht prefix", name);
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 4, "name `{}` should contain 4 parts", name);
        assert_eq!(parts[0], "ht");
        assert_eq!(parts[3].len(), 5, "suffix should be 5 characters");
        assert!(parts[3].chars().all(|c| c.is_ascii_alphanumeric()));
    }
}
