mod adjectives;
mod nouns;

use rand::Rng;

/// Generate a random name with optional random suffix.
///
/// # Examples
///
/// ```
/// // No random suffix - just adjective-noun
/// let name = hightower_naming::generate_random_name(None);
/// // Example: "brave-tiger"
///
/// // With random suffix of default length (5 characters)
/// let name = hightower_naming::generate_random_name(Some(5));
/// // Example: "brave-tiger-a1b2c"
///
/// // With custom random suffix length (10 characters)
/// let name = hightower_naming::generate_random_name(Some(10));
/// // Example: "brave-tiger-x9y8z7w6v5"
/// ```
pub fn generate_random_name(random_suffix_length: Option<usize>) -> String {
    generate_random_name_with_prefix(None, random_suffix_length)
}

/// Generate a random name with custom prefix and optional random suffix.
///
/// # Examples
///
/// ```
/// // With custom prefix
/// let name = hightower_naming::generate_random_name_with_prefix(Some("app"), None);
/// // Example: "app-brave-tiger"
///
/// // With custom prefix and random suffix
/// let name = hightower_naming::generate_random_name_with_prefix(Some("app"), Some(5));
/// // Example: "app-brave-tiger-a1b2c"
///
/// // No prefix (same as generate_random_name)
/// let name = hightower_naming::generate_random_name_with_prefix(None, Some(5));
/// // Example: "brave-tiger-a1b2c"
/// ```
pub fn generate_random_name_with_prefix(prefix: Option<&str>, random_suffix_length: Option<usize>) -> String {
    let mut rng = rand::thread_rng();
    let adjective = adjectives::ADJECTIVES[rng.gen_range(0..adjectives::ADJECTIVES.len())];
    let noun = nouns::NOUNS[rng.gen_range(0..nouns::NOUNS.len())];

    let base = match prefix {
        Some(p) if !p.is_empty() => format!("{}-{}-{}", p, adjective, noun),
        _ => format!("{}-{}", adjective, noun),
    };

    match random_suffix_length {
        Some(length) if length > 0 => {
            let random_chars: String = (0..length)
                .map(|_| {
                    let chars = b"0123456789";
                    chars[rng.gen_range(0..chars.len())] as char
                })
                .collect();
            format!("{}-{}", base, random_chars)
        }
        _ => base,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generates_valid_name() {
        let name = generate_random_name(Some(5));
        assert_eq!(name.matches('-').count(), 2);
    }

    #[test]
    fn test_name_format() {
        let name = generate_random_name(Some(5));
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert!(!parts[0].is_empty()); // adjective
        assert!(!parts[1].is_empty()); // noun
        assert_eq!(parts[2].len(), 5); // random chars
    }

    #[test]
    fn test_random_suffix_numeric() {
        let name = generate_random_name(Some(5));
        let parts: Vec<&str> = name.split('-').collect();
        let suffix = parts[2];
        assert!(suffix.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_adjective_from_list() {
        let name = generate_random_name(Some(5));
        let parts: Vec<&str> = name.split('-').collect();
        let adjective = parts[0];
        assert!(adjectives::ADJECTIVES.contains(&adjective));
    }

    #[test]
    fn test_noun_from_list() {
        let name = generate_random_name(Some(5));
        let parts: Vec<&str> = name.split('-').collect();
        let noun = parts[1];
        assert!(nouns::NOUNS.contains(&noun));
    }

    #[test]
    fn test_generates_different_names() {
        let name1 = generate_random_name(Some(5));
        let name2 = generate_random_name(Some(5));
        // Very unlikely to be the same
        assert_ne!(name1, name2);
    }

    #[test]
    fn test_no_suffix() {
        let name = generate_random_name(None);
        assert_eq!(name.matches('-').count(), 1);
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 2);
    }

    #[test]
    fn test_custom_suffix_length() {
        let name = generate_random_name(Some(10));
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[2].len(), 10);
    }

    #[test]
    fn test_zero_suffix_length() {
        let name = generate_random_name(Some(0));
        assert_eq!(name.matches('-').count(), 1);
    }

    #[test]
    fn test_no_trailing_dash() {
        let name_no_suffix = generate_random_name(None);
        assert!(!name_no_suffix.ends_with('-'));

        let name_zero_suffix = generate_random_name(Some(0));
        assert!(!name_zero_suffix.ends_with('-'));
    }

    #[test]
    fn test_custom_prefix() {
        let name = generate_random_name_with_prefix(Some("custom"), Some(5));
        assert!(name.starts_with("custom-"));
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "custom");
    }

    #[test]
    fn test_no_prefix() {
        let name = generate_random_name_with_prefix(None, Some(5));
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 3);
        assert!(adjectives::ADJECTIVES.contains(&parts[0]));
        assert!(nouns::NOUNS.contains(&parts[1]));
        assert_eq!(parts[2].len(), 5);
    }

    #[test]
    fn test_empty_prefix() {
        let name = generate_random_name_with_prefix(Some(""), None);
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 2);
        assert!(adjectives::ADJECTIVES.contains(&parts[0]));
        assert!(nouns::NOUNS.contains(&parts[1]));
    }
}
