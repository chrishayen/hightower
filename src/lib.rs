mod adjectives;
mod nouns;

use rand::Rng;

pub fn generate_random_name(random_suffix_length: Option<usize>) -> String {
    let mut rng = rand::thread_rng();
    let adjective = adjectives::ADJECTIVES[rng.gen_range(0..adjectives::ADJECTIVES.len())];
    let noun = nouns::NOUNS[rng.gen_range(0..nouns::NOUNS.len())];

    match random_suffix_length {
        Some(length) if length > 0 => {
            let random_chars: String = (0..length)
                .map(|_| {
                    let chars = b"abcdefghijklmnopqrstuvwxyz0123456789";
                    chars[rng.gen_range(0..chars.len())] as char
                })
                .collect();
            format!("ht-{}-{}-{}", adjective, noun, random_chars)
        }
        _ => format!("ht-{}-{}", adjective, noun),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generates_valid_name() {
        let name = generate_random_name(Some(5));
        assert!(name.starts_with("ht-"));
        assert_eq!(name.matches('-').count(), 3);
    }

    #[test]
    fn test_name_format() {
        let name = generate_random_name(Some(5));
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[0], "ht");
        assert!(!parts[1].is_empty()); // adjective
        assert!(!parts[2].is_empty()); // noun
        assert_eq!(parts[3].len(), 5); // random chars
    }

    #[test]
    fn test_random_suffix_alphanumeric() {
        let name = generate_random_name(Some(5));
        let parts: Vec<&str> = name.split('-').collect();
        let suffix = parts[3];
        assert!(suffix.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn test_adjective_from_list() {
        let name = generate_random_name(Some(5));
        let parts: Vec<&str> = name.split('-').collect();
        let adjective = parts[1];
        assert!(adjectives::ADJECTIVES.contains(&adjective));
    }

    #[test]
    fn test_noun_from_list() {
        let name = generate_random_name(Some(5));
        let parts: Vec<&str> = name.split('-').collect();
        let noun = parts[2];
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
        assert!(name.starts_with("ht-"));
        assert_eq!(name.matches('-').count(), 2);
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 3);
    }

    #[test]
    fn test_custom_suffix_length() {
        let name = generate_random_name(Some(10));
        let parts: Vec<&str> = name.split('-').collect();
        assert_eq!(parts.len(), 4);
        assert_eq!(parts[3].len(), 10);
    }

    #[test]
    fn test_zero_suffix_length() {
        let name = generate_random_name(Some(0));
        assert_eq!(name.matches('-').count(), 2);
    }
}
