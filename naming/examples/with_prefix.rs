use hightower_naming::generate_random_name_with_prefix;

fn main() {
    // With custom prefix
    let name = generate_random_name_with_prefix(Some("app"), None);
    println!("With 'app' prefix: {}", name);

    // With custom prefix and random suffix
    let name_with_suffix = generate_random_name_with_prefix(Some("app"), Some(5));
    println!("With 'app' prefix and 5-char suffix: {}", name_with_suffix);
}
