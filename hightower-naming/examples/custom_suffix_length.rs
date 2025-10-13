use hightower_naming::generate_random_name;

fn main() {
    // With custom random suffix length (10 characters)
    let name = generate_random_name(Some(10));
    println!("With 10-char random suffix: {}", name);
}
