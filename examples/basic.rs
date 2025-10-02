use hightower_naming::generate_random_name;

fn main() {
    // No random suffix - just adjective-noun
    let name = generate_random_name(None);
    println!("No random suffix: {}", name);
}
