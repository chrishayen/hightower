use naming::generate_random_name;

fn main() {
    // With random suffix of 5 characters
    let name = generate_random_name(Some(5));
    println!("With 5-char random suffix: {}", name);
}
