# hightower-naming

Generate random hightower-style names with epic adjectives and nouns.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
hightower-naming = "0.1.2"
```

## Usage

### Basic Usage

```rust
use hightower_naming::generate_random_name;

fn main() {
    // Generate name without random suffix
    let name = generate_random_name(None);
    println!("{}", name);
    // Example output: legendary-dragon

    // Generate name with 5 character random suffix
    let name = generate_random_name(Some(5));
    println!("{}", name);
    // Example output: legendary-dragon-7x9k2

    // Generate name with custom suffix length
    let name = generate_random_name(Some(10));
    println!("{}", name);
    // Example output: legendary-dragon-a3x9z7m4k2
}
```

### With Custom Prefix

```rust
use hightower_naming::generate_random_name_with_prefix;

fn main() {
    // Generate name with custom prefix
    let name = generate_random_name_with_prefix(Some("app"), None);
    println!("{}", name);
    // Example output: app-legendary-dragon

    // Generate name with custom prefix and random suffix
    let name = generate_random_name_with_prefix(Some("app"), Some(5));
    println!("{}", name);
    // Example output: app-legendary-dragon-7x9k2
}
```

## Name Format

Generated names follow the format:
- Without prefix: `{adjective}-{noun}[-{random}]`
- With prefix: `{prefix}-{adjective}-{noun}[-{random}]`

- **Prefix**: Optional custom prefix (default: none)
- **Adjective**: Random epic adjective (e.g., "alpha", "legendary", "unstoppable")
- **Noun**: Random powerful noun (e.g., "warrior", "titan", "phoenix")
- **Random suffix**: Optional alphanumeric string

## Examples

Run examples with:
```bash
cargo run --example basic
cargo run --example with_random_suffix
cargo run --example custom_suffix_length
cargo run --example with_prefix
```

Example outputs:
- `legendary-dragon` (no suffix, no prefix)
- `legendary-dragon-a3x9z` (5 character suffix)
- `unstoppable-titan-abc123def4` (10 character suffix)
- `app-supreme-phoenix` (custom prefix, no suffix)
- `app-alpha-warrior-m7k4p` (custom prefix with 5 character suffix)
