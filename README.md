# hightower-naming

Generate random hightower-style names with epic adjectives and nouns.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
hightower-naming = "0.1.0"
```

## Usage

### Basic Usage

```rust
use hightower_naming::generate_random_name;

fn main() {
    let name = generate_random_name();
    println!("{}", name);
    // Example output: ht-legendary-dragon-7x9k2
}
```

### Advanced Usage

```rust
use hightower_naming::generate_random_name_with_options;

fn main() {
    // Generate name without random suffix
    let name = generate_random_name_with_options(None);
    println!("{}", name);
    // Example output: ht-legendary-dragon

    // Generate name with custom suffix length
    let name = generate_random_name_with_options(Some(10));
    println!("{}", name);
    // Example output: ht-legendary-dragon-a3x9z7m4k2

    // Generate name with default suffix length (5 characters)
    let name = generate_random_name_with_options(Some(5));
    println!("{}", name);
    // Example output: ht-legendary-dragon-7x9k2
}
```

## Name Format

Generated names follow the format: `ht-{adjective}-{noun}-{random}`

- **Prefix**: Always `ht-`
- **Adjective**: Random epic adjective (e.g., "alpha", "legendary", "unstoppable")
- **Noun**: Random powerful noun (e.g., "warrior", "titan", "phoenix")
- **Random suffix**: Optional alphanumeric string (default: 5 characters)

## Examples

- `ht-alpha-warrior-a3x9z` (default, 5 character suffix)
- `ht-legendary-dragon-m7k4p` (default, 5 character suffix)
- `ht-unstoppable-titan` (no suffix)
- `ht-supreme-phoenix-abc123def456` (custom 12 character suffix)
