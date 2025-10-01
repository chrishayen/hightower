# hightower-naming

Generate random hightower-style names with epic adjectives and nouns.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
hightower-naming = "0.1.0"
```

## Usage

```rust
use hightower_naming::generate_random_name;

fn main() {
    let name = generate_random_name();
    println!("{}", name);
    // Example output: ht-legendary-dragon-7x9k2
}
```

## Name Format

Generated names follow the format: `ht-{adjective}-{noun}-{random}`

- **Prefix**: Always `ht-`
- **Adjective**: Random epic adjective (e.g., "alpha", "legendary", "unstoppable")
- **Noun**: Random powerful noun (e.g., "warrior", "titan", "phoenix")
- **Random suffix**: 5 character alphanumeric string

## Examples

- `ht-alpha-warrior-a3x9z`
- `ht-legendary-dragon-m7k4p`
- `ht-unstoppable-titan-q2w8r`
