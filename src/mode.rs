use crate::cli::Cli;

#[derive(Debug, PartialEq, Eq)]
pub enum Mode {
    Node,
    Root,
}

pub fn resolve(cli: &Cli) -> Mode {
    if cli.root { Mode::Root } else { Mode::Node }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_returns_node_when_root_flag_absent() {
        let cli = Cli {
            node: false,
            root: false,
            kv: None,
        };

        assert_eq!(resolve(&cli), Mode::Node);
    }

    #[test]
    fn resolve_prefers_root_when_flag_set() {
        let cli = Cli {
            node: false,
            root: true,
            kv: None,
        };

        assert_eq!(resolve(&cli), Mode::Root);
    }

    #[test]
    fn resolve_retains_node_when_flag_set() {
        let cli = Cli {
            node: true,
            root: false,
            kv: None,
        };

        assert_eq!(resolve(&cli), Mode::Node);
    }
}
