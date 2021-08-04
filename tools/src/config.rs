use crate::Opt;
use anyhow::{anyhow, bail, Error};
use fehler::throws;
use fs_err as fs;

pub struct Config {
    pub enable_verbose_logging: bool,
    pub use_test_key: bool,
}

impl Config {
    #[throws]
    pub fn load(opt: &Opt) -> Config {
        let text = fs::read_to_string(opt.conf_path())?;
        Config::parse(&text)?
    }

    #[throws]
    fn parse(text: &str) -> Config {
        let mut enable_verbose_logging = None;
        let mut use_test_key = None;

        for (index, line) in text.lines().enumerate() {
            let line_no = index + 1;
            let line = line.trim();

            // Ignore empty lines and comments.
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let parts: Vec<_> = line.splitn(2, '=').collect();
            if parts.len() != 2 {
                bail!(
                    "invalid config: line {}: expected 'option = value'",
                    line_no
                );
            }

            let key = parts[0].trim();
            let val = parts[1].trim();

            let parse_bool = || -> Result<Option<bool>, Error> {
                val.parse()
                    .map_err(|_| {
                        anyhow!(
                            "invalid config: line {}: expected bool value",
                            line_no
                        )
                    })
                    .map(Some)
            };

            match key {
                "enable_verbose_logging" => {
                    enable_verbose_logging = parse_bool()?
                }
                "use_test_key" => use_test_key = parse_bool()?,
                _ => println!("warning: unknown config option: {}", key),
            }
        }

        Config {
            enable_verbose_logging: enable_verbose_logging.unwrap_or(true),
            use_test_key: use_test_key.unwrap_or(false),
        }
    }

    /// Get all cargo features to enable while building crdyboot.
    pub fn get_crdyboot_features(&self) -> Vec<&'static str> {
        let mut features = Vec::new();
        if self.enable_verbose_logging {
            features.push("verbose");
        }
        if self.use_test_key {
            features.push("use_test_key");
        }
        features
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[throws]
    fn test_parse() {
        // An empty config is OK.
        let conf = Config::parse("")?;
        assert!(conf.enable_verbose_logging);

        // Parse a bool.
        let conf = Config::parse("enable_verbose_logging=false")?;
        assert!(!conf.enable_verbose_logging);

        // Invalid bool.
        assert!(Config::parse("enable_verbose_logging=asdf").is_err());

        // An unknown key is allowed.
        assert!(Config::parse("asdf=true").is_ok());
    }
}
