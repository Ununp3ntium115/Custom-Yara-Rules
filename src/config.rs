use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyroConfig {
    pub thor: ThorConfig,
    pub pyro: PyroServerConfig,
    pub scanning: ScanConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThorConfig {
    pub binary_path: String,
    pub license_path: String,
    pub rules_path: String,
    pub config_path: String,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PyroServerConfig {
    pub endpoint: String,
    pub api_key: Option<String>,
    pub timeout_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanConfig {
    pub output_format: String, // "json", "csv", "xml"
    pub temp_dir: Option<String>,
    pub cleanup: bool,
    pub exclude_paths: Vec<String>,
    pub max_file_size_mb: u64,
}

impl Default for PyroConfig {
    fn default() -> Self {
        Self {
            thor: ThorConfig {
                binary_path: get_default_thor_binary(),
                license_path: "thor-lite-license.lic".to_string(),
                rules_path: "custom-signatures".to_string(),
                config_path: "config/thor.yml".to_string(),
                flags: vec![
                    "--utc".to_string(),
                    "--rfc3339".to_string(),
                    "--nocsv".to_string(),
                    "--nolog".to_string(),
                    "--nothordb".to_string(),
                    "--module".to_string(),
                    "Filescan".to_string(),
                    "--allhds".to_string(),
                    "--json".to_string(),
                ],
            },
            pyro: PyroServerConfig {
                endpoint: "http://localhost:8080".to_string(),
                api_key: None,
                timeout_seconds: 300,
            },
            scanning: ScanConfig {
                output_format: "json".to_string(),
                temp_dir: None,
                cleanup: true,
                exclude_paths: vec![
                    "/proc".to_string(),
                    "/sys".to_string(),
                    "/dev".to_string(),
                    "C:\\Windows\\System32".to_string(),
                ],
                max_file_size_mb: 100,
            },
        }
    }
}

impl PyroConfig {
    pub fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        if !path.as_ref().exists() {
            log::warn!("Config file not found, creating default config");
            let default_config = Self::default();
            default_config.save(&path)?;
            return Ok(default_config);
        }

        let content = fs::read_to_string(path)?;
        let config: PyroConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    pub fn save<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let content = serde_yaml::to_string(self)?;
        fs::write(path, content)?;
        Ok(())
    }
}

fn get_default_thor_binary() -> String {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    
    match os {
        "windows" => format!("thor-lite_{}.exe", arch),
        _ => format!("thor-lite_{}", arch),
    }
}