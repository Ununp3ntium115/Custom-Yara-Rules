use clap::{Arg, Command};
use log::{error, info, warn};
use std::env;

mod config;
mod executor;
mod hooks;
mod platform;
mod scanner;

use crate::config::PyroConfig;
use crate::executor::PyroExecutor;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();

    let matches = Command::new("pyro-thor")
        .version("0.1.0")
        .author("M507")
        .about("Thor YARA Rules Package for Pyro - Rust multiplatform implementation")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("FILE")
                .help("Configuration file path")
                .default_value("config.yaml"),
        )
        .arg(
            Arg::new("scan-path")
                .short('p')
                .long("path")
                .value_name("PATH")
                .help("Path to scan")
                .default_value("/"),
        )
        .arg(
            Arg::new("output")
                .short('o')
                .long("output")
                .value_name("FILE")
                .help("Output file for results")
                .default_value("scan_results.json"),
        )
        .arg(
            Arg::new("verbose")
                .short('v')
                .long("verbose")
                .help("Enable verbose logging")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("redb-enabled")
                .long("redb-enabled")
                .help("Enable ReDB optimization for YARA rules")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("enterprise-mode")
                .long("enterprise-mode")
                .help("Enable enterprise features")
                .action(clap::ArgAction::SetTrue),
        )
        .arg(
            Arg::new("scan-uuid")
                .long("scan-uuid")
                .value_name("UUID")
                .help("Unique scan identifier"),
        )
        .get_matches();

    let config_path = matches.get_one::<String>("config").unwrap();
    let scan_path = matches.get_one::<String>("scan-path").unwrap();
    let output_path = matches.get_one::<String>("output").unwrap();
    let redb_enabled = matches.get_flag("redb-enabled");
    let enterprise_mode = matches.get_flag("enterprise-mode");
    let scan_uuid = matches.get_one::<String>("scan-uuid");

    if enterprise_mode {
        info!("🚀 Starting Pyro Thor Enterprise YARA scanner");
    } else {
        info!("Starting Pyro Thor YARA scanner");
    }
    
    info!("Config: {}, Scan path: {}, Output: {}", config_path, scan_path, output_path);
    
    if redb_enabled {
        info!("ReDB optimization enabled");
    }

    let mut config = PyroConfig::load(config_path)?;
    
    // Override config with CLI flags
    if redb_enabled {
        info!("Initializing ReDB YARA rules database...");
        let redb_hook = crate::hooks::initialize_yara_rules_hook("yara_rules.redb").await?;
        
        // Sync rules from directory if it exists
        if std::path::Path::new("custom-signatures/yara").exists() {
            let synced_count = crate::hooks::sync_yara_rules_from_directory(
                &redb_hook, 
                "custom-signatures/yara"
            ).await?;
            info!("Synced {} YARA rules to ReDB", synced_count);
        }
    }

    let executor = PyroExecutor::new(config);

    let result = if enterprise_mode {
        executor.execute_enterprise_scan(scan_path, output_path, redb_enabled).await
    } else {
        executor.execute_scan(scan_path, output_path).await
    };

    match result {
        Ok(_) => {
            info!("✅ Scan completed successfully");
            if let Some(uuid) = scan_uuid {
                info!("Scan UUID: {}", uuid);
            }
            Ok(())
        }
        Err(e) => {
            error!("❌ Scan failed: {}", e);
            Err(e)
        }
    }
}