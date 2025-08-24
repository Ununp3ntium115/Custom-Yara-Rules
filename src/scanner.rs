use crate::config::{PyroConfig, ThorConfig};
use crate::platform::PlatformInfo;
use crate::hooks::{YaraRulesRedbHook, initialize_yara_rules_hook};
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use tempfile::TempDir;
use tokio::fs;

pub struct ThorScanner {
    config: ThorConfig,
    platform: PlatformInfo,
    temp_dir: Option<TempDir>,
    redb_hook: Option<YaraRulesRedbHook>,
    enterprise_mode: bool,
}

impl ThorScanner {
    pub fn new(config: ThorConfig) -> Self {
        let platform = PlatformInfo::detect();
        
        Self {
            config,
            platform,
            temp_dir: None,
            redb_hook: None,
            enterprise_mode: false,
        }
    }

    pub fn with_enterprise_mode(mut self, enabled: bool) -> Self {
        self.enterprise_mode = enabled;
        self
    }

    pub async fn enable_redb_optimization(&mut self, db_path: &str) -> Result<()> {
        log::info!("🔧 Initializing ReDB optimization for YARA rules");
        let redb_hook = initialize_yara_rules_hook(db_path).await
            .context("Failed to initialize ReDB hook")?;
        
        self.redb_hook = Some(redb_hook);
        log::info!("✅ ReDB optimization enabled");
        Ok(())
    }

    pub async fn prepare_environment(&mut self) -> Result<PathBuf> {
        // Create temporary directory
        let temp_dir = tempfile::tempdir()
            .context("Failed to create temporary directory")?;
        
        let temp_path = temp_dir.path().to_path_buf();
        
        // Add Windows Defender exclusion if on Windows
        #[cfg(windows)]
        if self.platform.is_windows() {
            if let Err(e) = crate::platform::windows::add_defender_exclusion(
                temp_path.to_str().unwrap()
            ) {
                log::warn!("Failed to add Windows Defender exclusion: {}", e);
            }
        }

        self.temp_dir = Some(temp_dir);
        Ok(temp_path)
    }

    pub async fn extract_thor_package(&self, package_path: &Path, extract_to: &Path) -> Result<()> {
        log::info!("Extracting Thor package to: {}", extract_to.display());

        let file = std::fs::File::open(package_path)
            .context("Failed to open Thor package")?;
        
        let mut archive = zip::ZipArchive::new(file)
            .context("Failed to read ZIP archive")?;

        for i in 0..archive.len() {
            let mut file = archive.by_index(i)
                .context("Failed to read file from archive")?;
            
            let outpath = extract_to.join(file.name());

            if file.name().ends_with('/') {
                // Directory
                fs::create_dir_all(&outpath).await
                    .context("Failed to create directory")?;
            } else {
                // File
                if let Some(parent) = outpath.parent() {
                    fs::create_dir_all(parent).await
                        .context("Failed to create parent directory")?;
                }

                let mut outfile = std::fs::File::create(&outpath)
                    .context("Failed to create output file")?;
                
                std::io::copy(&mut file, &mut outfile)
                    .context("Failed to extract file")?;
            }

            // Set executable permissions on Unix systems
            #[cfg(unix)]
            if self.platform.is_unix() && file.name().contains("thor-lite") {
                if let Err(e) = crate::platform::unix::set_executable_permissions(
                    outpath.to_str().unwrap()
                ) {
                    log::warn!("Failed to set executable permissions: {}", e);
                }
            }
        }

        Ok(())
    }

    pub async fn run_scan(&self, scan_path: &str, output_path: &str) -> Result<Value> {
        let temp_path = self.temp_dir.as_ref()
            .context("Temporary directory not initialized")?
            .path();

        let thor_binary = temp_path
            .join("Thor")
            .join(self.platform.get_thor_binary_name());

        if !thor_binary.exists() {
            return Err(anyhow::anyhow!("Thor binary not found: {}", thor_binary.display()));
        }

        if self.enterprise_mode {
            log::info!("🚀 Running Thor Enterprise scan with binary: {}", thor_binary.display());
        } else {
            log::info!("Running Thor scan with binary: {}", thor_binary.display());
        }

        let mut cmd = Command::new(&thor_binary);
        
        // Add configuration flags
        for flag in &self.config.flags {
            cmd.arg(flag);
        }

        // Add enterprise-specific flags
        if self.enterprise_mode {
            cmd.arg("--enterprise-mode");
            cmd.arg("--ai-enhanced");
            
            if self.redb_hook.is_some() {
                cmd.arg("--redb-optimized");
                log::info("🔧 ReDB optimization enabled for scan");
            }
        }

        // Add scan path
        cmd.arg("--path").arg(scan_path);
        
        // Add rebase directory
        cmd.arg("--rebase-dir").arg(temp_path);

        // Set working directory
        cmd.current_dir(temp_path);
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        if self.enterprise_mode {
            log::info!("🎯 Executing enterprise command: {:?}", cmd);
        } else {
            log::info!("Executing command: {:?}", cmd);
        }

        let output = cmd.output()
            .context("Failed to execute Thor scanner")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(anyhow::anyhow!("Thor scan failed: {}", stderr));
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        
        // Parse JSON output
        let scan_results: Value = serde_json::from_str(&stdout)
            .context("Failed to parse Thor output as JSON")?;

        // Save results to file
        fs::write(output_path, &stdout).await
            .context("Failed to write scan results")?;

        if self.enterprise_mode {
            log::info!("🎯 Enterprise scan results saved to: {}", output_path);
            
            // Update ReDB with scan metadata if enabled
            if let Some(redb_hook) = &self.redb_hook {
                if let Ok(stats) = redb_hook.get_database_stats().await {
                    log::info!("📊 ReDB Stats - Rules: {}, Intel: {}", 
                              stats.yara_rules_count, stats.threat_intel_count);
                }
            }
        } else {
            log::info!("Scan results saved to: {}", output_path);
        }

        Ok(scan_results)
    }

    pub async fn cleanup(&mut self) -> Result<()> {
        if let Some(temp_dir) = &self.temp_dir {
            let temp_path = temp_dir.path();

            // Remove Windows Defender exclusion if on Windows
            #[cfg(windows)]
            if self.platform.is_windows() {
                if let Err(e) = crate::platform::windows::remove_defender_exclusion(
                    temp_path.to_str().unwrap()
                ) {
                    log::warn!("Failed to remove Windows Defender exclusion: {}", e);
                }
            }
        }

        // Drop temp_dir to trigger cleanup
        self.temp_dir = None;
        log::info!("Cleanup completed");
        
        Ok(())
    }
}