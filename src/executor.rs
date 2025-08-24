use crate::config::PyroConfig;
use crate::scanner::ThorScanner;
use anyhow::{Context, Result};
use serde_json::Value;
use std::path::Path;

pub struct PyroExecutor {
    config: PyroConfig,
}

impl PyroExecutor {
    pub fn new(config: PyroConfig) -> Self {
        Self { config }
    }

    pub async fn execute_scan(&self, scan_path: &str, output_path: &str) -> Result<Value> {
        self.execute_scan_with_options(scan_path, output_path, false, false).await
    }

    pub async fn execute_enterprise_scan(&self, scan_path: &str, output_path: &str, redb_enabled: bool) -> Result<Value> {
        self.execute_scan_with_options(scan_path, output_path, true, redb_enabled).await
    }

    async fn execute_scan_with_options(&self, scan_path: &str, output_path: &str, enterprise_mode: bool, redb_enabled: bool) -> Result<Value> {
        if enterprise_mode {
            log::info!("🚀 Starting Pyro Thor Enterprise scan execution");
        } else {
            log::info!("Starting Pyro Thor scan execution");
        }
        
        let mut scanner = ThorScanner::new(self.config.thor.clone())
            .with_enterprise_mode(enterprise_mode);
        
        // Enable ReDB optimization if requested
        if redb_enabled {
            scanner.enable_redb_optimization("yara_rules.redb").await
                .context("Failed to enable ReDB optimization")?;
        }
        
        // Prepare environment
        let temp_path = scanner.prepare_environment().await
            .context("Failed to prepare scanning environment")?;

        // Download Thor package if needed
        let thor_package_path = self.ensure_thor_package().await
            .context("Failed to ensure Thor package availability")?;

        // Extract Thor package
        scanner.extract_thor_package(&thor_package_path, &temp_path).await
            .context("Failed to extract Thor package")?;

        // Run the scan
        let results = scanner.run_scan(scan_path, output_path).await
            .context("Failed to run Thor scan")?;

        // Send results to Pyro server if configured
        if let Some(api_key) = &self.config.pyro.api_key {
            self.send_results_to_pyro(&results, api_key).await
                .context("Failed to send results to Pyro server")?;
        }

        // Cleanup
        if self.config.scanning.cleanup {
            scanner.cleanup().await
                .context("Failed to cleanup temporary files")?;
        }

        if enterprise_mode {
            log::info!("🎯 Enterprise scan execution completed successfully");
        } else {
            log::info!("Scan execution completed successfully");
        }
        Ok(results)
    }

    async fn ensure_thor_package(&self) -> Result<std::path::PathBuf> {
        // Check if Thor package exists locally
        let local_package = Path::new("Custom.DFIR.Yara.AllRules.zip");
        
        if local_package.exists() {
            log::info!("Using local Thor package: {}", local_package.display());
            return Ok(local_package.to_path_buf());
        }

        // Try to download from Pyro server
        log::info!("Downloading Thor package from Pyro server: {}", self.config.pyro.endpoint);
        
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(self.config.pyro.timeout_seconds))
            .build()
            .context("Failed to create HTTP client")?;

        let url = format!("{}/api/tools/Custom.DFIR.Yara.AllRules.zip", self.config.pyro.endpoint);
        
        let mut request = client.get(&url);
        
        if let Some(api_key) = &self.config.pyro.api_key {
            request = request.header("Authorization", format!("Bearer {}", api_key));
        }

        let response = request.send().await
            .context("Failed to download Thor package")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to download Thor package: HTTP {}", 
                response.status()
            ));
        }

        let bytes = response.bytes().await
            .context("Failed to read Thor package bytes")?;

        tokio::fs::write(local_package, bytes).await
            .context("Failed to save Thor package")?;

        log::info!("Thor package downloaded successfully");
        Ok(local_package.to_path_buf())
    }

    async fn send_results_to_pyro(&self, results: &Value, api_key: &str) -> Result<()> {
        log::info!("Sending scan results to Pyro server");

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(self.config.pyro.timeout_seconds))
            .build()
            .context("Failed to create HTTP client")?;

        let url = format!("{}/api/scan-results", self.config.pyro.endpoint);

        let response = client
            .post(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(results)
            .send()
            .await
            .context("Failed to send results to Pyro server")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to send results to Pyro server: HTTP {}", 
                response.status()
            ));
        }

        log::info!("Scan results sent to Pyro server successfully");
        Ok(())
    }
}