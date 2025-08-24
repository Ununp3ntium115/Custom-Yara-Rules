use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub os: String,
    pub arch: String,
    pub temp_dir: PathBuf,
    pub executable_extension: String,
}

impl PlatformInfo {
    pub fn detect() -> Self {
        let os = env::consts::OS.to_string();
        let arch = env::consts::ARCH.to_string();
        
        let temp_dir = match os.as_str() {
            "windows" => PathBuf::from("C:\\Users\\Public"),
            _ => PathBuf::from("/var/tmp"),
        };

        let executable_extension = match os.as_str() {
            "windows" => ".exe".to_string(),
            _ => String::new(),
        };

        Self {
            os,
            arch,
            temp_dir,
            executable_extension,
        }
    }

    pub fn get_thor_binary_name(&self) -> String {
        format!("thor-lite_{}{}", self.arch, self.executable_extension)
    }

    pub fn get_temp_path(&self, filename: &str) -> PathBuf {
        self.temp_dir.join(filename)
    }

    pub fn is_windows(&self) -> bool {
        self.os == "windows"
    }

    pub fn is_unix(&self) -> bool {
        matches!(self.os.as_str(), "linux" | "macos" | "darwin")
    }
}

#[cfg(windows)]
pub mod windows {
    use std::process::Command;
    use anyhow::Result;

    pub fn add_defender_exclusion(path: &str) -> Result<()> {
        let output = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-NonInteractive", 
                "-ExecutionPolicy", "Bypass",
                "-Command",
                &format!("Add-MpPreference -ExclusionPath '{}'", path)
            ])
            .output()?;

        if !output.status.success() {
            log::warn!("Failed to add Windows Defender exclusion: {}", 
                String::from_utf8_lossy(&output.stderr));
        }

        Ok(())
    }

    pub fn remove_defender_exclusion(path: &str) -> Result<()> {
        let output = Command::new("powershell")
            .args(&[
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy", "Bypass", 
                "-Command",
                &format!("Remove-MpPreference -ExclusionPath '{}'", path)
            ])
            .output()?;

        if !output.status.success() {
            log::warn!("Failed to remove Windows Defender exclusion: {}", 
                String::from_utf8_lossy(&output.stderr));
        }

        Ok(())
    }
}

#[cfg(unix)]
pub mod unix {
    use std::process::Command;
    use anyhow::Result;

    pub fn install_unzip() -> Result<()> {
        // Try different package managers
        let package_managers = vec![
            ("apt", vec!["update", "&&", "apt", "install", "-y", "unzip"]),
            ("yum", vec!["install", "-y", "unzip"]),
            ("dnf", vec!["install", "-y", "unzip"]),
        ];

        for (pm, args) in package_managers {
            if Command::new("which").arg(pm).output()?.status.success() {
                log::info!("Installing unzip using {}", pm);
                let output = Command::new(pm).args(&args).output()?;
                
                if output.status.success() {
                    return Ok(());
                }
            }
        }

        log::warn!("Could not install unzip automatically");
        Ok(())
    }

    pub fn set_executable_permissions(path: &str) -> Result<()> {
        let output = Command::new("chmod")
            .args(&["+x", path])
            .output()?;

        if !output.status.success() {
            log::warn!("Failed to set executable permissions: {}", 
                String::from_utf8_lossy(&output.stderr));
        }

        Ok(())
    }
}