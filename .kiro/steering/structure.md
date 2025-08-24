# Project Structure

## Repository Organization

### Root Level Files
- `Cargo.toml` - Rust project configuration and dependencies
- `config.yaml` - Default configuration file
- `Custom.DFIR.Yara.AllRules.zip` - Packaged Thor distribution (gitignored)
- `README.md` - Project documentation and setup instructions
- `.gitignore` - Excludes Thor binaries and generated packages

### Source Code Structure
```
src/
├── main.rs          # Application entry point and CLI
├── config.rs        # Configuration management
├── platform.rs      # Platform-specific operations
├── scanner.rs       # Thor scanner wrapper
├── executor.rs      # Main execution logic
└── hooks/           # Enterprise hooks and integrations
    ├── mod.rs       # Hooks module exports
    └── yara_rules_redb.rs  # ReDB YARA rules optimization
```

### Expected Thor Directory Structure (Not in Git)
The `Thor/` directory contains the actual scanning components but is excluded from version control:

```
Thor/
├── config/                       # Thor configuration files
│   ├── directory-excludes.cfg    # Directory exclusion patterns
│   ├── false_positive_filters.cfg # False positive filtering
│   ├── thor-util.yml            # Utility configuration
│   ├── thor.yml                 # Main Thor configuration
│   └── tmpl-*.yml               # Configuration templates
├── custom-signatures/           # Detection signatures
│   ├── iocs/                    # Indicators of Compromise
│   ├── misc/                    # Miscellaneous signatures
│   └── yara/                    # YARA rules directory
├── config.yaml                  # Root configuration
├── thor-lite-your_lic_here.lic  # License file
└── thor-lite_*                  # Platform-specific binaries
```

## File Naming Conventions
- **Artifact files**: `Custom.{Category}.{Name}.{Type}.yaml`
- **Binary naming**: `thor-lite_{architecture}[.exe]`
- **Configuration files**: Lowercase with hyphens or underscores
- **License files**: Include placeholder text for customization

## Key Architectural Patterns
- **Modular Rust design**: Separated concerns across modules (config, platform, scanner, executor, hooks)
- **Async/await**: Non-blocking I/O operations using Tokio
- **Cross-platform compatibility**: Platform-specific code isolated in platform module
- **Configuration-driven**: YAML-based configuration with sensible defaults
- **Error handling**: Comprehensive error handling with anyhow and thiserror
- **Self-contained execution**: Automatic environment setup and cleanup
- **ReDB integration**: High-performance embedded database for YARA rules optimization
- **Enterprise hooks**: Extensible hook system for advanced integrations