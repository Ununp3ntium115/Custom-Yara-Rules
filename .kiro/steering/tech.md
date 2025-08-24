# Technology Stack

## Core Technologies
- **Rust**: Primary programming language for multiplatform support
- **Tokio**: Async runtime for concurrent operations
- **Serde**: Serialization/deserialization for YAML and JSON
- **Reqwest**: HTTP client for Pyro server communication
- **Clap**: Command-line argument parsing
- **ReDB**: High-performance embedded database for YARA rules optimization
- **Thor YARA Scanner**: Core malware detection engine

## Build System & Deployment
- **Cargo**: Rust's built-in build system and package manager
- **Cross-compilation**: Support for Windows, Linux, and macOS targets
- **Static linking**: Self-contained binaries with minimal dependencies

## Common Commands

### Development & Building
```bash
# Build for current platform
cargo build --release

# Cross-compile for different targets
cargo build --release --target x86_64-pc-windows-gnu
cargo build --release --target x86_64-unknown-linux-gnu
cargo build --release --target x86_64-apple-darwin

# Run tests
cargo test

# Check code formatting
cargo fmt --check

# Run linter
cargo clippy
```

### Usage
```bash
# Run with default config
./pyro-thor

# Specify custom config and scan path
./pyro-thor -c custom-config.yaml -p /path/to/scan -o results.json

# Enable verbose logging
./pyro-thor -v

# Enterprise mode with ReDB optimization
./pyro-thor --enterprise-mode --redb-enabled --scan-uuid $(uuidgen)

# ReDB-optimized scanning
./pyro-thor --redb-enabled -v
```

### Packaging for Deployment
```bash
# Create Thor package (if not downloading from server)
zip -r Custom.DFIR.Yara.AllRules.zip Thor/
```

## Architecture Considerations
- **Cross-platform compatibility**: Artifact handles OS detection and binary selection automatically
- **Self-contained execution**: All dependencies packaged within the artifact
- **Cleanup automation**: Built-in cleanup routines prevent endpoint pollution
- **Security-first**: Includes Windows Defender exclusions and proper file permissions