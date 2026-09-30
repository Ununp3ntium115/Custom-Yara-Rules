# Makefile for cross-platform builds

.PHONY: all build build-release clean test fmt clippy cross-compile macos-arm64 macos-universal help

# Default target
all: build

# Build for current platform
build:
	cargo build

# Build release version
build-release:
	cargo build --release

# Cross-compile for all major platforms
cross-compile:
	@echo "Building for Windows x86_64..."
	cargo build --release --target x86_64-pc-windows-gnu
	@echo "Building for Linux x86_64..."
	cargo build --release --target x86_64-unknown-linux-gnu
	@echo "Building for macOS x86_64..."
	cargo build --release --target x86_64-apple-darwin
	@echo "Building for macOS arm64 (Apple Silicon)..."
	cargo build --release --target aarch64-apple-darwin
	@echo "Cross-compilation complete!"

# Apple Silicon only (run on a macOS host, or let CI do it: .github/workflows/build-macos.yml)
macos-arm64:
	cargo build --release --target aarch64-apple-darwin

# Universal macOS binary (arm64 + x86_64) — needs a macOS host for lipo
macos-universal:
	cargo build --release --target aarch64-apple-darwin
	cargo build --release --target x86_64-apple-darwin
	mkdir -p target/universal-apple-darwin/release
	lipo -create \
		target/aarch64-apple-darwin/release/pyro-thor \
		target/x86_64-apple-darwin/release/pyro-thor \
		-output target/universal-apple-darwin/release/pyro-thor
	lipo -info target/universal-apple-darwin/release/pyro-thor

# Run tests
test:
	cargo test

# Format code
fmt:
	cargo fmt

# Run clippy linter
clippy:
	cargo clippy -- -D warnings

# Clean build artifacts
clean:
	cargo clean
	rm -f scan_results.json
	rm -f *.log

# Package Thor (if Thor directory exists)
package-thor:
	@if [ -d "Thor" ]; then \
		echo "Packaging Thor directory..."; \
		zip -r Custom.DFIR.Yara.AllRules.zip Thor/; \
		echo "Package created: Custom.DFIR.Yara.AllRules.zip"; \
	else \
		echo "Thor directory not found. Please set up Thor binaries first."; \
	fi

# Install cross-compilation targets
install-targets:
	rustup target add x86_64-pc-windows-gnu
	rustup target add x86_64-unknown-linux-gnu
	rustup target add x86_64-apple-darwin
	rustup target add aarch64-apple-darwin

# Help
help:
	@echo "Available targets:"
	@echo "  build           - Build for current platform"
	@echo "  build-release   - Build release version"
	@echo "  cross-compile   - Build for all major platforms"
	@echo "  macos-arm64     - Build for Apple Silicon (aarch64-apple-darwin)"
	@echo "  macos-universal - Build a universal arm64 + x86_64 macOS binary"
	@echo "  test            - Run tests"
	@echo "  fmt             - Format code"
	@echo "  clippy          - Run linter"
	@echo "  clean           - Clean build artifacts"
	@echo "  package-thor    - Create Thor ZIP package"
	@echo "  install-targets - Install cross-compilation targets"
	@echo "  help            - Show this help"