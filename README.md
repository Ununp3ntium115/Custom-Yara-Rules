# Thor YARA Rules Package for Velociraptor

A Velociraptor artifact that makes it easy to run Thor YARA scans across your entire fleet. This Velociraptor artifact enables automated deployment and execution of Thor YARA scanning across your environment. It packages Thor binaries, YARA rules, and IOC signatures into a one unit that can be distributed to endpoints through Velociraptor. The artifact automatically handles binary selection based on the client's operating system and architecture, making it seamless to scan Windows, Linux, and macOS systems.


## Current Directory Structure
```
.
├── Custom.DFIR.Yara.AllRules.yaml  # Velociraptor artifact configuration
├── Custom.DFIR.Yara.AllRules.zip   # Packaged Thor for Velociraptor -> contains the below folder called "Thor" 
└── Thor/
    ├── config/                       # Thor configuration directory
    │   ├── directory-excludes.cfg    # Directory exclusion patterns
    │   ├── false_positive_filters.cfg # False positive filtering rules
    │   ├── thor-util.yml            # Thor utility configuration
    │   ├── thor.yml                 # Main Thor configuration
    │   ├── tmpl-action.yml          # Action template
    │   ├── tmpl-deepdive.yml        # Deep dive template
    │   ├── tmpl-log-to-share.yml    # Log sharing template
    │   └── tmpl-sigma.yml           # Sigma rule template
    ├── custom-signatures/           # Custom signatures directory
    │   ├── iocs/                    # Indicators of Compromise
    │   ├── misc/                    # Miscellaneous signatures
    │   └── yara/                    # YARA rules
    ├── config.yaml                  # Root configuration file
    ├── thor-lite-your_lic_here.lic  # Thor license file
    ├── thor-lite_386               # Linux/macOS x86 binary
    ├── thor-lite_386.exe           # Windows x86 binary
    ├── thor-lite_amd64             # Linux/macOS AMD64 binary
    └── thor-lite_amd64.exe         # Windows AMD64 binary
```

## Setup Instructions

1. Ensure you have the correct Thor binaries for your target platforms:
   - Windows AMD64: `thor-lite_amd64.exe`
   - Windows x86: `thor-lite_386.exe`
   - Linux/macOS AMD64: `thor-lite_amd64`
   - Linux/macOS x86: `thor-lite_386`

2. Place your Thor license file:
   - Rename your license to `thor-lite-your_lic_here.lic`
   - Place it in the Thor root directory

3. Configure YARA rules:
   - Add custom YARA rules to the `custom-signatures/` directory
   - Modify `config/config.yaml` as needed

4. Package for Velociraptor:
   - Zip the entire `Thor` directory
   - Upload to Velociraptor's server directory

## Usage

Once executed on clients to Velociraptor, the artifact will:
1. Download the Thor package to the client
2. Extract it to a temporary location
3. Run Thor with appropriate flags based on the OS
4. Clean up after execution

## Important Notes

- Ensure all binaries have proper execute permissions
- The artifact handles OS-specific paths and commands automatically
- The package will be extracted to:
  - Windows: `C:\Users\Public\`
  - Linux/macOS: `/var/tmp/`
- The artifact will automatically select the appropriate binary based on the client's architecture
