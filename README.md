# audit-tree.sh - Shai-Hulud npm Worm Scanner

A comprehensive security scanner for detecting the Shai-Hulud npm worm and similar supply chain attacks in your local repositories.

## 🚨 About the Shai-Hulud Worm

Shai-Hulud is a self-replicating worm targeting the npm ecosystem that injects malicious code into packages, steals developer and cloud tokens, and propagates via compromised maintainer accounts and GitHub workflows. First observed in mid-September 2025, it has rapidly spread across hundreds of npm packages.

### Key Characteristics:
- **Propagation**: Modifies `package.json` to add malicious `postinstall` scripts
- **Execution**: Runs `bundle.js` during package installation
- **Data Theft**: Harvests npm, GitHub, AWS, and GCP tokens
- **Exfiltration**: Creates public GitHub repos and uses GitHub Actions to leak data
- **Lateral Movement**: Uses stolen credentials to compromise additional packages

## 🛡️ What This Script Does

`audit-tree.sh` performs deep scanning of your local repositories to detect:

- ✅ Malicious `bundle.js` files with known hashes
- ✅ Suspicious `postinstall` scripts in `package.json`
- ✅ The `shai-hulud-workflow.yml` GitHub Action
- ✅ Exposed tokens in `.npmrc` files
- ✅ Webhook exfiltration URLs (specifically `webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`)
- ✅ System-level infection files (`/tmp/processor.sh`, `/tmp/migrate-repos.sh`)
- ✅ Repositories with `shai-hulud` branches
- ✅ Suspicious `-migration` repository suffixes

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/audit-tree.git
cd audit-tree

# Make the script executable
chmod +x audit-tree.sh
```

### Basic Usage

```bash
# Scan current directory and all subdirectories
./audit-tree.sh

# Scan a specific directory
./audit-tree.sh /path/to/projects

# Generate JSON output for CI/CD pipelines
./audit-tree.sh . --json
```

## 📋 Requirements

### Required:
- **zsh** (default on macOS, available on Linux)
- **git** (for repository analysis)

### Optional but Recommended:
- **jq** - For enhanced `package.json` analysis
- **ripgrep (rg)** - For faster scanning of large codebases
- **sha256sum** or **shasum** - For file hash verification

The script will detect missing dependencies and continue with reduced functionality.

## 🔍 Detection Examples

### Human-Readable Output
```bash
$ ./audit-tree.sh

🔍 Enhanced NPM Worm Scanner - Checking for Shai-Hulud indicators
================================================================
Scanning directory: .
Started at:         Thu 18 Sep 10:52:13 BST 2025

🔬 Checking for system-level indicators...

📁 Building file index and checking for suspicious files/directories...
⚠️  FOUND: bundle.js in a package root
   Location: ./vulnerable-package/
   🚨 CRITICAL: Hash matches known malicious bundle.js!

🚨 CRITICAL: Found malicious 'postinstall' script in ./package.json
   Script:   postinstall: "node bundle.js"

🌐 Scanning all non-binary files for string indicators...
🚨 CRITICAL: Found known malicious webhook URL!
   File:    ./src/exfiltrate.js
   Match:   webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7

================================================================
🚨 Found 3 potential indicator(s). Manual review is required.

📄 Suspicious files requiring immediate manual review:
   - ./vulnerable-package/bundle.js
   - ./package.json
   - ./src/exfiltrate.js
```

### JSON Output for CI/CD
```bash
$ ./audit-tree.sh . --json | jq
{
  "scan_completed": "2025-09-18T09:52:13Z",
  "scan_directory": ".",
  "issues_found": 3,
  "scanned_git_directories": 5,
  "scanned_package_json": 12,
  "suspicious_files": [
    "./vulnerable-package/bundle.js",
    "./package.json",
    "./src/exfiltrate.js"
  ],
  "missing_dependencies": [],
  "tools_used": {
    "grep": "rg",
    "hash": "sha256sum"
  }
}
```

## 🎯 Known Indicators of Compromise (IOCs)

The script searches for these specific indicators:

### Files and Hashes
- **bundle.js** with SHA-256: `46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09`
- **.github/workflows/shai-hulud-workflow.yml**
- **/tmp/processor.sh** and **/tmp/migrate-repos.sh** (system infection)

### Package Modifications
- `postinstall` scripts executing `node bundle.js`
- Suspicious lifecycle hooks with `curl`, `wget`, or `eval()`
- Force-published packages with `npm publish --force`

### Repository Artifacts
- Branches named **shai-hulud**
- Public repositories named **Shai-Hulud** containing `data.json`
- Repositories with **-migration** suffix (indicating exposed private code)

### Network Indicators
- Webhook URL: `webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7`
- TruffleHog filesystem scans of root directory

## 🛠️ Advanced Usage

### CI/CD Integration

```yaml
# GitHub Actions example
- name: Scan for npm worm
  run: |
    chmod +x audit-tree.sh
    if ! ./audit-tree.sh . --json > scan-results.json; then
      echo "::error::Potential npm worm detected!"
      cat scan-results.json | jq -r '.suspicious_files[]' | while read file; do
        echo "::warning file=$file::Suspicious file detected"
      done
      exit 1
    fi
```

### Automated Monitoring

```bash
# Add to cron for daily scans
0 2 * * * /path/to/audit-tree.sh /home/projects --json >> /var/log/npm-worm-scan.log 2>&1
```

## 🚑 If Infections Are Found

1. **Immediately rotate all credentials**:
   - npm tokens
   - GitHub personal access tokens
   - Cloud provider credentials (AWS, GCP, Azure)

2. **Clean infected packages**:
   ```bash
   # Remove malicious files
   rm -f bundle.js
   rm -f .github/workflows/shai-hulud-workflow.yml
   
   # Remove malicious postinstall scripts
   npm pkg delete scripts.postinstall
   ```

3. **Audit and revert packages**:
   ```bash
   # Check npm publish history
   npm view <package-name> time --json
   
   # Revert to clean version
   npm install <package-name>@<clean-version> --save-exact
   ```

4. **Review GitHub repositories**:
   - Delete any "Shai-Hulud" or "-migration" repositories
   - Check GitHub Actions logs for data exfiltration
   - Review audit logs for unauthorized access

## 🔒 Prevention Best Practices

1. **Enable 2FA** on npm and GitHub accounts
2. **Use granular access tokens** with minimal permissions
3. **Implement package publishing restrictions**
4. **Regular dependency audits**: `npm audit`
5. **Lock file verification** before deployments
6. **Monitor for unexpected package publishes**

## 📊 Performance Considerations

- Uses `ripgrep` when available for 10x faster scanning
- Excludes `node_modules` and `.git` directories by default
- Single-pass file indexing minimizes disk I/O
- Efficient pattern matching with fixed strings where possible

## 🤝 Contributing

Contributions are welcome! Please submit:
- Additional IOCs from real-world detections
- Performance improvements
- Support for additional package managers (yarn, pnpm)
- YARA/Semgrep rule equivalents

## 📚 References

- [ReversingLabs: Shai-Hulud Worm Analysis](https://www.reversinglabs.com/blog/shai-hulud-worm-npm)
- [Kaspersky: Supply Chain Attack Details](https://www.kaspersky.com/blog/tinycolor-shai-hulud-supply-chain-attack/54315/)
- [UpGuard: Attack Explained](https://www.upguard.com/blog/the-shai-hulud-attack-explained)

## ⚖️ License

MIT License - See [LICENSE](LICENSE) file for details

## ⚠️ Disclaimer

This tool is provided for security auditing purposes only. Always verify findings manually before taking action. The authors are not responsible for any misuse or damage caused by this tool.

---

**Stay safe out there!** 🛡️ If this tool helped you detect an infection, please consider sharing your experience (anonymized) to help improve detection patterns.
