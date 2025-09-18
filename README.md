Below is a ready-to-use GitHub README that describes the Shai‑Hulud npm worm in depth, including indicators of compromise, attack flow, detection, and response. Each statement references public analyses and incident write‑ups.

# Shai‑Hulud npm Worm: Technical Overview and Detection Guide

Shai‑Hulud is a self‑replicating worm targeting the npm ecosystem that injects malicious code into packages, steals developer and cloud tokens, and propagates via compromised maintainer accounts and GitHub workflows.[2][4]
It executes through postinstall hooks, exfiltrates secrets to attacker infrastructure and public GitHub repos, and attempts to mass‑expose private repositories to accelerate credential theft and code leakage.[4][2]

## Key facts

- First observed mid‑September 2025 with rapid spread across hundreds of npm packages, including popular dependencies, via compromised maintainer accounts.[2]
- Propagation uses automated modification of victim‑maintained packages by adding a postinstall script that runs a malicious bundle.js on install.[2]
- Secrets theft targets npm, GitHub, AWS, and GCP tokens directly and via bundled secret‑scanning (e.g., TruffleHog) to harvest further credentials.[2]
- Exfiltration methods include creating a public GitHub repo named “Shai‑Hulud” containing data.json and a GitHub Actions workflow that sends data to webhook.site via double Base64 encoding.[4]

## Attack chain

1) Initial compromise  
- Maintainer account credentials are obtained (phishing, token leakage, or prior compromises) and used to publish tainted package versions under trusted names.[2]

2) Package modification and postinstall trigger  
- The worm adds a postinstall entry to package.json that executes bundle.js at install time, enabling execution on developer machines and CI agents that consume the compromised version.[2]

3) Secrets discovery and theft  
- The payload directly targets env vars and token locations for npm, GitHub, AWS, and GCP and invokes secret‑scanning to expand loot beyond standard locations.[2]

4) Exfiltration to attacker infrastructure  
- Two primary paths are used: creation of a public repo named “Shai‑Hulud” with a data.json containing stolen credentials/system info, and a GitHub Actions workflow “.github/workflows/shai‑hulud‑workflow.yml” that exfiltrates to webhook.site using encoded payloads.[4]

5) Lateral spread via maintainer privileges  
- With stolen npm credentials, the worm updates all packages the victim maintains, injecting the same postinstall + bundle.js mechanism to continue propagation.[2]

6) Repository exposure for data mining  
- The malware attempts to create public copies of private repos with a “‑migration” suffix to harvest embedded secrets and code for further exploitation.[2]

## Indicators of compromise (IOCs)

- Files and scripts  
  - package.json containing a postinstall running “node bundle.js” or equivalent suspicious installer scripts.[2]
  - Presence of bundle.js added to packages without legitimate justification in the project’s history.[2]
  - Malicious GitHub workflow: .github/workflows/shai‑hulud‑workflow.yml created on a branch named “shai‑hulud”.[4]

- GitHub artifacts and naming patterns  
  - Public repo named “Shai‑Hulud” under victim accounts containing data.json with encoded secrets and system info.[4]
  - Public “migration” repos created from private ones, with names suffixed by “‑migration” and descriptions referencing Shai‑Hulud migration.[2]

- Network/Exfil endpoints  
  - Outbound requests to webhook.site with specific UUID endpoints as documented in incident analyses, carrying double Base64‑encoded payloads.[4]

- Behavioral signals  
  - npm publish activity from atypical hosts or CI runners and forced publishes of many packages in a short span under a single maintainer.[2]
  - Postinstall execution spawning external tooling (e.g., secret scanners) and anomalous outbound network connections during install phases.[2]

## Impact

- Credential compromise of developer, registry, and cloud accounts enabling further package tampering, lateral movement, and data theft across organizations.[2]
- Exposure of private repositories and source code, enabling downstream attacks and long‑tail leakage of embedded secrets or sensitive IP.[2]

## Detection strategies

- Static scans of repos and package artifacts  
  - Search for package.json postinstall invoking bundle.js or other unexpected scripts and for the presence of bundle.js in release artifacts.[2]
  - Audit for .github/workflows/shai‑hulud‑workflow.yml, branches named “shai‑hulud,” and any public repos named “Shai‑Hulud” with data.json.[4]

- Inventory and SBOM checks  
  - Diff lockfiles (package‑lock.json/yarn.lock/pnpm‑lock.yaml) and artifact layers to find versions reported as compromised by public analyses and advisories.[2]

- Runtime and CI monitoring  
  - Alert on node processes executing installer‑time scripts initiating network egress or invoking secret scanners during npm/yarn/pnpm install phases.[2]
  - Monitor for unusual npm publish bursts and registry writes from non‑standard runners or developer endpoints outside known release workflows.[2]

- Network analytics  
  - Block/alert on webhook.site exfiltration domains and investigate any encoded POST bodies from build agents or developer machines.[4]

## Response and remediation

- Immediate token rotation  
  - Revoke and rotate npm, GitHub, and cloud tokens; invalidate PATs and organization‑level secrets that may have been accessed via Actions.[4]

- Package hygiene and cache purging  
  - Roll back affected packages to known‑good versions, clear npm caches on developer machines and CI workers, and reinstall from trusted locks.[4]

- GitHub cleanup  
  - Remove attacker‑created “Shai‑Hulud” repos and the malicious Actions workflow; review Actions logs for encoded data exfiltration events.[4]

- Hardening to prevent re‑infection  
  - Restrict who can publish to npm, enforce 2FA and granular tokens, protect private repos from public “migration,” and add approvals for public repo creation.[2]

## Why this worm spread quickly

- It abuses trusted maintainer privileges to insert itself into legitimate packages, piggybacking on the dependency graph and install lifecycle to execute widely.[2]
- Dual exfiltration channels (public repos and Actions to webhook.site) plus automated migration of private repos increase both visibility and data theft efficiency.[4]

## References

- ReversingLabs: In‑depth analysis of the self‑replicating npm worm, propagation via postinstall and bundle.js, token theft targets, and repo migration behavior.[2]
- Kaspersky: Exfiltration details via public “Shai‑Hulud” repos and GitHub Actions to webhook.site, and incident response guidance and outcomes.[4]

Contributions welcome. Please open issues or PRs with additional IOCs, safe YARA/Semgrep rules, and reproducible detections observed in real environments.[4][2]

[1](https://github.com/brunos3d/crysknife)
[2](https://www.reversinglabs.com/blog/shai-hulud-worm-npm)
[3](https://www.reversinglabs.com/blog/threat-actor-banana-squad-exploits-github-repos-in-new-campaign)
[4](https://www.kaspersky.com/blog/tinycolor-shai-hulud-supply-chain-attack/54315/)
[5](https://www.upguard.com/blog/the-shai-hulud-attack-explained)
[6](https://news.ycombinator.com/item?id=45260741)
[7](https://hackread.com/hackers-exploit-fake-github-repositories-gitvenom-malware/)
[8](https://github.com/orgs/community/discussions/173836)
[9](https://x.com/david_das_neves?lang=en-GB)
[10](https://hackread.com/silverrat-source-code-leaked-online-you-need-to-know/)
