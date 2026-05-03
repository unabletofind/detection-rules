<!-- ============================================================
  HOW TO USE THIS FILE
  ============================================================
  1. On GitHub, create a NEW repository named: detection-rules
  2. Make it PUBLIC.
  3. Add this file as README.md
  4. Create the folder structure shown below in the repo:
       detection-rules/
       ├── README.md (this file)
       ├── kql/
       │   └── powershell-encoded-commands.kql
       ├── spl/
       │   └── password-spray-detection.spl
       ├── sigma/
       │   └── onenote-suspicious-child-process.yml
       └── yara/
           └── stx-rat-cpuid-antivm.yar
  5. The actual rule contents are below this file in
     /mnt/user-data/outputs/detection-rules-samples/
  ============================================================
-->

# Detection Rules

Hunting queries and detection logic for SOC use. Mapped to MITRE ATT&CK, severity-tagged, and tested against real telemetry.

Maintained by [@unabletofind](https://github.com/unabletofind) — SOC Analyst, Hyderabad.

[![Portfolio](https://img.shields.io/badge/Portfolio-00ffe5?style=flat-square)](https://unabletofind.github.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square)](LICENSE)
![Last Updated](https://img.shields.io/github/last-commit/unabletofind/detection-rules?style=flat-square)

---

## Structure

```
detection-rules/
├── kql/        # KQL queries for Microsoft Sentinel & Defender XDR
├── spl/        # Splunk SPL searches
├── sigma/      # Platform-agnostic Sigma rules
└── yara/       # YARA signatures for malware detection
```

---

## Rule Index

### KQL (Microsoft Sentinel / Defender XDR)

| Rule | MITRE | Severity | Description |
|------|-------|----------|-------------|
| [PowerShell Encoded Commands](kql/powershell-encoded-commands.kql) | T1059.001, T1027 | High | Catches base64-encoded PowerShell — classic loader pattern |
| [AiTM Multi-ASN Sign-in](kql/aitm-multi-asn-signin.kql) | T1557, T1078.004 | High | Hunts adversary-in-the-middle session hijacks |
| [Office Spawning rundll32](kql/office-rundll32.kql) | T1218.011, T1204.002 | Medium | Cobalt Strike + macro loader pattern |
| [Impossible Travel — Tuned](kql/impossible-travel-tuned.kql) | T1078 | Low | Reduced-noise version of built-in rule |

### SPL (Splunk)

| Rule | MITRE | Severity | Description |
|------|-------|----------|-------------|
| [Password Spray Detection](spl/password-spray-detection.spl) | T1110.003 | High | Failed auth burst followed by success |

### Sigma

| Rule | MITRE | Severity | Description |
|------|-------|----------|-------------|
| [OneNote Suspicious Child Process](sigma/onenote-suspicious-child-process.yml) | T1204.002, T1059 | High | Phishing payload — OneNote spawning scripts/LOLBins |

### YARA

| Rule | Family | Description |
|------|--------|-------------|
| [STX RAT — CPUID Anti-VM](yara/stx-rat-cpuid-antivm.yar) | STX RAT | Detects CPUID-based sandbox evasion |

---

## How to Use

### For KQL rules (Sentinel / Defender XDR)
1. Copy the query from the `.kql` file
2. Paste into **Sentinel → Logs** or **Defender XDR → Advanced Hunting**
3. Adjust the `lookback` window if needed
4. Convert to a Custom Detection Rule if you want it to alert continuously

### For SPL rules (Splunk)
1. Copy the search from the `.spl` file
2. Paste into Splunk Search & Reporting
3. Save as a saved search or alert with your thresholds

### For Sigma rules
1. Use [`sigmac`](https://github.com/SigmaHQ/sigma) to convert to your SIEM's query language
2. Or import into a Sigma-aware platform (Wazuh, Elastic with Sigma plugin)

### For YARA rules
1. Compile with `yarac` or use directly with `yara`
2. Scan a file or directory: `yara stx-rat-cpuid-antivm.yar suspicious_sample.exe`

---

## Contributing

Found a false positive? Have an improvement? Open an issue or a PR — happy to discuss.

This is a personal collection so I review every PR carefully.

---

## Disclaimer

These rules are provided **as-is** for educational and defensive use. Always:
- Test in a non-production environment first
- Tune thresholds and exclusions for your environment
- Verify the rule fires on known-good test data before deploying to production

I'm not responsible for false positives or alert fatigue caused by un-tuned deployment.

---

## License

[MIT](LICENSE) — use these freely. Attribution appreciated but not required.

---

<sub>Maintained by Swetha Devi Sai Priya Bonu · [Portfolio](https://unabletofind.github.io/) · [LinkedIn](https://linkedin.com/in/bonu-swetha-devi-sai-priya)</sub>
