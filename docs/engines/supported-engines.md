# Supported Analysis Engines & Optional Scanner Guide

This document defines the official support tier, dependency requirements, health probing mechanisms, and maintenance procedures for the Verdyx threat analysis engine fleet.

---

## 1. Supported Default Engine Set (Tier 1)

These engines compile and run in the default configuration out-of-the-box on all supported platforms (macOS, Linux, Docker). They require **no external system packages, C-library bindings, external daemons, or machine learning runtime weights**.

| Engine ID | Name | Engine Type | Core Capabilities | Default Rules/Signatures Location |
| :--- | :--- | :--- | :--- | :--- |
| `static_analyzer` | Static Analyzer | Binary Analysis | PE/ELF/Mach-O parsing via Goblin, section table entropy calculation, extracted ASCII/Unicode string analysis. | Embedded heuristic rules |
| `hash_analyzer` | Hash Analyzer | Cryptographic Hashing | Computes SHA-256, MD5, SHA-1, BLAKE2/3, and queries cached threat reputation databases. | In-memory & Redis cache |
| `heuristic_engine` | Heuristic Engine | Behavioral Scoring | Regular expression pattern matching detecting API sequences, registry persistence, obfuscation, and shellcode primitives. | Embedded regex rules in `analyzers/heuristic_engine.rs` |
| `signature_matcher` | Signature Matcher | Signature Matching | High-throughput hash, hex byte sequence, and string pattern matching. | JSON definition files in `rules/signatures/*.json` |
| Built-in Scanners | File, URL, Archive, Email Scanners | Transport Protocols | ZIP/TAR extraction, URL syntax & live TLS certificate inspection, MIME parsing. | Protocol specifications |

### Health & Runtime Guarantees
- The default engines always report `online` upon engine initialization.
- If a signature file is malformed, `SignatureMatcher` logs a structured warning and continues with valid rules without crashing.
- No fabricated clean verdicts are returned if file parsing fails.

---

## 2. Optional Native Engines (Tier 2)

Optional engines provide deeper detection capabilities but depend on system libraries, running daemons, or trained neural weights. They are gated at compile-time via Cargo features and dynamically probed at runtime.

### 2.1 YARA Engine (`yara-engine`)
- **Cargo Feature**: `--features yara-engine`
- **System Dependencies**:
  - macOS: `brew install yara`
  - Debian/Ubuntu: `apt-get install -y libyara-dev`
- **Rule Path**: Configurable via `YARA_RULES_PATH` (default: `./rules/yara`)
- **Health Detection**:
  - The engine scans the rule directory recursively and compiles all `.yara` / `.yar` files.
  - If the directory is missing, empty, or compilation fails, the engine is reported as `unavailable` with the compiler error message. It will **not** pretend to be online.
- **Rules Supplied**:
  - `rules/yara/malware/eicar.yara`
  - `rules/yara/suspicious/php_webshell.yara`
  - `rules/yara/suspicious/packer_upx.yara`
  - `rules/yara/exploits/shellcode.yara`

### 2.2 ClamAV Daemon Scanner (`clamav`)
- **Cargo Feature**: `--features clamav`
- **System Dependencies**:
  - A running ClamAV daemon (`clamd`).
  - macOS: `brew install clamav && clamd`
  - Debian/Ubuntu: `apt-get install -y clamav-daemon clamav-freshclam`
- **Configuration**:
  - `CLAMAV_HOST`: Hostname or IP of the ClamAV daemon (default: `localhost`).
  - `CLAMAV_PORT`: TCP port (default: `3310`).
- **Health Detection**:
  - The engine performs an active `PING` TCP probe to `CLAMAV_HOST:CLAMAV_PORT`.
  - If the daemon does not respond with `PONG` or the socket times out, the engine status reports `unavailable` (`"clamd daemon unreachable on host:port"`).
  - During file analysis, if ClamAV cannot be contacted, an explicit `Unavailable` detection is logged; it does **not** generate a fake "clean" verdict.

### 2.3 Machine Learning ONNX Engine (`ml-engine`)
- **Cargo Feature**: `--features ml-engine`
- **System Dependencies**:
  - ONNX Runtime (`ort = "=2.0.0-rc.13"`).
  - Downloaded or pre-trained ONNX model files.
- **Model Path**: Configurable via `ML_MODEL_PATH` (default: `./ml_models/model.onnx`).
- **Health Detection**:
  - Probes existence and readability of the model artifact file.
  - If the model file is absent, reports status `unavailable` (`"Model artifact missing at path"`).

---

## 3. Engine Health & Status Reporting

Engine availability is transparently exposed to administrators and monitoring systems via two API endpoints:

### GET `/health`
Returns the service health status, package version, compile-time flags, and a `detailed_engines` breakdown.

### GET `/engines/status`
Returns a comprehensive capability report:
```json
{
  "totalEngines": 7,
  "activeEngines": 4,
  "unavailableEngines": 3,
  "defaultEngines": [
    "static_analyzer",
    "hash_analyzer",
    "heuristic_engine",
    "signature_matcher"
  ],
  "optionalEngines": [
    "yara_engine",
    "clamav",
    "ml_engine"
  ],
  "engines": [
    {
      "id": "static_analyzer",
      "name": "Static Binary Analyzer",
      "engineType": "static",
      "isOptional": false,
      "status": "online",
      "version": "0.1.0",
      "details": "Static binary format and entropy analysis active"
    },
    {
      "id": "signature_matcher",
      "name": "Signature Matcher",
      "engineType": "signature",
      "isOptional": false,
      "status": "online",
      "version": "0.1.0",
      "details": "6 signatures loaded across pattern types"
    },
    {
      "id": "clamav",
      "name": "ClamAV Daemon",
      "engineType": "antivirus",
      "isOptional": true,
      "status": "unavailable",
      "version": "0.1.0",
      "details": "Optional engine compiled with feature flag clamav",
      "error": "clamd daemon unreachable at localhost:3310"
    }
  ]
}
```

---

## 4. Update and Versioning Procedures

### 4.1 Signature Updates
1. **JSON Signatures**: Add new definitions to `backend/analysis-engine/rules/signatures/`. The format requires:
   ```json
   {
     "id": "SIG-XYZ",
     "name": "Threat-Name",
     "signature_type": "StringPattern | FileHash | BinaryPattern",
     "threat_family": "Family",
     "severity": "Info | Low | Medium | High | Critical",
     "patterns": [ { "pattern_type": "String", "value": "needle" } ],
     "description": "Explanation",
     "metadata": {},
     "enabled": true
   }
   ```
2. **Hot-Reload / Restart**: Restarting the `analysis-engine` process automatically reloads and compiles all `.json` and `.yara` definitions without needing database migrations.

### 4.2 Safe Verification & Testing
Test samples are located in `backend/analysis-engine/tests/samples/`:
- `clean_sample.txt`: Benign baseline verifying zero false positives.
- `eicar_test.com`: Standard EICAR string verifying signature matching and YARA detection pipelines without biological malware risk.
- `webshell_sample.php`: Verifies heuristic and YARA indicator detection.

Automated verification can be executed at any time via:
```bash
cargo +1.94.1 test -p analysis-engine --test engine_validation
```
