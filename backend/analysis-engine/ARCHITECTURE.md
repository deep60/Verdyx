# Analysis Engine Service Analysis

## Overview
The `analysis-engine` is a core microservice responsible for deep inspection of artifacts (files, URLs, emails). It is built with **Rust** for performance and safety, designed as an asynchronous, event-driven system.

### Tech Stack
-   **Language**: Rust
-   **Runtime**: Tokio (Async I/O)
-   **Database**: PostgreSQL (via `sqlx`)
-   **Messaging/Queue**: Redis (Job Queue), Kafka (Events)
-   **Storage**: AWS S3 / MinIO (Artifact storage)
-   **Sandboxing**: Docker

## Architecture
The service operates on a queue-based worker pattern:
1.  **Submission**: Jobs are queued in Redis/Kafka.
2.  **Scheduling**: `scheduler.rs` manages job priority (Low/Medium/High/Critical) and dispatch, supporting strategies like FIFO, Priority, and Fair Share.
3.  **Execution**: `worker.rs` pulls jobs and orchestrates the analysis pipeline.
4.  **Analysis**: Artifacts pass through multiple scanners and analyzers.
5.  **Persistence**: Results are stored in Postgres; blobs (files/pcaps) in S3.

## Key Components

### 1. Core Models (`src/models/`)
-   **`ScanJob`**: Represents a unit of work. Tracks status (Queued, Processing, Completed), retries, and priority.
-   **`AnalysisResult`**: Aggregates findings from all engines (Verdict, Confidence, Severity).
-   **`ThreatIndicator`**: standardized IoC format (FileHash, IP, Domain, etc.) mapped to MITRE ATT&CK.

### 2. Queue System (`src/queue/`)
-   **`consumer.rs`**: listens to Redis `analysis_queue`.
-   **`scheduler.rs`**: Advanced scheduling logic. Handles timeouts, retries, and worker slot management.
-   **`worker.rs`**: The "brain" of execution. Downloads artifacts, instantiates analyzers, accumulates results, and updates DB/Kafka.

### 3. Analyzers & Scanners (`src/analyzers/`, `src/scanners/`)
The system distinguishes between *Scanners* (artifact-type specific parsing) and *Analyzers* (detection logic).

**Scanners:**
-   **`FileScanner`**: Magic bytes, entropy (packing detection), string extraction, embedded file extraction (PE/ZIP).
-   **`UrlScanner`**: Domain reputation, phishing patterns, SSL validation, content analysis.
-   **`ArchiveScanner`**: Recursive extraction, zip bomb detection, nested archive handling.
-   **`EmailScanner`**: SPF/DKIM/DMARC checks, header analysis, attachment scanning.

**Analyzers:**
-   **`StaticAnalyzer`** (`static_analyzer.rs`):
    -   Uses `goblin` to parse PE, ELF, Mach-O binaries.
    -   **Entropy Analysis**: Detects packed/encrypted code (`entropy_threshold: 7.0`).
    -   **String Analysis**: Extracts URLs, IPs, Emails, Crypto addresses (BTC/ETH).
    -   **Pattern Matching**: regex-based detection for injection, keylogging, and ransomware notes.
-   **`DynamicAnalyzer`** (`dynamic_analyzer.rs`):
    -   Orchestrates Docker-based sandboxing with configurable resource limits (CPU, RAM).
    -   Captures **DynamicBehavior**: File ops, Registry changes, Network traffic (pcap), Process trees, Screenshots.
    -   Generates comprehensive reports using `ReportGenerator`.
-   **`YaraEngine`** (`yara_engine.rs`):
    -   Manages compilation and execution of YARA rules.
    -   Supports rule namespaces, tags, and metadata.
    -   *Current State*: Compilation logic is simulated/placeholder.
-   **`MlAnalyzer`** (`ml_analyzer.rs`):
    -   **Runtime**: ONNX Runtime (`ort` crate).
    -   **Models**: `ThreatClassifier` (multi-class) and `AnomalyDetector`.
    -   **Features**: Extracts file properties, PE characteristics, and static features for inference.
-   **`HeuristicEngine`** (`heuristic_engine.rs`):
    -   Regex-based behavioral heuristics.
    -   **Categories**: Malware, Exploit (ROP/Shellcode), Network (C2), Obfuscation (Base64/XOR), Ransomware, Cryptomining.
    -   Assigns severity scores and confidence levels.
-   **`SignatureMatcher`** (`signature_matcher.rs`):
    -   Generic signature engine supporting: File Hashes, Binary Patterns (Hex), String Patterns, PE Section Hashes.
    -   Includes caching and parallel matching.
-   **`ClamAvAnalyzer`** (`clamav_analyzer.rs`):
    -   Integrates with local/remote ClamAV daemon via TCP.
    -   Maps virus names to `ThreatCategory` (e.g., "Worm", "Trojan").
-   **`HashAnalyzer`** (`hash_analyzer.rs`):
    -   Queries external threat intel (VirusTotal, MalwareBazaar, HybridAnalysis) for each source with a key.
    -   A hash no source knows gets no verdict; only the EICAR test file is recognised offline.
    -   Implements **Resilience**: Circuit Breakers, Rate Limiters, Retries.
-   **abuse.ch lookups** (`scanners/abuse_ch.rs`, used by the URL scanner):
    -   URLhaus (exact URL, and hosts still serving malware) and ThreatFox (URL, domain, `ip:port` IOCs).
    -   Needs `ABUSE_CH_API_KEY` (free, https://auth.abuse.ch/); without it these sources are skipped.
    -   Results are cached for 30 minutes; a feed outage is reported, never fatal.

### 4. Sandbox Subsystem (`src/sandbox/`)
Provides isolated execution for dynamic analysis.
-   **`container.rs`**: Manages Docker containers.
    -   Custom image: `verdyx/sandbox` (Ubuntu-based with Wine, Python, Node, strace, tcpdump).
    -   Security: `no-new-privileges`, `seccomp=unconfined`, mostly no network access (unless configured).
-   **`monitor.rs`**: Real-time behavior capture.
    -   **File System**: Uses `strace` to track `open`, `write`, `unlink`.
    -   **Network**: Uses `netstat` and `tcpdump` (pcap capture).
    -   **Processes**: Tracks process creation via `ps`.
    -   **Screenshots**: Captures visual output periodically using `scrot`.

### 5. Storage (`src/storage/`)
-   **`database.rs`**: Postgres CRUD for Jobs and Results using connection pooling.
-   **`s3_client.rs`**: Handles upload/download of artifacts to S3-compatible storage.

## Data Flow
1.  **Ingestion**: `api-gateway` (presumably) or other service pushes a job to Redis.
2.  **Scheduling**: `scheduler` picks up the job.
3.  **Processing**: `worker` claims the job.
    -   Downloads file from S3.
    -   Runs `FileScanner` -> `StaticAnalyzer` -> `YaraEngine` -> `HashAnalyzer`.
    -   If executable/script -> Runs `DynamicAnalyzer` (Sandbox).
4.  **Result Aggregation**: `worker` combines all findings into `AnalysisResult`.
5.  **Verdict**: Calculates final `ThreatVerdict` (Malicious/Benign) based on detection consensus.
6.  **Notification**: Updates Postgres, sends event to Kafka/Redis PubSub.
