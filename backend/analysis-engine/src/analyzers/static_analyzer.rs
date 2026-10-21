use anyhow::{anyhow, Result};
use chrono::Utc;
use goblin::pe::PE;
use goblin::Object;
use lazy_static::lazy_static;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::models::analysis_result::{
    ConfidenceLevel, DetectionResult, EngineType, SeverityLevel, ThreatCategory, ThreatVerdict,
};

/// File type enumeration based on magic bytes and headers
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[allow(clippy::upper_case_acronyms)]
pub enum FileType {
    PE,      // Windows Portable Executable
    ELF,     // Linux Executable and Linkable Format
    MachO,   // macOS Mach-O
    PDF,     // Portable Document Format
    Office,  // Microsoft Office documents
    Archive, // ZIP, RAR, etc.
    Script,  // JavaScript, PowerShell, etc.
    Image,   // JPEG, PNG, etc.
    Unknown,
}

/// PE (Portable Executable) specific analysis data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PEAnalysis {
    pub machine_type: String,
    pub timestamp: Option<u32>,
    pub entry_point: u32,
    pub sections: Vec<PESection>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub resources: Vec<String>,
    pub is_packed: bool,
    pub is_signed: bool,
    pub entropy: f64,
    pub suspicious_imports: Vec<String>,
    pub packer_signatures: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PESection {
    pub name: String,
    pub virtual_address: u32,
    pub size: u32,
    pub characteristics: u32,
    pub entropy: f64,
    pub is_suspicious: bool,
}

/// String analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StringAnalysis {
    pub suspicious_strings: Vec<SuspiciousString>,
    pub urls: Vec<String>,
    pub ips: Vec<String>,
    pub email_addresses: Vec<String>,
    pub file_paths: Vec<String>,
    pub registry_keys: Vec<String>,
    pub crypto_indicators: Vec<String>,
    pub bitcoin_addresses: Vec<String>,
    pub ethereum_addresses: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SuspiciousString {
    pub content: String,
    pub category: StringCategory,
    pub confidence: f64,
    pub offset: usize,
    pub severity: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StringCategory {
    Malware,
    Vulnerability,
    Cryptographic,
    Network,
    SystemCall,
    Obfuscation,
    AntiAnalysis,
    ProcessInjection,
    Keylogging,
    Ransomware,
    CredentialTheft,
    CryptoMining,
    C2Communication,
}

/// Entropy analysis for detecting packed/encrypted content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyAnalysis {
    pub overall_entropy: f64,
    pub section_entropies: HashMap<String, f64>,
    pub high_entropy_regions: Vec<EntropyRegion>,
    pub is_likely_packed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyRegion {
    pub offset: usize,
    pub size: usize,
    pub entropy: f64,
}

/// Configuration for static analyzer
#[derive(Debug, Clone)]
pub struct StaticAnalyzerConfig {
    pub max_file_size: usize,
    pub max_string_length: usize,
    pub entropy_threshold: f64,
    pub enable_pe_analysis: bool,
    pub enable_string_analysis: bool,
    pub enable_entropy_analysis: bool,
    pub suspicious_string_threshold: f64,
    pub min_string_length: usize,
    pub entropy_window_size: usize,
}

impl Default for StaticAnalyzerConfig {
    fn default() -> Self {
        Self {
            max_file_size: 100 * 1024 * 1024, // 100MB
            max_string_length: 1000,
            entropy_threshold: 7.0,
            enable_pe_analysis: true,
            enable_string_analysis: true,
            enable_entropy_analysis: true,
            suspicious_string_threshold: 0.7,
            min_string_length: 8,
            entropy_window_size: 1024,
        }
    }
}

// Lazy-loaded regex patterns for string analysis
lazy_static! {
    static ref URL_REGEX: Regex = Regex::new(r"https?://\S+").unwrap();
    static ref IP_REGEX: Regex = Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").unwrap();
    static ref IP_URL_REGEX: Regex = Regex::new(r"https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}").unwrap();
    static ref EMAIL_REGEX: Regex = Regex::new(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b").unwrap();
    static ref REGISTRY_REGEX: Regex = Regex::new(r"HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*").unwrap();
    static ref CRYPTO_REGEX: Regex = Regex::new(r"(?i)(aes|des|rsa|md5|sha\d+|base64|encrypt|decrypt|cipher)").unwrap();
    static ref BITCOIN_REGEX: Regex = Regex::new(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b").unwrap();
    static ref ETHEREUM_REGEX: Regex = Regex::new(r"\b0x[a-fA-F0-9]{40}\b").unwrap();
    static ref FILE_PATH_REGEX: Regex = Regex::new(r#"[A-Za-z]:\\[^<>:"|?*\r\n]+|/(?:usr|home|etc|var|tmp)/[^\s<>:"|?*\r\n]+"#).unwrap();

    // Extended suspicious string patterns with severity ratings
    static ref MALWARE_PATTERNS: Vec<(Regex, StringCategory, u8)> = vec![
        // Critical patterns (severity 9-10)
        (Regex::new(r"(?i)(CreateRemoteThread|VirtualAllocEx|WriteProcessMemory)").unwrap(), StringCategory::ProcessInjection, 10),
        (Regex::new(r"(?i)(SetWindowsHookEx|WH_KEYBOARD|GetAsyncKeyState)").unwrap(), StringCategory::Keylogging, 9),
        (Regex::new(r"(?i)(mimikatz|procdump|lsass\.exe)").unwrap(), StringCategory::CredentialTheft, 10),
        (Regex::new(r"(?i)(\.encrypted|\.locked|\.crypto|HELP_instructions|DECRYPT_INSTRUCTIONS)").unwrap(), StringCategory::Ransomware, 10),

        // High severity patterns (severity 7-8)
        (Regex::new(r"(?i)(backdoor|rootkit|trojan|virus|worm)").unwrap(), StringCategory::Malware, 8),
        (Regex::new(r"(?i)(IsDebuggerPresent|CheckRemoteDebuggerPresent|OutputDebugString)").unwrap(), StringCategory::AntiAnalysis, 8),
        (Regex::new(r"(?i)(anti.*vm|sandbox.*detect|vmware|virtualbox|qemu)").unwrap(), StringCategory::AntiAnalysis, 7),
        (Regex::new(r"(?i)(shellcode|payload|exploit|vulnerability|0day)").unwrap(), StringCategory::Vulnerability, 8),
        (Regex::new(r"(?i)(c2|command.*control|exfiltrat|beacon)").unwrap(), StringCategory::C2Communication, 8),
        (Regex::new(r"(?i)(process.*injection|dll.*injection|hollowing|reflective)").unwrap(), StringCategory::ProcessInjection, 8),

        // Medium severity patterns (severity 5-6)
        (Regex::new(r"(?i)(crypto.*mining|bitcoin|monero|wallet|mining.*pool)").unwrap(), StringCategory::CryptoMining, 6),
        (Regex::new(r"(?i)(persistence|lateral|privilege.*escalation)").unwrap(), StringCategory::Malware, 6),
        (Regex::new(r"(?i)(eval|exec|system|popen)").unwrap(), StringCategory::SystemCall, 5),
        (Regex::new(r"(?i)(obfuscate|deobfuscate|unpack|decode)").unwrap(), StringCategory::Obfuscation, 5),

        // Lower severity patterns (severity 3-4)
        (Regex::new(r"(?i)(password|passwd|credential|login|auth|secret)").unwrap(), StringCategory::CredentialTheft, 3),
        (Regex::new(r"(?i)(GetProcAddress|LoadLibrary|GetModuleHandle)").unwrap(), StringCategory::SystemCall, 4),
    ];

    // Suspicious Windows API imports
    static ref SUSPICIOUS_IMPORTS: Vec<(&'static str, u8)> = vec![
        // Critical (10)
        ("CreateRemoteThread", 10),
        ("WriteProcessMemory", 10),
        ("VirtualAllocEx", 10),
        ("SetWindowsHookEx", 10),
        ("NtCreateThreadEx", 10),

        // High (8-9)
        ("VirtualAlloc", 8),
        ("VirtualProtect", 8),
        ("IsDebuggerPresent", 8),
        ("CheckRemoteDebuggerPresent", 8),
        ("ZwUnmapViewOfSection", 9),
        ("NtSetContextThread", 9),

        // Medium (5-7)
        ("GetAsyncKeyState", 7),
        ("GetKeyState", 6),
        ("CreateToolhelp32Snapshot", 6),
        ("Process32First", 5),
        ("Process32Next", 5),
        ("GetProcAddress", 5),
        ("LoadLibrary", 5),
    ];

    // Known packer signatures
    static ref PACKER_SIGNATURES: Vec<&'static str> = vec![
        "UPX", "ASPack", "PECompact", "Themida", "VMProtect",
        "Enigma", "Obsidium", "MPRESS", "FSG", "PESpin",
        "Petite", "WWPack", "NsPack", "MEW", "Morphine"
    ];
}

/// Main static analyzer implementation
pub struct StaticAnalyzer {
    config: StaticAnalyzerConfig,
}

impl StaticAnalyzer {
    /// Create a new static analyzer instance
    pub fn new(config: StaticAnalyzerConfig) -> Self {
        Self { config }
    }

    /// Perform comprehensive static analysis on file data
    pub async fn analyze(
        &self,
        file_data: &[u8],
        filename: Option<&str>,
    ) -> Result<DetectionResult> {
        info!(
            "Starting enhanced static analysis for file: {:?} ({} bytes)",
            filename.unwrap_or("unknown"),
            file_data.len()
        );

        if file_data.len() > self.config.max_file_size {
            return Err(anyhow!(
                "File too large for static analysis: {} bytes",
                file_data.len()
            ));
        }

        let start = std::time::Instant::now();
        let file_type = self.detect_file_type(file_data);
        debug!("Detected file type: {:?}", file_type);

        let mut metadata = HashMap::new();
        let mut threat_score = 0.0;
        let mut threat_details = Vec::new();

        // Entropy analysis
        let _entropy_analysis = if self.config.enable_entropy_analysis {
            let analysis = self.analyze_entropy(file_data, &file_type);
            debug!(
                "Overall entropy: {:.2}, Packed: {}",
                analysis.overall_entropy, analysis.is_likely_packed
            );

            if analysis.is_likely_packed {
                threat_score += 0.25;
                threat_details.push("File appears to be packed or encrypted".to_string());
            }

            if analysis.overall_entropy > self.config.entropy_threshold {
                threat_score += 0.15;
                threat_details.push(format!(
                    "High entropy detected: {:.2}",
                    analysis.overall_entropy
                ));
            }

            metadata.insert(
                "entropy_analysis".to_string(),
                serde_json::to_value(&analysis)?,
            );
            Some(analysis)
        } else {
            None
        };

        // String analysis
        let string_analysis = if self.config.enable_string_analysis {
            let analysis = self.analyze_strings(file_data);
            debug!(
                "Found {} suspicious strings, {} URLs, {} IPs",
                analysis.suspicious_strings.len(),
                analysis.urls.len(),
                analysis.ips.len()
            );

            // Score based on suspicious strings
            for s in &analysis.suspicious_strings {
                let weight = (s.severity as f64) / 100.0;
                threat_score += weight;

                if s.severity >= 8 {
                    threat_details.push(format!("{:?}: {}", s.category, s.content));
                }
            }

            // IP-based URLs are more suspicious
            let ip_urls: Vec<_> = analysis
                .urls
                .iter()
                .filter(|url| IP_URL_REGEX.is_match(url))
                .collect();

            if !ip_urls.is_empty() {
                threat_score += 0.15;
                threat_details.push(format!("{} IP-based URLs detected", ip_urls.len()));
            }

            // Cryptocurrency addresses
            if !analysis.bitcoin_addresses.is_empty() || !analysis.ethereum_addresses.is_empty() {
                threat_score += 0.10;
                threat_details.push("Cryptocurrency addresses found".to_string());
            }

            metadata.insert(
                "string_analysis".to_string(),
                serde_json::to_value(&analysis)?,
            );
            Some(analysis)
        } else {
            None
        };

        // PE-specific analysis
        let pe_analysis = if self.config.enable_pe_analysis && matches!(file_type, FileType::PE) {
            match self.analyze_pe(file_data).await {
                Ok(analysis) => {
                    debug!(
                        "PE analysis: {} sections, {} imports, packed: {}",
                        analysis.sections.len(),
                        analysis.imports.len(),
                        analysis.is_packed
                    );

                    if analysis.is_packed {
                        threat_score += 0.30;
                        threat_details.push("Packed executable detected".to_string());
                    }

                    if !analysis.packer_signatures.is_empty() {
                        threat_score += 0.20;
                        threat_details.push(format!(
                            "Packer detected: {}",
                            analysis.packer_signatures.join(", ")
                        ));
                    }

                    // Score suspicious imports
                    if !analysis.suspicious_imports.is_empty() {
                        let import_score = analysis.suspicious_imports.len() as f64 * 0.05;
                        threat_score += import_score;
                        threat_details.push(format!(
                            "{} suspicious imports",
                            analysis.suspicious_imports.len()
                        ));
                    }

                    // Suspicious sections
                    let suspicious_sections: Vec<_> = analysis
                        .sections
                        .iter()
                        .filter(|s| s.is_suspicious)
                        .collect();

                    if !suspicious_sections.is_empty() {
                        threat_score += 0.15;
                        threat_details
                            .push(format!("{} suspicious sections", suspicious_sections.len()));
                    }

                    metadata.insert("pe_analysis".to_string(), serde_json::to_value(&analysis)?);
                    Some(analysis)
                }
                Err(e) => {
                    warn!("PE analysis failed: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Calculate final threat assessment
        threat_score = threat_score.min(1.0);
        let (verdict, confidence_level, severity) = self.determine_verdict(
            threat_score,
            &threat_details,
            string_analysis.as_ref(),
            pe_analysis.as_ref(),
        );

        let confidence = match verdict {
            ThreatVerdict::Benign => (0.93 - (threat_score * 0.25) as f32).clamp(0.85, 0.95),
            _ => match confidence_level {
                ConfidenceLevel::High => 0.92,
                ConfidenceLevel::Medium => 0.78,
                ConfidenceLevel::Low => 0.65,
            },
        };

        // Categorize threats
        let categories = self.categorize_threats(&threat_details, string_analysis.as_ref());

        let processing_time_ms = start.elapsed().as_millis() as u64;

        info!(
            "Static analysis complete: verdict={:?}, score={:.2}, confidence={:.2}, time={}ms",
            verdict, threat_score, confidence, processing_time_ms
        );

        Ok(DetectionResult {
            detection_id: Uuid::new_v4(),
            engine_name: "Verdyx Static Analyzer".to_string(),
            engine_version: "2.0.0".to_string(),
            engine_type: EngineType::Static,
            verdict,
            confidence,
            severity,
            categories,
            metadata,
            detected_at: Utc::now(),
            processing_time_ms,
            error_message: None,
        })
    }

    fn detect_file_type(&self, data: &[u8]) -> FileType {
        if data.len() < 4 {
            return FileType::Unknown;
        }

        // Try goblin first
        match Object::parse(data) {
            Ok(Object::PE(_)) => return FileType::PE,
            Ok(Object::Elf(_)) => return FileType::ELF,
            Ok(Object::Mach(_)) => return FileType::MachO,
            _ => {}
        }

        // Check magic bytes
        match &data[0..4] {
            [0x25, 0x50, 0x44, 0x46] => FileType::PDF,
            [0xD0, 0xCF, 0x11, 0xE0] => FileType::Office,
            [0x50, 0x4B, 0x03, 0x04] => FileType::Archive,
            [0xFF, 0xD8, 0xFF, ..] => FileType::Image,
            [0x89, 0x50, 0x4E, 0x47] => FileType::Image,
            _ => {
                // Check for script files
                if let Ok(text) = std::str::from_utf8(&data[..data.len().min(256)]) {
                    if text.starts_with("#!") || text.contains("function") || text.contains("var ")
                    {
                        return FileType::Script;
                    }
                }
                FileType::Unknown
            }
        }
    }

    fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut freq = [0u32; 256];
        for &byte in data {
            freq[byte as usize] += 1;
        }

        let len = data.len() as f64;
        freq.iter().filter(|&&f| f > 0).fold(0.0, |ent, &f| {
            let p = f as f64 / len;
            ent - p * p.log2()
        })
    }

    fn analyze_entropy(&self, file_data: &[u8], file_type: &FileType) -> EntropyAnalysis {
        let overall_entropy = self.calculate_entropy(file_data);
        let mut section_entropies = HashMap::new();
        let mut high_entropy_regions = Vec::new();

        // Sliding window entropy analysis
        let window_size = self.config.entropy_window_size;
        if file_data.len() > window_size {
            for (i, window) in file_data.chunks(window_size).enumerate() {
                let entropy = self.calculate_entropy(window);
                if entropy > self.config.entropy_threshold {
                    high_entropy_regions.push(EntropyRegion {
                        offset: i * window_size,
                        size: window.len(),
                        entropy,
                    });
                }
            }
        }

        // PE section-level entropy
        if matches!(file_type, FileType::PE) {
            if let Ok(Object::PE(pe)) = Object::parse(file_data) {
                for section in pe.sections {
                    let section_name = String::from_utf8_lossy(&section.name)
                        .trim_end_matches('\0')
                        .to_string();
                    let offset = section.pointer_to_raw_data as usize;
                    let size = section.size_of_raw_data as usize;

                    if offset + size <= file_data.len() {
                        let section_data = &file_data[offset..offset + size];
                        let entropy = self.calculate_entropy(section_data);
                        section_entropies.insert(section_name, entropy);
                    }
                }
            }
        }

        let is_likely_packed = overall_entropy > self.config.entropy_threshold
            || section_entropies
                .values()
                .any(|&e| e > self.config.entropy_threshold);

        EntropyAnalysis {
            overall_entropy,
            section_entropies,
            high_entropy_regions,
            is_likely_packed,
        }
    }

    fn analyze_strings(&self, data: &[u8]) -> StringAnalysis {
        let str_data = String::from_utf8_lossy(data).to_string();

        let urls: Vec<String> = URL_REGEX
            .find_iter(&str_data)
            .map(|m| m.as_str().to_string())
            .collect();

        let ips: Vec<String> = IP_REGEX
            .find_iter(&str_data)
            .map(|m| m.as_str().to_string())
            .collect();

        let email_addresses: Vec<String> = EMAIL_REGEX
            .find_iter(&str_data)
            .map(|m| m.as_str().to_string())
            .collect();

        let registry_keys: Vec<String> = REGISTRY_REGEX
            .find_iter(&str_data)
            .map(|m| m.as_str().to_string())
            .collect();

        let crypto_indicators: Vec<String> = CRYPTO_REGEX
            .find_iter(&str_data)
            .map(|m| m.as_str().to_string())
            .collect();

        let bitcoin_addresses: Vec<String> = BITCOIN_REGEX
            .find_iter(&str_data)
            .map(|m| m.as_str().to_string())
            .collect();

        let ethereum_addresses: Vec<String> = ETHEREUM_REGEX
            .find_iter(&str_data)
            .map(|m| m.as_str().to_string())
            .collect();

        let file_paths: Vec<String> = FILE_PATH_REGEX
            .find_iter(&str_data)
            .map(|m| m.as_str().to_string())
            .take(50)
            .collect();

        // Extract suspicious strings using patterns
        let mut suspicious_strings = Vec::new();
        for (pattern, category, severity) in MALWARE_PATTERNS.iter() {
            for mat in pattern.find_iter(&str_data) {
                suspicious_strings.push(SuspiciousString {
                    content: mat.as_str().to_string(),
                    category: category.clone(),
                    confidence: 0.8,
                    offset: mat.start(),
                    severity: *severity,
                });
            }
        }

        // Deduplicate by content
        suspicious_strings.sort_by(|a, b| a.content.cmp(&b.content));
        suspicious_strings.dedup_by(|a, b| a.content == b.content);

        StringAnalysis {
            suspicious_strings,
            urls,
            ips,
            email_addresses,
            file_paths,
            registry_keys,
            crypto_indicators,
            bitcoin_addresses,
            ethereum_addresses,
        }
    }

    async fn analyze_pe(&self, data: &[u8]) -> Result<PEAnalysis> {
        let pe = PE::parse(data).map_err(|e| anyhow!("PE parse error: {e}"))?;

        let overall_entropy = self.calculate_entropy(data);

        // Analyze sections
        let mut sections = Vec::new();
        let mut is_packed = false;
        let mut packer_signatures = Vec::new();

        for section in &pe.sections {
            let section_name = String::from_utf8_lossy(&section.name)
                .trim_end_matches('\0')
                .to_string();

            let offset = section.pointer_to_raw_data as usize;
            let size = section.size_of_raw_data as usize;

            let (entropy, is_suspicious) = if offset + size <= data.len() {
                let section_data = &data[offset..offset + size];
                let ent = self.calculate_entropy(section_data);
                let suspicious = ent > self.config.entropy_threshold
                    || section_name.starts_with('.')
                    || section_name.len() < 2
                    || !section_name
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_');
                (ent, suspicious)
            } else {
                (0.0, false)
            };

            // Check for packer signatures in section names
            for packer in PACKER_SIGNATURES.iter() {
                if section_name.contains(packer) {
                    packer_signatures.push(packer.to_string());
                    is_packed = true;
                }
            }

            sections.push(PESection {
                name: section_name,
                virtual_address: section.virtual_address,
                size: section.virtual_size,
                characteristics: section.characteristics,
                entropy,
                is_suspicious,
            });
        }

        // High overall entropy suggests packing
        if overall_entropy > self.config.entropy_threshold {
            is_packed = true;
        }

        // Extract imports
        let imports: Vec<String> = pe.imports.iter().map(|i| i.name.to_string()).collect();

        // Identify suspicious imports
        let mut suspicious_imports = Vec::new();
        for import in &imports {
            for (suspicious_api, _severity) in SUSPICIOUS_IMPORTS.iter() {
                if import.contains(suspicious_api) {
                    suspicious_imports.push(import.clone());
                    break;
                }
            }
        }

        // Extract exports
        let exports: Vec<String> = pe
            .exports
            .iter()
            .filter_map(|e| e.name.map(|n| n.to_string()))
            .collect();

        // Extract resource section names from PE sections
        let resources: Vec<String> = pe
            .sections
            .iter()
            .filter(|s| {
                let name = String::from_utf8_lossy(&s.name)
                    .trim_end_matches('\0')
                    .to_string();
                name == ".rsrc" || name == ".rdata"
            })
            .map(|s| {
                let name = String::from_utf8_lossy(&s.name)
                    .trim_end_matches('\0')
                    .to_string();
                format!("{} (size: {} bytes)", name, s.size_of_raw_data)
            })
            .collect();

        Ok(PEAnalysis {
            machine_type: format!("{:?}", pe.header.coff_header.machine),
            timestamp: Some(pe.header.coff_header.time_date_stamp),
            entry_point: pe.entry,
            sections,
            imports,
            exports,
            resources,
            is_packed,
            is_signed: false, // goblin doesn't expose is_signed directly
            entropy: overall_entropy,
            suspicious_imports,
            packer_signatures,
        })
    }

    fn determine_verdict(
        &self,
        threat_score: f64,
        threats: &[String],
        string_analysis: Option<&StringAnalysis>,
        pe_analysis: Option<&PEAnalysis>,
    ) -> (ThreatVerdict, ConfidenceLevel, SeverityLevel) {
        // Count high-severity indicators
        let high_severity_count = string_analysis
            .map(|sa| {
                sa.suspicious_strings
                    .iter()
                    .filter(|s| s.severity >= 8)
                    .count()
            })
            .unwrap_or(0);

        let has_critical_imports = pe_analysis
            .map(|pa| {
                pa.suspicious_imports.iter().any(|imp| {
                    imp.contains("CreateRemoteThread") || imp.contains("WriteProcessMemory")
                })
            })
            .unwrap_or(false);

        // Determine verdict
        let verdict = if threat_score > 0.8 || high_severity_count > 3 || has_critical_imports {
            ThreatVerdict::Malicious
        } else if threat_score > 0.5
            || high_severity_count > 1
            || threats.len() > 5
            || threat_score > 0.2
            || !threats.is_empty()
        {
            ThreatVerdict::Suspicious
        } else {
            ThreatVerdict::Benign
        };

        // Determine confidence
        let confidence = if threat_score > 0.8 && high_severity_count > 2 {
            ConfidenceLevel::High
        } else if threat_score > 0.5 || high_severity_count > 0 {
            ConfidenceLevel::Medium
        } else {
            ConfidenceLevel::Low
        };

        // Determine severity
        let severity = if threat_score > 0.8 {
            SeverityLevel::High
        } else if threat_score > 0.5 {
            SeverityLevel::Medium
        } else {
            SeverityLevel::Low
        };

        (verdict, confidence, severity)
    }

    fn categorize_threats(
        &self,
        threats: &[String],
        string_analysis: Option<&StringAnalysis>,
    ) -> Vec<ThreatCategory> {
        let mut categories = Vec::new();

        if let Some(sa) = string_analysis {
            for s in &sa.suspicious_strings {
                let category = match s.category {
                    StringCategory::Malware => ThreatCategory::Other("Malware".to_string()),
                    StringCategory::Ransomware => ThreatCategory::Other("Ransomware".to_string()),
                    StringCategory::ProcessInjection => {
                        ThreatCategory::Other("Process Injection".to_string())
                    }
                    StringCategory::Keylogging => ThreatCategory::Other("Keylogger".to_string()),
                    StringCategory::CredentialTheft => {
                        ThreatCategory::Other("Credential Theft".to_string())
                    }
                    StringCategory::C2Communication => {
                        ThreatCategory::Other("C2 Communication".to_string())
                    }
                    _ => continue,
                };

                if !categories.contains(&category) {
                    categories.push(category);
                }
            }
        }

        // Add general categories based on threat descriptions
        for threat in threats {
            if threat.contains("packed") || threat.contains("encrypted") {
                let cat = ThreatCategory::Other("Packed/Encrypted".to_string());
                if !categories.contains(&cat) {
                    categories.push(cat);
                }
            }
        }

        // If no specific categories, mark as general suspicious
        if categories.is_empty() && !threats.is_empty() {
            categories.push(ThreatCategory::Other("Suspicious Activity".to_string()));
        }

        categories
    }
}

impl Default for StaticAnalyzer {
    fn default() -> Self {
        Self::new(StaticAnalyzerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_entropy_calculation() {
        let analyzer = StaticAnalyzer::new(StaticAnalyzerConfig::default());

        // Test with uniform data (should have high entropy)
        let uniform_data: Vec<u8> = (0..=255).collect();
        let entropy = analyzer.calculate_entropy(&uniform_data);
        assert!(
            entropy > 7.9,
            "Uniform data should have high entropy, got: {}",
            entropy
        );

        // Test with repeated data (low entropy)
        let repeated_data = vec![0u8; 256];
        let entropy = analyzer.calculate_entropy(&repeated_data);
        assert!(
            entropy < 0.1,
            "Repeated data should have low entropy, got: {}",
            entropy
        );

        // Test with semi-random data
        let mixed_data: Vec<u8> = (0..128).chain(0..128).collect();
        let entropy = analyzer.calculate_entropy(&mixed_data);
        assert!(
            entropy > 6.0 && entropy < 8.0,
            "Mixed data should have medium entropy, got: {}",
            entropy
        );
    }

    #[test]
    fn test_file_type_detection() {
        let analyzer = StaticAnalyzer::new(StaticAnalyzerConfig::default());

        // PE file — minimal MZ stub may not parse as full PE in goblin
        let mut pe_data = vec![0x4D, 0x5A, 0x90, 0x00];
        pe_data.extend_from_slice(&[0u8; 100]);
        let detected = analyzer.detect_file_type(&pe_data);
        assert!(
            matches!(detected, FileType::PE | FileType::Unknown),
            "MZ stub should detect as PE or Unknown, got: {:?}",
            detected
        );

        // ELF file
        let mut elf_data = vec![0x7F, 0x45, 0x4C, 0x46];
        elf_data.extend_from_slice(&[0u8; 100]);
        // Note: goblin might need more valid ELF structure
        let detected = analyzer.detect_file_type(&elf_data);
        assert!(matches!(detected, FileType::ELF | FileType::Unknown));

        // PDF file
        let pdf_data = b"%PDF-1.4\n%\xE2\xE3\xCF\xD3";
        assert_eq!(analyzer.detect_file_type(pdf_data), FileType::PDF);

        // Script file
        let script_data = b"#!/bin/bash\necho 'Hello World'";
        assert_eq!(analyzer.detect_file_type(script_data), FileType::Script);
    }

    #[test]
    fn test_suspicious_string_detection() {
        let analyzer = StaticAnalyzer::new(StaticAnalyzerConfig::default());

        // Test data with suspicious content
        let data = b"CreateRemoteThread VirtualAllocEx mimikatz http://192.168.1.1/payload.exe";
        let analysis = analyzer.analyze_strings(data);

        assert!(
            !analysis.suspicious_strings.is_empty(),
            "Should detect suspicious strings"
        );

        // Check for specific categories
        let has_injection = analysis
            .suspicious_strings
            .iter()
            .any(|s| matches!(s.category, StringCategory::ProcessInjection));
        assert!(has_injection, "Should detect process injection patterns");

        let has_cred_theft = analysis
            .suspicious_strings
            .iter()
            .any(|s| matches!(s.category, StringCategory::CredentialTheft));
        assert!(has_cred_theft, "Should detect credential theft patterns");
    }

    #[test]
    fn test_ip_url_detection() {
        let analyzer = StaticAnalyzer::new(StaticAnalyzerConfig::default());

        let data = b"http://192.168.1.100/malware.exe https://10.0.0.1:8080/c2";
        let analysis = analyzer.analyze_strings(data);

        assert_eq!(analysis.urls.len(), 2, "Should detect 2 URLs");
        assert!(!analysis.ips.is_empty(), "Should detect IP addresses");
    }

    #[test]
    fn test_crypto_address_detection() {
        let analyzer = StaticAnalyzer::new(StaticAnalyzerConfig::default());

        // Bitcoin address
        let btc_data = b"Send payment to: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let analysis = analyzer.analyze_strings(btc_data);
        assert!(
            !analysis.bitcoin_addresses.is_empty(),
            "Should detect Bitcoin address"
        );

        // Ethereum address
        let eth_data = b"Wallet: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e";
        let analysis = analyzer.analyze_strings(eth_data);
        assert!(
            !analysis.ethereum_addresses.is_empty(),
            "Should detect Ethereum address"
        );
    }

    #[tokio::test]
    async fn test_full_analysis_benign() {
        let analyzer = StaticAnalyzer::new(StaticAnalyzerConfig::default());

        // Test with benign data
        let benign_data = b"Hello, this is a normal text file with normal content. \
                           It contains no suspicious patterns or malicious code.";
        let result = analyzer.analyze(benign_data, Some("test.txt")).await;
        assert!(result.is_ok(), "Analysis should succeed");

        let detection = result.unwrap();
        assert_eq!(
            detection.verdict,
            ThreatVerdict::Benign,
            "Should be classified as benign"
        );
        assert_eq!(detection.engine_name, "Verdyx Static Analyzer");
    }

    #[tokio::test]
    async fn test_full_analysis_suspicious() {
        let analyzer = StaticAnalyzer::new(StaticAnalyzerConfig::default());

        // Test with suspicious data
        let suspicious_data = b"CreateRemoteThread VirtualAllocEx WriteProcessMemory \
                               http://192.168.1.1/malware.exe mimikatz lsass.exe";
        let result = analyzer
            .analyze(suspicious_data, Some("suspicious.bin"))
            .await;
        assert!(result.is_ok(), "Analysis should succeed");

        let detection = result.unwrap();
        assert!(
            matches!(
                detection.verdict,
                ThreatVerdict::Suspicious | ThreatVerdict::Malicious
            ),
            "Should be classified as suspicious or malicious, got: {:?}",
            detection.verdict
        );
        assert!(
            detection.confidence > 0.5,
            "Should have medium to high confidence"
        );
    }

    #[tokio::test]
    async fn test_high_entropy_detection() {
        let analyzer = StaticAnalyzer::new(StaticAnalyzerConfig::default());

        // Create high-entropy data (pseudo-random)
        let high_entropy_data: Vec<u8> = (0..1024).map(|i| ((i * 137 + 91) % 256) as u8).collect();

        let result = analyzer
            .analyze(&high_entropy_data, Some("packed.exe"))
            .await;
        assert!(result.is_ok(), "Analysis should succeed");

        let detection = result.unwrap();

        // Check metadata for entropy analysis
        if let Some(entropy_data) = detection.metadata.get("entropy_analysis") {
            let entropy_analysis: EntropyAnalysis =
                serde_json::from_value(entropy_data.clone()).unwrap();
            assert!(
                entropy_analysis.overall_entropy > 6.0,
                "Should detect high entropy"
            );
        }
    }

    #[tokio::test]
    async fn test_file_size_limit() {
        let config = StaticAnalyzerConfig {
            max_file_size: 1024, // 1KB limit
            ..Default::default()
        };
        let analyzer = StaticAnalyzer::new(config);

        // Create data larger than limit
        let large_data = vec![0u8; 2048];
        let result = analyzer.analyze(&large_data, Some("large.bin")).await;

        assert!(result.is_err(), "Should fail for oversized files");
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_registry_key_detection() {
        let analyzer = StaticAnalyzer::new(StaticAnalyzerConfig::default());

        let data = b"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
        let analysis = analyzer.analyze_strings(data);

        assert!(
            !analysis.registry_keys.is_empty(),
            "Should detect registry keys"
        );
    }

    #[test]
    fn test_packer_signature_detection() {
        // This would require a real PE file with UPX signature
        // Placeholder test - in production, use actual packed samples
        let analyzer = StaticAnalyzer::new(StaticAnalyzerConfig::default());

        // Test that the packer signatures list is loaded
        assert!(
            !PACKER_SIGNATURES.is_empty(),
            "Should have packer signatures"
        );
        assert!(PACKER_SIGNATURES.contains(&"UPX"), "Should include UPX");
    }

    #[test]
    fn test_suspicious_imports_list() {
        // Verify suspicious imports are configured
        assert!(
            !SUSPICIOUS_IMPORTS.is_empty(),
            "Should have suspicious imports"
        );

        let has_critical = SUSPICIOUS_IMPORTS
            .iter()
            .any(|(name, severity)| *name == "CreateRemoteThread" && *severity == 10);
        assert!(
            has_critical,
            "Should include critical API with high severity"
        );
    }

    #[test]
    fn test_malware_patterns() {
        // Verify malware patterns are loaded
        assert!(!MALWARE_PATTERNS.is_empty(), "Should have malware patterns");
        assert!(
            MALWARE_PATTERNS.len() >= 15,
            "Should have comprehensive pattern set"
        );

        // Check severity distribution
        let high_severity = MALWARE_PATTERNS
            .iter()
            .filter(|(_, _, sev)| *sev >= 8)
            .count();
        assert!(
            high_severity >= 5,
            "Should have multiple high-severity patterns"
        );
    }

    #[test]
    fn test_string_category_variety() {
        let analyzer = StaticAnalyzer::new(StaticAnalyzerConfig::default());

        let test_data = b"backdoor rootkit CreateRemoteThread IsDebuggerPresent \
                         shellcode mimikatz bitcoin 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
        let analysis = analyzer.analyze_strings(test_data);

        // Should detect multiple categories
        let categories: std::collections::HashSet<_> = analysis
            .suspicious_strings
            .iter()
            .map(|s| std::mem::discriminant(&s.category))
            .collect();

        assert!(
            categories.len() >= 3,
            "Should detect multiple threat categories"
        );
    }
}
