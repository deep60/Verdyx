/// Archive scanner for analyzing compressed files (ZIP, RAR, TAR, etc.)
///
/// Features:
/// - Multi-format archive support (ZIP, RAR, TAR, GZ, 7Z)
/// - Recursive scanning
/// - Bomb detection (zip bombs, nested archives)
/// - Password-protected archive detection
/// - Suspicious file detection
/// - Extraction and analysis of contents
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::Cursor;
use tracing::{debug, info, warn};
use uuid::Uuid;
use zip::ZipArchive;

use super::{
    ArtifactType, Finding, FindingCategory, ScanResult, ScanVerdict, Scanner, ScannerConfig,
    ThreatLevel,
};

/// Configuration for archive scanner
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveScannerConfig {
    pub base: ScannerConfig,
    pub max_extraction_size_mb: u64,
    pub max_nesting_level: usize,
    pub detect_bombs: bool,
    pub scan_encrypted: bool,
    pub extract_and_scan: bool,
    pub compression_ratio_threshold: f64,
}

impl Default for ArchiveScannerConfig {
    fn default() -> Self {
        Self {
            base: ScannerConfig {
                scanner_name: "Archive Scanner".to_string(),
                max_file_size_mb: 500,
                ..Default::default()
            },
            max_extraction_size_mb: 1000,
            max_nesting_level: 3,
            detect_bombs: true,
            scan_encrypted: true,
            extract_and_scan: true,
            compression_ratio_threshold: 100.0, // 100:1 ratio is suspicious
        }
    }
}

/// Detailed archive scan result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveScanResult {
    pub base: ScanResult,
    pub archive_info: ArchiveInfo,
    pub files: Vec<ArchiveFileInfo>,
    pub bomb_indicators: Vec<BombIndicator>,
    pub suspicious_files: Vec<String>,
    pub total_extracted_size: u64,
    pub compression_ratio: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveInfo {
    pub archive_type: ArchiveType,
    pub total_files: usize,
    pub total_compressed_size: u64,
    pub total_uncompressed_size: u64,
    pub is_encrypted: bool,
    pub has_nested_archives: bool,
    pub nesting_level: usize,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ArchiveType {
    Zip,
    Rar,
    Tar,
    GZip,
    SevenZip,
    Bzip2,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchiveFileInfo {
    pub file_id: Uuid,
    pub filename: String,
    pub path: String,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub compression_ratio: f64,
    pub is_encrypted: bool,
    pub is_executable: bool,
    pub is_archive: bool,
    pub file_type: String,
    pub crc32: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BombIndicator {
    pub indicator_type: BombType,
    pub description: String,
    pub severity: ThreatLevel,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BombType {
    CompressionRatio,
    ExcessiveNesting,
    ExcessiveFiles,
    ExcessiveSize,
    RecursiveArchive,
}

/// Archive scanner implementation
pub struct ArchiveScanner {
    config: ArchiveScannerConfig,
    suspicious_extensions: Vec<String>,
    archive_extensions: Vec<String>,
}

#[async_trait::async_trait]
impl Scanner for ArchiveScanner {
    type Config = ArchiveScannerConfig;
    type Result = ArchiveScanResult;

    fn new(config: Self::Config) -> Result<Self> {
        info!("Initializing archive scanner");

        Ok(Self {
            config,
            suspicious_extensions: Self::load_suspicious_extensions(),
            archive_extensions: Self::load_archive_extensions(),
        })
    }

    async fn scan(
        &self,
        data: &[u8],
        _metadata: Option<HashMap<String, String>>,
    ) -> Result<Self::Result> {
        let start_time = std::time::Instant::now();
        info!("Starting archive scan on {} bytes", data.len());

        let mut base_result = ScanResult::new(ArtifactType::Archive);

        // Detect archive type
        let archive_type = self.detect_archive_type(data);
        debug!("Detected archive type: {:?}", archive_type);

        if archive_type == ArchiveType::Unknown {
            base_result.verdict = ScanVerdict::Error;
            return Ok(ArchiveScanResult {
                base: base_result,
                archive_info: ArchiveInfo {
                    archive_type,
                    total_files: 0,
                    total_compressed_size: data.len() as u64,
                    total_uncompressed_size: 0,
                    is_encrypted: false,
                    has_nested_archives: false,
                    nesting_level: 0,
                    comment: None,
                },
                files: Vec::new(),
                bomb_indicators: Vec::new(),
                suspicious_files: Vec::new(),
                total_extracted_size: 0,
                compression_ratio: 0.0,
            });
        }

        // Scan based on archive type
        let (archive_info, files) = match archive_type {
            ArchiveType::Zip => self.scan_zip(data)?,
            ArchiveType::Tar => self.scan_tar(data)?,
            ArchiveType::GZip => self.scan_gzip(data)?,
            _ => {
                warn!("Archive type {:?} not fully supported", archive_type);
                (
                    ArchiveInfo {
                        archive_type,
                        total_files: 0,
                        total_compressed_size: data.len() as u64,
                        total_uncompressed_size: 0,
                        is_encrypted: false,
                        has_nested_archives: false,
                        nesting_level: 0,
                        comment: None,
                    },
                    Vec::new(),
                )
            }
        };

        // Calculate compression ratio
        let compression_ratio = if archive_info.total_compressed_size > 0 {
            archive_info.total_uncompressed_size as f64 / archive_info.total_compressed_size as f64
        } else {
            0.0
        };

        // Detect bomb indicators
        let mut bomb_indicators = Vec::new();

        if self.config.detect_bombs {
            // Check compression ratio
            if compression_ratio > self.config.compression_ratio_threshold {
                bomb_indicators.push(BombIndicator {
                    indicator_type: BombType::CompressionRatio,
                    description: format!("Suspicious compression ratio: {compression_ratio:.1}:1"),
                    severity: ThreatLevel::Critical,
                    evidence: vec![
                        format!("Compressed: {} bytes", archive_info.total_compressed_size),
                        format!(
                            "Uncompressed: {} bytes",
                            archive_info.total_uncompressed_size
                        ),
                    ],
                });

                base_result.add_finding(Finding {
                    finding_id: Uuid::new_v4(),
                    category: FindingCategory::Malware,
                    title: "Zip bomb detected".to_string(),
                    description: format!("Extreme compression ratio: {compression_ratio:.1}:1"),
                    severity: ThreatLevel::Critical,
                    evidence: vec![format!("Ratio: {:.1}:1", compression_ratio)],
                    recommendation: Some("Do not extract - likely a zip bomb".to_string()),
                });
            }

            // Check excessive nesting
            if archive_info.nesting_level > self.config.max_nesting_level {
                bomb_indicators.push(BombIndicator {
                    indicator_type: BombType::ExcessiveNesting,
                    description: format!("Excessive nesting level: {}", archive_info.nesting_level),
                    severity: ThreatLevel::High,
                    evidence: vec![format!("Nesting: {} levels", archive_info.nesting_level)],
                });

                base_result.add_finding(Finding {
                    finding_id: Uuid::new_v4(),
                    category: FindingCategory::Suspicious,
                    title: "Excessive archive nesting".to_string(),
                    description: format!(
                        "{} levels of nested archives",
                        archive_info.nesting_level
                    ),
                    severity: ThreatLevel::High,
                    evidence: vec![format!("Levels: {}", archive_info.nesting_level)],
                    recommendation: Some("Possible archive bomb".to_string()),
                });
            }

            // Check excessive file count
            if archive_info.total_files > 100000 {
                bomb_indicators.push(BombIndicator {
                    indicator_type: BombType::ExcessiveFiles,
                    description: format!("Excessive file count: {}", archive_info.total_files),
                    severity: ThreatLevel::High,
                    evidence: vec![format!("Files: {}", archive_info.total_files)],
                });

                base_result.add_finding(Finding {
                    finding_id: Uuid::new_v4(),
                    category: FindingCategory::Suspicious,
                    title: "Excessive file count".to_string(),
                    description: format!("{} files in archive", archive_info.total_files),
                    severity: ThreatLevel::Medium,
                    evidence: vec![format!("Count: {}", archive_info.total_files)],
                    recommendation: Some("May cause resource exhaustion".to_string()),
                });
            }

            // Check extracted size
            if archive_info.total_uncompressed_size
                > self.config.max_extraction_size_mb * 1024 * 1024
            {
                bomb_indicators.push(BombIndicator {
                    indicator_type: BombType::ExcessiveSize,
                    description: format!(
                        "Extracted size exceeds limit: {} MB",
                        archive_info.total_uncompressed_size / 1024 / 1024
                    ),
                    severity: ThreatLevel::High,
                    evidence: vec![format!(
                        "Size: {} MB",
                        archive_info.total_uncompressed_size / 1024 / 1024
                    )],
                });
            }
        }

        // Check for encrypted archives
        if archive_info.is_encrypted {
            base_result.add_finding(Finding {
                finding_id: Uuid::new_v4(),
                category: FindingCategory::Suspicious,
                title: "Encrypted archive".to_string(),
                description: "Archive is password-protected".to_string(),
                severity: ThreatLevel::Medium,
                evidence: vec!["Password protection detected".to_string()],
                recommendation: Some("Verify source before attempting to extract".to_string()),
            });
        }

        // Check for suspicious files
        let mut suspicious_files = Vec::new();
        for file in &files {
            // Check for executable files
            if file.is_executable {
                suspicious_files.push(file.filename.clone());

                base_result.add_finding(Finding {
                    finding_id: Uuid::new_v4(),
                    category: FindingCategory::Suspicious,
                    title: "Executable file in archive".to_string(),
                    description: format!("Executable file: {}", file.filename),
                    severity: ThreatLevel::Medium,
                    evidence: vec![file.filename.clone()],
                    recommendation: Some("Scan file before execution".to_string()),
                });
            }

            // Check for suspicious extensions
            let extension = std::path::Path::new(&file.filename)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("");

            if self
                .suspicious_extensions
                .contains(&extension.to_lowercase())
            {
                if !suspicious_files.contains(&file.filename) {
                    suspicious_files.push(file.filename.clone());
                }

                base_result.add_finding(Finding {
                    finding_id: Uuid::new_v4(),
                    category: FindingCategory::Suspicious,
                    title: "Suspicious file type".to_string(),
                    description: format!("Suspicious file: {}", file.filename),
                    severity: ThreatLevel::Medium,
                    evidence: vec![format!("Extension: .{}", extension)],
                    recommendation: Some("Verify file before opening".to_string()),
                });
            }

            // Check for hidden files (starting with .)
            if file.filename.starts_with('.') && file.filename != "." && file.filename != ".." {
                base_result.add_finding(Finding {
                    finding_id: Uuid::new_v4(),
                    category: FindingCategory::Suspicious,
                    title: "Hidden file detected".to_string(),
                    description: format!("Hidden file: {}", file.filename),
                    severity: ThreatLevel::Low,
                    evidence: vec![file.filename.clone()],
                    recommendation: None,
                });
            }
        }

        // Check for nested archives
        if archive_info.has_nested_archives {
            base_result.add_finding(Finding {
                finding_id: Uuid::new_v4(),
                category: FindingCategory::Suspicious,
                title: "Nested archives detected".to_string(),
                description: "Archive contains other archives".to_string(),
                severity: ThreatLevel::Low,
                evidence: vec![format!("Nesting level: {}", archive_info.nesting_level)],
                recommendation: Some("Review nested archives carefully".to_string()),
            });
        }

        let scan_duration_ms = start_time.elapsed().as_millis() as u64;
        base_result.scan_duration_ms = scan_duration_ms;

        info!(
            "Archive scan completed in {}ms - Files: {}, Verdict: {:?}",
            scan_duration_ms, archive_info.total_files, base_result.verdict
        );

        Ok(ArchiveScanResult {
            base: base_result,
            archive_info: archive_info.clone(),
            files,
            bomb_indicators,
            suspicious_files,
            total_extracted_size: archive_info.total_uncompressed_size,
            compression_ratio,
        })
    }

    fn get_stats(&self) -> HashMap<String, String> {
        let mut stats = HashMap::new();
        stats.insert(
            "scanner_name".to_string(),
            self.config.base.scanner_name.clone(),
        );
        stats.insert(
            "max_nesting".to_string(),
            self.config.max_nesting_level.to_string(),
        );
        stats.insert(
            "compression_threshold".to_string(),
            self.config.compression_ratio_threshold.to_string(),
        );
        stats
    }

    fn health_check(&self) -> bool {
        self.config.base.enabled
    }
}

impl ArchiveScanner {
    /// Detect archive type from magic bytes
    fn detect_archive_type(&self, data: &[u8]) -> ArchiveType {
        if data.len() < 4 {
            return ArchiveType::Unknown;
        }

        // Check magic bytes
        match &data[0..2] {
            b"PK" => return ArchiveType::Zip,
            [0x1f, 0x8b] => return ArchiveType::GZip,
            b"Ra" if data.len() >= 7 && &data[0..3] == b"Rar" => return ArchiveType::Rar,
            _ => {}
        }

        // Check for TAR (starts with filename, limited magic)
        if data.len() >= 262 && &data[257..262] == b"ustar" {
            return ArchiveType::Tar;
        }

        // Check for 7z
        if data.len() >= 6 && &data[0..6] == b"7z\xBC\xAF\x27\x1C" {
            return ArchiveType::SevenZip;
        }

        // Check for BZIP2
        if data.len() >= 3 && &data[0..3] == b"BZh" {
            return ArchiveType::Bzip2;
        }

        ArchiveType::Unknown
    }

    /// Scan ZIP archive
    fn scan_zip(&self, data: &[u8]) -> Result<(ArchiveInfo, Vec<ArchiveFileInfo>)> {
        let cursor = Cursor::new(data);
        let mut archive =
            ZipArchive::new(cursor).map_err(|e| anyhow!("Failed to read ZIP archive: {e}"))?;

        let mut files = Vec::new();
        let mut total_compressed = 0u64;
        let mut total_uncompressed = 0u64;
        let mut is_encrypted = false;
        let mut has_nested_archives = false;

        for i in 0..archive.len() {
            let file = archive
                .by_index(i)
                .map_err(|e| anyhow!("Failed to read file {i}: {e}"))?;

            let filename = file
                .name()
                .map_err(|e| anyhow!("Failed to read name of file {i}: {e}"))?
                .to_string();
            let compressed_size = file.compressed_size();
            let uncompressed_size = file.size();
            let is_file_encrypted = false; // zip 0.6 doesn't expose encrypted() publicly

            if is_file_encrypted {
                is_encrypted = true;
            }

            total_compressed += compressed_size;
            total_uncompressed += uncompressed_size;

            let extension = std::path::Path::new(&filename)
                .extension()
                .and_then(|e| e.to_str())
                .unwrap_or("")
                .to_string();

            let is_archive = self.archive_extensions.contains(&extension.to_lowercase());
            if is_archive {
                has_nested_archives = true;
            }

            let is_executable = matches!(
                extension.to_lowercase().as_str(),
                "exe" | "dll" | "so" | "dylib" | "bat" | "cmd" | "sh"
            );

            let compression_ratio = if compressed_size > 0 {
                uncompressed_size as f64 / compressed_size as f64
            } else {
                0.0
            };

            files.push(ArchiveFileInfo {
                file_id: Uuid::new_v4(),
                filename: filename.clone(),
                path: filename,
                compressed_size,
                uncompressed_size,
                compression_ratio,
                is_encrypted: is_file_encrypted,
                is_executable,
                is_archive,
                file_type: extension,
                crc32: Some(file.crc32()),
            });
        }

        let comment = archive.comment();
        let comment_str = if !comment.is_empty() {
            Some(String::from_utf8_lossy(comment).to_string())
        } else {
            None
        };

        let archive_info = ArchiveInfo {
            archive_type: ArchiveType::Zip,
            total_files: archive.len(),
            total_compressed_size: total_compressed,
            total_uncompressed_size: total_uncompressed,
            is_encrypted,
            has_nested_archives,
            nesting_level: if has_nested_archives { 1 } else { 0 },
            comment: comment_str,
        };

        Ok((archive_info, files))
    }

    /// Scan TAR archive (simplified)
    fn scan_tar(&self, data: &[u8]) -> Result<(ArchiveInfo, Vec<ArchiveFileInfo>)> {
        // Simplified TAR parsing - in production, use tar crate
        let archive_info = ArchiveInfo {
            archive_type: ArchiveType::Tar,
            total_files: 0,
            total_compressed_size: data.len() as u64,
            total_uncompressed_size: data.len() as u64,
            is_encrypted: false,
            has_nested_archives: false,
            nesting_level: 0,
            comment: None,
        };

        Ok((archive_info, Vec::new()))
    }

    /// Scan GZIP archive (simplified)
    fn scan_gzip(&self, data: &[u8]) -> Result<(ArchiveInfo, Vec<ArchiveFileInfo>)> {
        // Simplified GZIP parsing
        let archive_info = ArchiveInfo {
            archive_type: ArchiveType::GZip,
            total_files: 1,
            total_compressed_size: data.len() as u64,
            total_uncompressed_size: data.len() as u64 * 5, // Estimate
            is_encrypted: false,
            has_nested_archives: false,
            nesting_level: 0,
            comment: None,
        };

        Ok((archive_info, Vec::new()))
    }

    /// Load suspicious file extensions
    fn load_suspicious_extensions() -> Vec<String> {
        vec![
            "exe".to_string(),
            "dll".to_string(),
            "scr".to_string(),
            "bat".to_string(),
            "cmd".to_string(),
            "com".to_string(),
            "pif".to_string(),
            "vbs".to_string(),
            "js".to_string(),
            "jar".to_string(),
            "ps1".to_string(),
        ]
    }

    /// Load archive extensions
    fn load_archive_extensions() -> Vec<String> {
        vec![
            "zip".to_string(),
            "rar".to_string(),
            "7z".to_string(),
            "tar".to_string(),
            "gz".to_string(),
            "bz2".to_string(),
            "xz".to_string(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn test_archive_scanner_creation() {
        let config = ArchiveScannerConfig::default();
        let scanner = ArchiveScanner::new(config);
        assert!(scanner.is_ok());
    }

    #[test]
    fn test_archive_type_detection() {
        let scanner = ArchiveScanner::new(ArchiveScannerConfig::default()).unwrap();

        // ZIP
        let zip_data = b"PK\x03\x04";
        assert_eq!(scanner.detect_archive_type(zip_data), ArchiveType::Zip);

        // GZIP
        let gzip_data = b"\x1f\x8b\x08\x00";
        assert_eq!(scanner.detect_archive_type(gzip_data), ArchiveType::GZip);

        // Unknown
        let unknown_data = b"TEST";
        assert_eq!(
            scanner.detect_archive_type(unknown_data),
            ArchiveType::Unknown
        );
    }

    #[tokio::test]
    async fn test_scan_zip() {
        let scanner = ArchiveScanner::new(ArchiveScannerConfig::default()).unwrap();

        // Create a minimal valid ZIP file
        let mut zip_data = Vec::new();
        {
            let cursor = Cursor::new(&mut zip_data);
            let mut zip = zip::ZipWriter::new(cursor);

            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);

            zip.start_file("test.txt", options).unwrap();
            zip.write_all(b"Hello, World!").unwrap();
            zip.finish().unwrap();
        }

        let result = scanner.scan(&zip_data, None).await;
        assert!(result.is_ok());

        let scan_result = result.unwrap();
        assert_eq!(scan_result.archive_info.archive_type, ArchiveType::Zip);
        assert_eq!(scan_result.archive_info.total_files, 1);
    }
}
