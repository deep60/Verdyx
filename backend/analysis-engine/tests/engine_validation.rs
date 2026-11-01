use analysis_engine::analyzers::heuristic_engine::HeuristicEngine;
use analysis_engine::analyzers::signature_matcher::{SignatureMatcher, SignatureMatcherConfig};
use analysis_engine::models::analysis_result::{
    AnalysisResult, DetectionResult, EngineType, FileMetadata, SeverityLevel, ThreatCategory,
    ThreatVerdict,
};
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;

#[tokio::test]
async fn test_signature_matcher_loads_and_detects_eicar() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let rules_dir = format!("{}/rules/signatures", manifest_dir);

    let config = SignatureMatcherConfig {
        signatures_dir: rules_dir,
        max_file_size: 10 * 1024 * 1024,
        enable_caching: false,
        cache_ttl_seconds: 60,
        parallel_matching: false,
        max_matches_per_file: 50,
    };

    let matcher = SignatureMatcher::new(config)
        .await
        .expect("load signatures");
    assert!(
        matcher.signature_count() > 0,
        "should load at least 1 default signature"
    );

    // Test with EICAR sample
    let eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let matches = matcher.match_bytes(eicar_bytes).await.expect("match bytes");
    assert!(
        !matches.is_empty(),
        "EICAR string must trigger a signature match"
    );
    assert!(
        matches.iter().any(|m| m.threat_family == "EICAR-Test"),
        "match must report EICAR-Test family"
    );

    // Test with clean sample
    let clean_bytes = b"Hello, this is a clean file without any malicious strings.";
    let clean_matches = matcher
        .match_bytes(clean_bytes)
        .await
        .expect("match clean bytes");
    assert!(
        clean_matches.is_empty(),
        "Clean sample must produce 0 signature matches"
    );
}

#[tokio::test]
async fn test_heuristic_engine_detects_suspicious_patterns() {
    let engine = HeuristicEngine::new();

    // Clean buffer
    let clean_data = "This is normal plaintext text with no script commands.";
    let clean_matches = engine
        .analyze_content(clean_data, Path::new("clean.txt"))
        .await
        .expect("analyze clean");
    assert!(
        clean_matches.is_empty(),
        "Clean data must produce no heuristic hits"
    );

    // Suspicious registry persistence command
    let suspicious_data = "reg.exe add HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v EvilService /t REG_SZ /d evil.exe";
    let susp_matches = engine
        .analyze_content(suspicious_data, Path::new("setup.bat"))
        .await
        .expect("analyze suspicious");
    assert!(
        !susp_matches.is_empty(),
        "Registry persistence pattern must yield heuristic matches"
    );
}

#[test]
fn test_consensus_explainability_and_unavailable_engine_handling() {
    let file_metadata = FileMetadata {
        filename: Some("sample.bin".to_string()),
        file_size: 1024,
        mime_type: "application/octet-stream".to_string(),
        md5: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
        sha1: "da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        sha512: None,
        entropy: Some(4.5),
        magic_bytes: None,
        executable_info: None,
    };

    let mut result = AnalysisResult::new(Uuid::new_v4(), file_metadata);

    // Add 2 active malicious detections
    result.add_detection(DetectionResult {
        detection_id: Uuid::new_v4(),
        engine_name: "signature_matcher".to_string(),
        engine_version: "0.1.0".to_string(),
        engine_type: EngineType::Static,
        verdict: ThreatVerdict::Malicious,
        confidence: 0.95,
        severity: SeverityLevel::High,
        categories: vec![ThreatCategory::Malware],
        metadata: HashMap::new(),
        detected_at: chrono::Utc::now(),
        processing_time_ms: 12,
        error_message: None,
    });

    result.add_detection(DetectionResult {
        detection_id: Uuid::new_v4(),
        engine_name: "heuristic_engine".to_string(),
        engine_version: "0.1.0".to_string(),
        engine_type: EngineType::Behavioral,
        verdict: ThreatVerdict::Malicious,
        confidence: 0.85,
        severity: SeverityLevel::High,
        categories: vec![ThreatCategory::Malware],
        metadata: HashMap::new(),
        detected_at: chrono::Utc::now(),
        processing_time_ms: 5,
        error_message: None,
    });

    // Add 1 active benign detection
    result.add_detection(DetectionResult {
        detection_id: Uuid::new_v4(),
        engine_name: "static_analyzer".to_string(),
        engine_version: "0.1.0".to_string(),
        engine_type: EngineType::Static,
        verdict: ThreatVerdict::Benign,
        confidence: 0.70,
        severity: SeverityLevel::Info,
        categories: vec![],
        metadata: HashMap::new(),
        detected_at: chrono::Utc::now(),
        processing_time_ms: 18,
        error_message: None,
    });

    // Add 1 unavailable engine detection
    let mut unavail_meta = HashMap::new();
    unavail_meta.insert("status".to_string(), serde_json::json!("unavailable"));
    result.add_detection(DetectionResult {
        detection_id: Uuid::new_v4(),
        engine_name: "clamav".to_string(),
        engine_version: "unknown".to_string(),
        engine_type: EngineType::Static,
        verdict: ThreatVerdict::Unknown,
        confidence: 0.0,
        severity: SeverityLevel::Info,
        categories: vec![],
        metadata: unavail_meta,
        detected_at: chrono::Utc::now(),
        processing_time_ms: 0,
        error_message: Some("clamd daemon unreachable on localhost:3310".to_string()),
    });

    // Verify consensus behavior
    assert_eq!(result.consensus_verdict, ThreatVerdict::Malicious);
    assert_eq!(result.participating_engines.len(), 3);
    assert_eq!(result.unavailable_engines.len(), 1);
    assert_eq!(result.unavailable_engines[0].engine_name, "clamav");
    assert_eq!(result.vote_distribution.malicious, 2);
    assert_eq!(result.vote_distribution.benign, 1);
    assert_eq!(result.vote_distribution.unknown, 1);
    assert_eq!(result.vote_distribution.total_participating, 3);
    assert_eq!(result.vote_distribution.total_engines, 4);
    assert!(result.agreement_score > 0.0 && result.agreement_score <= 100.0);
    assert!(
        result.consensus_explanation.contains("clamav"),
        "Explanation must explicitly detail unavailable engine influence"
    );
    assert!(
        !result.verdict_history.is_empty(),
        "Verdict history must have an audit record"
    );
}
