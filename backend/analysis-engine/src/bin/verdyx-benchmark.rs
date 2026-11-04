//! Detection benchmark: runs every analysis engine over a fixed set of
//! known-malicious and known-clean files and reports how each one did.
//!
//! ```text
//! verdyx-benchmark --manifest manifest.json --samples DIR --out DIR
//!                  [--clean-dir DIR]... [--rules DIR] [--with-feeds] [--limit N]
//! ```
//!
//! * Malicious files are read from `<samples>/malicious/<sha256>` and must
//!   match the hash in the manifest; anything missing or altered is skipped.
//! * Clean files are every regular file under `<samples>/clean/<source>/` and
//!   under each `--clean-dir`.
//! * Hash-reputation feeds are off unless `--with-feeds` is given. The
//!   malicious set comes from MalwareBazaar, so a MalwareBazaar lookup would
//!   find every sample by construction and inflate the score.
//!
//! The report goes to `<out>/report.md` and `<out>/report.json`.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::time::Instant;

use analysis_engine::analyzers::{
    AnalysisEngine, AnalysisEngineConfig, AnalysisOptions, FileAnalysisRequest,
};
use analysis_engine::models::analysis_result::{DetectionResult, EngineType, ThreatVerdict};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Files above this size are skipped, matching the upload limit.
const MAX_FILE_SIZE: u64 = 20 * 1024 * 1024;
/// Name used for the ML engine's prediction while it's advisory-only.
const ML_ADVISORY: &str = "ML Engine (advisory)";

#[derive(Deserialize)]
struct Manifest {
    malicious: Vec<ManifestSample>,
}

#[derive(Deserialize)]
struct ManifestSample {
    sha256: String,
    category: String,
    file_type: String,
    family: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
enum Label {
    Malicious,
    Clean,
}

struct Sample {
    label: Label,
    path: PathBuf,
    /// Short name for the report: `<group>/<path inside the group>`.
    display: String,
    /// Filename handed to the engines; some of them look at the extension.
    filename: String,
    /// File-type category for malicious files, release name for clean ones.
    group: String,
    family: Option<String>,
    expected_sha256: Option<String>,
}

/// How one engine judged one file.
#[derive(Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    /// Malicious or Suspicious.
    Flagged,
    Benign,
    /// Unknown, an error, or the engine was unavailable.
    NoVerdict,
}

#[derive(Serialize)]
struct Vote {
    engine: String,
    verdict: String,
    outcome: Outcome,
    confidence: f32,
    /// The engine's internal score, where it has one (static threat score,
    /// heuristic risk score), so thresholds can be re-tuned from the report.
    #[serde(skip_serializing_if = "Option::is_none")]
    score: Option<f64>,
    /// What the engine based its verdict on.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    reasons: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    yara_rules: Vec<String>,
}

#[derive(Serialize)]
struct SampleResult {
    label: Label,
    group: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    family: Option<String>,
    file: String,
    sha256: String,
    size: usize,
    consensus: String,
    consensus_outcome: Outcome,
    votes: Vec<Vote>,
    ms: u64,
}

#[derive(Default, Clone, Copy, Serialize)]
struct Tally {
    total: usize,
    flagged: usize,
    malicious_verdicts: usize,
    benign: usize,
    no_verdict: usize,
}

impl Tally {
    fn add(&mut self, outcome: Outcome, malicious_verdict: bool) {
        self.total += 1;
        match outcome {
            Outcome::Flagged => self.flagged += 1,
            Outcome::Benign => self.benign += 1,
            Outcome::NoVerdict => self.no_verdict += 1,
        }
        if malicious_verdict {
            self.malicious_verdicts += 1;
        }
    }

    fn flagged_rate(&self) -> f64 {
        ratio(self.flagged, self.total)
    }
}

struct Args {
    manifest: PathBuf,
    samples: PathBuf,
    out: PathBuf,
    clean_dirs: Vec<PathBuf>,
    rules: Option<PathBuf>,
    with_feeds: bool,
    limit: Option<usize>,
}

fn parse_args() -> Result<Args> {
    let mut manifest = None;
    let mut samples = None;
    let mut out = None;
    let mut clean_dirs = Vec::new();
    let mut rules = None;
    let mut with_feeds = false;
    let mut limit = None;

    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = || it.next().with_context(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "--manifest" => manifest = Some(PathBuf::from(value()?)),
            "--samples" => samples = Some(PathBuf::from(value()?)),
            "--out" => out = Some(PathBuf::from(value()?)),
            "--clean-dir" => clean_dirs.push(PathBuf::from(value()?)),
            "--rules" => rules = Some(PathBuf::from(value()?)),
            "--limit" => limit = Some(value()?.parse().context("--limit")?),
            "--with-feeds" => with_feeds = true,
            "-h" | "--help" => {
                println!(
                    "verdyx-benchmark --manifest FILE --samples DIR --out DIR \
                     [--clean-dir DIR]... [--rules DIR] [--with-feeds] [--limit N]"
                );
                std::process::exit(0);
            }
            other => bail!("unknown argument: {other}"),
        }
    }

    Ok(Args {
        manifest: manifest.context("--manifest is required")?,
        samples: samples.context("--samples is required")?,
        out: out.context("--out is required")?,
        clean_dirs,
        rules,
        with_feeds,
        limit,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::ERROR)
        .with_writer(std::io::stderr)
        .init();

    let args = parse_args()?;
    let manifest: Manifest = serde_json::from_slice(
        &std::fs::read(&args.manifest).with_context(|| format!("{:?}", args.manifest))?,
    )
    .context("parsing the manifest")?;

    let mut samples = collect_samples(&args, &manifest)?;
    if let Some(limit) = args.limit {
        // Keep the mix: take `limit` of each label.
        let (mut mal, mut clean): (Vec<_>, Vec<_>) = samples
            .into_iter()
            .partition(|s| s.label == Label::Malicious);
        mal.truncate(limit);
        clean.truncate(limit);
        samples = mal.into_iter().chain(clean).collect();
    }

    let mut config = AnalysisEngineConfig::default();
    if let Some(rules) = &args.rules {
        config.yara_engine.rules_directory = rules.clone();
    }
    if !args.with_feeds {
        config.hash_analyzer.virustotal_api_key = None;
        config.hash_analyzer.malwarebazaar_api_key = None;
        config.hash_analyzer.hybrid_analysis_api_key = None;
    }
    let mut engine = AnalysisEngine::new(config).await?;
    let engine_stats = engine.get_stats().await;

    let started = Instant::now();
    let mut results = Vec::with_capacity(samples.len());
    let mut skipped = Vec::new();

    for (i, sample) in samples.iter().enumerate() {
        if i % 50 == 0 {
            eprintln!("[{i}/{}] {:.0?}", samples.len(), started.elapsed());
        }
        match run_sample(&mut engine, sample).await {
            Ok(Some(result)) => results.push(result),
            Ok(None) => skipped.push(format!("{} (hash mismatch)", sample.display)),
            Err(e) => skipped.push(format!("{}: {e:#}", sample.display)),
        }
        // Each file gets a fresh view: no cached verdicts from earlier files.
        engine.clear_caches().await;
    }

    let missing = manifest.malicious.len()
        - samples
            .iter()
            .filter(|s| s.label == Label::Malicious)
            .count();

    let report = Report::build(
        &results,
        &skipped,
        missing,
        args.with_feeds,
        &engine_stats,
        started.elapsed().as_secs(),
    );

    std::fs::create_dir_all(&args.out)?;
    std::fs::write(args.out.join("report.md"), report.markdown())?;
    std::fs::write(
        args.out.join("report.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "summary": &report,
            "samples": &results,
            "skipped": &skipped,
        }))?,
    )?;

    eprintln!(
        "Done: {} files in {:.0?}. Report in {}",
        results.len(),
        started.elapsed(),
        args.out.display()
    );
    Ok(())
}

fn collect_samples(args: &Args, manifest: &Manifest) -> Result<Vec<Sample>> {
    let mut samples = Vec::new();

    let mal_dir = args.samples.join("malicious");
    for entry in &manifest.malicious {
        let path = mal_dir.join(&entry.sha256);
        if path.is_file() {
            samples.push(Sample {
                label: Label::Malicious,
                display: format!("{}/{}", entry.family, entry.sha256),
                path,
                filename: format!("{}.{}", &entry.sha256[..16], entry.file_type),
                group: entry.category.clone(),
                family: Some(entry.family.clone()),
                expected_sha256: Some(entry.sha256.to_lowercase()),
            });
        }
    }

    let clean_root = args.samples.join("clean");
    if clean_root.is_dir() {
        let mut sources: Vec<_> = std::fs::read_dir(&clean_root)?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.is_dir())
            .collect();
        sources.sort();
        for source in sources {
            let group = file_name(&source);
            add_clean_dir(&mut samples, &source, &group)?;
        }
    }
    for dir in &args.clean_dirs {
        let group = format!("system{}", dir.display()).replace('/', "-");
        add_clean_dir(&mut samples, dir, &group)?;
    }

    Ok(samples)
}

fn add_clean_dir(samples: &mut Vec<Sample>, dir: &Path, group: &str) -> Result<()> {
    let mut stack = vec![dir.to_path_buf()];
    let mut found = Vec::new();
    while let Some(d) = stack.pop() {
        for entry in std::fs::read_dir(&d).with_context(|| format!("{}", d.display()))? {
            let entry = entry?;
            // symlink_metadata: don't follow links, so nothing is counted twice.
            let meta = entry.path().symlink_metadata()?;
            if meta.is_dir() {
                stack.push(entry.path());
            } else if meta.is_file() && meta.len() > 0 && meta.len() <= MAX_FILE_SIZE {
                found.push(entry.path());
            }
        }
    }
    found.sort();
    for path in found {
        let inside = path
            .strip_prefix(dir)
            .unwrap_or(&path)
            .display()
            .to_string();
        samples.push(Sample {
            label: Label::Clean,
            display: format!("{group}/{inside}"),
            filename: file_name(&path),
            path,
            group: group.to_string(),
            family: None,
            expected_sha256: None,
        });
    }
    Ok(())
}

async fn run_sample(engine: &mut AnalysisEngine, sample: &Sample) -> Result<Option<SampleResult>> {
    let data = std::fs::read(&sample.path)?;
    let sha256 = hex::encode(Sha256::digest(&data));
    if let Some(expected) = &sample.expected_sha256 {
        if *expected != sha256 {
            return Ok(None);
        }
    }

    let size = data.len();
    let started = Instant::now();
    let result = engine
        .analyze_file(FileAnalysisRequest {
            filename: sample.filename.clone(),
            file_data: data,
            file_hashes: None,
            analysis_options: AnalysisOptions::default(),
        })
        .await?;

    let mut votes: Vec<Vote> = result.detections.iter().map(vote_from).collect();
    // While the ML engine is advisory its own detection carries no verdict;
    // score the prediction it would have made as a separate row.
    if let Some(advisory) = result.detections.iter().find_map(advisory_ml_vote) {
        votes.push(advisory);
    }

    Ok(Some(SampleResult {
        label: sample.label,
        group: sample.group.clone(),
        family: sample.family.clone(),
        file: sample.display.clone(),
        sha256,
        size,
        consensus: format!("{:?}", result.consensus_verdict),
        consensus_outcome: outcome_of(&result.consensus_verdict, false),
        votes,
        ms: started.elapsed().as_millis() as u64,
    }))
}

fn vote_from(d: &DetectionResult) -> Vote {
    let yara_rules = if d.engine_type == EngineType::Yara {
        d.metadata
            .get("matched_rules")
            .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
            .unwrap_or_default()
    } else {
        Vec::new()
    };
    let score = ["threat_score", "risk_score"]
        .iter()
        .find_map(|k| d.metadata.get(*k).and_then(|v| v.as_f64()));
    let reasons = if let Some(details) = d.metadata.get("threat_details") {
        serde_json::from_value::<Vec<String>>(details.clone()).unwrap_or_default()
    } else if d.engine_type == EngineType::Yara {
        Vec::new()
    } else {
        // Heuristic engine: the names of the rules that matched.
        d.metadata
            .get("matches")
            .and_then(|m| m.as_array())
            .map(|ms| {
                ms.iter()
                    .filter_map(|m| m.get("rule_name").and_then(|n| n.as_str()))
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_default()
    };
    Vote {
        engine: d.engine_name.clone(),
        verdict: format!("{:?}", d.verdict),
        outcome: outcome_of(&d.verdict, d.error_message.is_some()),
        confidence: d.confidence,
        score,
        reasons,
        yara_rules,
    }
}

fn advisory_ml_vote(d: &DetectionResult) -> Option<Vote> {
    let verdict = d.metadata.get("advisory_verdict")?.as_str()?;
    let verdict = match verdict.to_ascii_lowercase().as_str() {
        "malicious" => ThreatVerdict::Malicious,
        "suspicious" => ThreatVerdict::Suspicious,
        "benign" => ThreatVerdict::Benign,
        _ => ThreatVerdict::Unknown,
    };
    let confidence = d
        .metadata
        .get("advisory_confidence")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0) as f32;
    Some(Vote {
        engine: ML_ADVISORY.to_string(),
        verdict: format!("{verdict:?}"),
        outcome: outcome_of(&verdict, false),
        confidence,
        score: Some(confidence as f64),
        reasons: Vec::new(),
        yara_rules: Vec::new(),
    })
}

fn outcome_of(verdict: &ThreatVerdict, errored: bool) -> Outcome {
    if errored {
        return Outcome::NoVerdict;
    }
    match verdict {
        ThreatVerdict::Malicious | ThreatVerdict::Suspicious => Outcome::Flagged,
        ThreatVerdict::Benign => Outcome::Benign,
        ThreatVerdict::Unknown => Outcome::NoVerdict,
    }
}

const CONSENSUS: &str = "Consensus";

#[derive(Serialize)]
struct Report {
    malicious_files: usize,
    clean_files: usize,
    families: usize,
    missing_from_manifest: usize,
    skipped: usize,
    feeds_enabled: bool,
    seconds: u64,
    engine_stats: BTreeMap<String, String>,
    /// engine -> tally over malicious files
    detection: BTreeMap<String, Tally>,
    /// engine -> tally over clean files
    false_positives: BTreeMap<String, Tally>,
    /// category -> engine -> tally (malicious)
    detection_by_category: BTreeMap<String, BTreeMap<String, Tally>>,
    /// clean source -> engine -> tally
    false_positives_by_source: BTreeMap<String, BTreeMap<String, Tally>>,
    /// YARA rule -> clean files it matched
    yara_rules_on_clean: Vec<(String, usize)>,
    /// YARA rule -> malicious files it matched
    yara_rules_on_malicious: Vec<(String, usize)>,
    /// engine -> (reason, clean files, malicious files), most clean hits first
    reasons: BTreeMap<String, Vec<(String, usize, usize)>>,
    /// Families where the consensus missed every sample.
    missed_families: Vec<String>,
    /// Clean files the consensus flagged, with the engines that flagged them.
    consensus_false_positives: Vec<(String, Vec<String>)>,
    #[serde(skip)]
    engines: Vec<String>,
}

impl Report {
    fn build(
        results: &[SampleResult],
        skipped: &[String],
        missing: usize,
        feeds_enabled: bool,
        engine_stats: &HashMap<String, String>,
        seconds: u64,
    ) -> Self {
        let mut detection: BTreeMap<String, Tally> = BTreeMap::new();
        let mut false_positives: BTreeMap<String, Tally> = BTreeMap::new();
        let mut by_category: BTreeMap<String, BTreeMap<String, Tally>> = BTreeMap::new();
        let mut by_source: BTreeMap<String, BTreeMap<String, Tally>> = BTreeMap::new();
        let mut rules_clean: HashMap<String, usize> = HashMap::new();
        let mut rules_mal: HashMap<String, usize> = HashMap::new();
        let mut family_hits: BTreeMap<String, (usize, usize)> = BTreeMap::new();
        // engine -> reason -> (clean, malicious)
        let mut reason_counts: BTreeMap<String, HashMap<String, (usize, usize)>> = BTreeMap::new();
        let mut consensus_fps = Vec::new();

        for r in results {
            let (overall, groups, rules) = match r.label {
                Label::Malicious => (&mut detection, &mut by_category, &mut rules_mal),
                Label::Clean => (&mut false_positives, &mut by_source, &mut rules_clean),
            };
            let group = groups.entry(r.group.clone()).or_default();

            let is_mal = r.consensus == "Malicious";
            overall
                .entry(CONSENSUS.to_string())
                .or_default()
                .add(r.consensus_outcome, is_mal);
            group
                .entry(CONSENSUS.to_string())
                .or_default()
                .add(r.consensus_outcome, is_mal);

            for v in &r.votes {
                let is_mal = v.verdict == "Malicious";
                overall
                    .entry(v.engine.clone())
                    .or_default()
                    .add(v.outcome, is_mal);
                group
                    .entry(v.engine.clone())
                    .or_default()
                    .add(v.outcome, is_mal);
                for rule in &v.yara_rules {
                    *rules.entry(rule.clone()).or_default() += 1;
                }
                let mut seen = std::collections::HashSet::new();
                for reason in &v.reasons {
                    let key = normalize_reason(reason);
                    if !seen.insert(key.clone()) {
                        continue;
                    }
                    let e = reason_counts
                        .entry(v.engine.clone())
                        .or_default()
                        .entry(key)
                        .or_default();
                    match r.label {
                        Label::Clean => e.0 += 1,
                        Label::Malicious => e.1 += 1,
                    }
                }
            }

            match r.label {
                Label::Malicious => {
                    let fam = r.family.clone().unwrap_or_else(|| "unknown".into());
                    let e = family_hits.entry(fam).or_default();
                    e.0 += 1;
                    if r.consensus_outcome == Outcome::Flagged {
                        e.1 += 1;
                    }
                }
                Label::Clean if r.consensus_outcome == Outcome::Flagged => {
                    let by: Vec<String> = r
                        .votes
                        .iter()
                        .filter(|v| v.outcome == Outcome::Flagged && v.engine != ML_ADVISORY)
                        .map(|v| v.engine.clone())
                        .collect();
                    consensus_fps.push((r.file.clone(), by));
                }
                Label::Clean => {}
            }
        }

        let mut engines: Vec<String> = detection
            .keys()
            .chain(false_positives.keys())
            .filter(|e| e.as_str() != CONSENSUS)
            .cloned()
            .collect();
        engines.sort();
        engines.dedup();

        Report {
            malicious_files: detection.get(CONSENSUS).map_or(0, |t| t.total),
            clean_files: false_positives.get(CONSENSUS).map_or(0, |t| t.total),
            families: family_hits.len(),
            missing_from_manifest: missing,
            skipped: skipped.len(),
            feeds_enabled,
            seconds,
            engine_stats: engine_stats.clone().into_iter().collect(),
            detection,
            false_positives,
            detection_by_category: by_category,
            false_positives_by_source: by_source,
            reasons: reason_counts
                .into_iter()
                .map(|(engine, counts)| {
                    let mut v: Vec<_> = counts.into_iter().map(|(k, (c, m))| (k, c, m)).collect();
                    v.sort_by(|a, b| b.1.cmp(&a.1).then(b.2.cmp(&a.2)).then(a.0.cmp(&b.0)));
                    v.truncate(25);
                    (engine, v)
                })
                .collect(),
            yara_rules_on_clean: top(rules_clean, 25),
            yara_rules_on_malicious: top(rules_mal, 25),
            missed_families: family_hits
                .into_iter()
                .filter(|(_, (_, hit))| *hit == 0)
                .map(|(f, (n, _))| format!("{f} ({n})"))
                .collect(),
            consensus_false_positives: consensus_fps,
            engines,
        }
    }

    fn markdown(&self) -> String {
        use std::fmt::Write;
        let mut md = String::new();
        let empty = Tally::default();
        let get = |m: &BTreeMap<String, Tally>, k: &str| m.get(k).copied().unwrap_or(empty);

        let _ = writeln!(md, "# Verdyx detection benchmark\n");
        let _ = writeln!(
            md,
            "{} malicious files ({} families) and {} clean files, analysed in {} s. \
             Hash-reputation feeds were **{}**.{}{}\n",
            self.malicious_files,
            self.families,
            self.clean_files,
            self.seconds,
            if self.feeds_enabled { "on" } else { "off" },
            if self.missing_from_manifest > 0 {
                format!(
                    " {} manifest samples weren't downloaded.",
                    self.missing_from_manifest
                )
            } else {
                String::new()
            },
            if self.skipped > 0 {
                format!(" {} files were skipped (see report.json).", self.skipped)
            } else {
                String::new()
            },
        );
        let _ = writeln!(
            md,
            "*Flagged* means a Malicious or Suspicious verdict. *No verdict* means \
             Unknown, an error, or the engine was unavailable.\n"
        );

        let c_det = get(&self.detection, CONSENSUS);
        let c_fp = get(&self.false_positives, CONSENSUS);
        let _ = writeln!(md, "## Consensus\n");
        let _ = writeln!(md, "| | Result |\n|---|---|");
        let _ = writeln!(
            md,
            "| Malware flagged | **{}** ({}/{}) |",
            pct(c_det.flagged_rate()),
            c_det.flagged,
            c_det.total
        );
        let _ = writeln!(
            md,
            "| Malware called Malicious | {} ({}) |",
            pct(ratio(c_det.malicious_verdicts, c_det.total)),
            c_det.malicious_verdicts
        );
        let _ = writeln!(
            md,
            "| Malware called Benign | {} ({}) |",
            pct(ratio(c_det.benign, c_det.total)),
            c_det.benign
        );
        let _ = writeln!(
            md,
            "| Clean files flagged (false positives) | **{}** ({}/{}) |\n",
            pct(c_fp.flagged_rate()),
            c_fp.flagged,
            c_fp.total
        );

        let _ = writeln!(md, "## Per engine\n");
        let _ = writeln!(
            md,
            "| Engine | Malware flagged | No verdict on malware | Clean flagged | No verdict on clean |"
        );
        let _ = writeln!(md, "|---|---|---|---|---|");
        for e in &self.engines {
            let d = get(&self.detection, e);
            let f = get(&self.false_positives, e);
            let _ = writeln!(
                md,
                "| {e} | {} | {} | {} | {} |",
                pct(d.flagged_rate()),
                pct(ratio(d.no_verdict, d.total)),
                pct(f.flagged_rate()),
                pct(ratio(f.no_verdict, f.total)),
            );
        }
        let _ = writeln!(md);

        let cols = self.voting_engines();
        let header = |md: &mut String, first: &str| {
            let _ = write!(md, "| {first} | Files | Consensus |");
            for e in &cols {
                let _ = write!(md, " {e} |");
            }
            let _ = writeln!(md);
            let _ = writeln!(md, "|---|---|---|{}", "---|".repeat(cols.len()));
        };

        let _ = writeln!(md, "## Malware flagged, by file type\n");
        header(&mut md, "Type");
        for (cat, tallies) in &self.detection_by_category {
            let c = get(tallies, CONSENSUS);
            let _ = write!(md, "| {cat} | {} | {} |", c.total, pct(c.flagged_rate()));
            for e in &cols {
                let _ = write!(md, " {} |", pct(get(tallies, e).flagged_rate()));
            }
            let _ = writeln!(md);
        }
        let _ = writeln!(md);

        let _ = writeln!(md, "## Clean files flagged, by source\n");
        header(&mut md, "Source");
        for (src, tallies) in &self.false_positives_by_source {
            let c = get(tallies, CONSENSUS);
            let _ = write!(md, "| {src} | {} | {} |", c.total, pct(c.flagged_rate()));
            for e in &cols {
                let _ = write!(md, " {} |", pct(get(tallies, e).flagged_rate()));
            }
            let _ = writeln!(md);
        }
        let _ = writeln!(md);

        for (engine, rows) in &self.reasons {
            if rows.is_empty() {
                continue;
            }
            let _ = writeln!(md, "## {engine}: what it reacts to\n");
            let _ = writeln!(
                md,
                "Share of files where each indicator fired. A good indicator is common \
                 on malware and rare on clean files.\n"
            );
            let _ = writeln!(
                md,
                "| Indicator | Clean files | Malicious files |\n|---|---|---|"
            );
            for (reason, clean, mal) in rows {
                let _ = writeln!(
                    md,
                    "| {} | {} ({clean}) | {} ({mal}) |",
                    reason.replace('|', "\\|"),
                    pct(ratio(*clean, self.clean_files)),
                    pct(ratio(*mal, self.malicious_files)),
                );
            }
            let _ = writeln!(md);
        }

        if !self.yara_rules_on_clean.is_empty() {
            let _ = writeln!(md, "## YARA rules that matched clean files\n");
            let _ = writeln!(md, "| Rule | Clean files |\n|---|---|");
            for (rule, n) in &self.yara_rules_on_clean {
                let _ = writeln!(md, "| `{rule}` | {n} |");
            }
            let _ = writeln!(md);
        }
        if !self.yara_rules_on_malicious.is_empty() {
            let _ = writeln!(md, "## YARA rules that matched malware most often\n");
            let _ = writeln!(md, "| Rule | Malicious files |\n|---|---|");
            for (rule, n) in &self.yara_rules_on_malicious {
                let _ = writeln!(md, "| `{rule}` | {n} |");
            }
            let _ = writeln!(md);
        }
        if !self.consensus_false_positives.is_empty() {
            let _ = writeln!(md, "## Clean files the consensus flagged\n");
            let _ = writeln!(md, "| File | Flagged by |\n|---|---|");
            for (file, by) in self.consensus_false_positives.iter().take(40) {
                let _ = writeln!(md, "| `{file}` | {} |", by.join(", "));
            }
            if self.consensus_false_positives.len() > 40 {
                let _ = writeln!(
                    md,
                    "\n…and {} more in report.json.",
                    self.consensus_false_positives.len() - 40
                );
            }
            let _ = writeln!(md);
        }
        if !self.missed_families.is_empty() {
            let _ = writeln!(md, "## Families the consensus missed entirely\n");
            let _ = writeln!(md, "{}\n", self.missed_families.join(", "));
        }

        let _ = writeln!(md, "## Engine setup\n");
        let _ = writeln!(md, "| Setting | Value |\n|---|---|");
        for (k, v) in &self.engine_stats {
            let _ = writeln!(md, "| {k} | {v} |");
        }
        md
    }

    /// Engines worth a column in the breakdown tables: those that produced a
    /// verdict on at least one file.
    fn voting_engines(&self) -> Vec<String> {
        self.engines
            .iter()
            .filter(|e| {
                let any =
                    |m: &BTreeMap<String, Tally>| m.get(*e).is_some_and(|t| t.no_verdict < t.total);
                any(&self.detection) || any(&self.false_positives)
            })
            .cloned()
            .collect()
    }
}

/// Collapse numbers so "High entropy detected: 7.21" and "...: 7.85" count
/// as one indicator.
fn normalize_reason(reason: &str) -> String {
    let mut out = String::new();
    let mut in_number = false;
    for ch in reason.chars() {
        if ch.is_ascii_digit() || (in_number && ch == '.') {
            if !in_number {
                out.push('N');
                in_number = true;
            }
        } else {
            in_number = false;
            out.push(ch);
        }
    }
    out.chars().take(90).collect()
}

fn top(counts: HashMap<String, usize>, n: usize) -> Vec<(String, usize)> {
    let mut v: Vec<_> = counts.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

fn ratio(n: usize, d: usize) -> f64 {
    if d == 0 {
        0.0
    } else {
        n as f64 / d as f64
    }
}

fn pct(r: f64) -> String {
    format!("{:.1}%", r * 100.0)
}

fn file_name(p: &Path) -> String {
    p.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(
        label: Label,
        group: &str,
        consensus: &str,
        votes: Vec<(&str, &str)>,
    ) -> SampleResult {
        let to_verdict = |v: &str| match v {
            "Malicious" => ThreatVerdict::Malicious,
            "Suspicious" => ThreatVerdict::Suspicious,
            "Benign" => ThreatVerdict::Benign,
            _ => ThreatVerdict::Unknown,
        };
        SampleResult {
            label,
            group: group.into(),
            family: (label == Label::Malicious).then(|| "Fam".into()),
            file: format!("{group}-file"),
            sha256: String::new(),
            size: 1,
            consensus: consensus.into(),
            consensus_outcome: outcome_of(&to_verdict(consensus), false),
            votes: votes
                .into_iter()
                .map(|(engine, v)| Vote {
                    engine: engine.into(),
                    verdict: v.into(),
                    outcome: outcome_of(&to_verdict(v), false),
                    confidence: 0.5,
                    score: None,
                    reasons: vec![],
                    yara_rules: if engine == "YARA" && v != "Benign" {
                        vec!["Rule_A".into()]
                    } else {
                        vec![]
                    },
                })
                .collect(),
            ms: 1,
        }
    }

    #[test]
    fn report_counts_detections_and_false_positives() {
        let results = vec![
            result(
                Label::Malicious,
                "pe",
                "Malicious",
                vec![("YARA", "Malicious"), ("Static", "Benign")],
            ),
            result(
                Label::Malicious,
                "pe",
                "Benign",
                vec![("YARA", "Benign"), ("Static", "Benign")],
            ),
            result(
                Label::Malicious,
                "script",
                "Suspicious",
                vec![("YARA", "Suspicious"), ("Static", "Unknown")],
            ),
            result(
                Label::Clean,
                "putty",
                "Benign",
                vec![("YARA", "Benign"), ("Static", "Benign")],
            ),
            result(
                Label::Clean,
                "putty",
                "Suspicious",
                vec![("YARA", "Suspicious"), ("Static", "Benign")],
            ),
        ];
        let r = Report::build(&results, &[], 0, false, &HashMap::new(), 1);

        let c = r.detection[CONSENSUS];
        assert_eq!(
            (c.total, c.flagged, c.malicious_verdicts, c.benign),
            (3, 2, 1, 1)
        );
        let fp = r.false_positives[CONSENSUS];
        assert_eq!((fp.total, fp.flagged), (2, 1));

        let s = r.detection["Static"];
        assert_eq!((s.flagged, s.benign, s.no_verdict), (0, 2, 1));
        assert_eq!(r.detection_by_category["pe"][CONSENSUS].flagged, 1);
        assert_eq!(r.yara_rules_on_clean, vec![("Rule_A".to_string(), 1)]);
        assert_eq!(r.consensus_false_positives.len(), 1);
        assert_eq!(r.consensus_false_positives[0].1, vec!["YARA".to_string()]);
        assert!(r.missed_families.is_empty());

        let md = r.markdown();
        assert!(md.contains("| Malware flagged | **66.7%** (2/3) |"));
        assert!(md.contains("| Clean files flagged (false positives) | **50.0%** (1/2) |"));
    }

    #[test]
    fn numbers_in_reasons_are_collapsed() {
        assert_eq!(
            normalize_reason("High entropy detected: 7.21"),
            "High entropy detected: N"
        );
        assert_eq!(
            normalize_reason("12 suspicious imports"),
            "N suspicious imports"
        );
    }

    #[test]
    fn errored_detection_has_no_verdict() {
        assert!(outcome_of(&ThreatVerdict::Malicious, true) == Outcome::NoVerdict);
        assert!(outcome_of(&ThreatVerdict::Unknown, false) == Outcome::NoVerdict);
        assert!(outcome_of(&ThreatVerdict::Suspicious, false) == Outcome::Flagged);
    }
}
