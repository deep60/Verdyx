//! Unpack archives so the engines can see the files inside.
//!
//! Malware is usually delivered zipped, often with the password `infected`, so
//! judging only the archive's compressed bytes misses it. [`unpack`] returns
//! the inner files of a zip, 7z, tar, gzip or tar.gz, bounded by
//! [`UnpackLimits`] so a hostile archive (a zip bomb, thousands of entries)
//! can't exhaust memory. Each read is capped while decompressing, so sizes
//! claimed in archive headers are never trusted.
//!
//! Formats that are zip files underneath but have their own structure (Office
//! documents, Android APKs, Java JARs, OpenDocument) are not treated as plain
//! archives: their parts mean nothing on their own to the generic engines.

use std::io::{Cursor, Read};

/// Passwords commonly used to share malware samples (MalwareBazaar, vx-
/// underground, mail attachments). Tried in order on encrypted archives.
pub const COMMON_PASSWORDS: [&str; 3] = ["infected", "malware", "virus"];

#[derive(Debug, Clone, Copy)]
pub struct UnpackLimits {
    /// Files taken from one archive; the rest are listed as skipped.
    pub max_members: usize,
    /// A file larger than this when decompressed is skipped.
    pub max_member_bytes: u64,
    /// Decompressed bytes taken from one archive in total.
    pub max_total_bytes: u64,
}

impl UnpackLimits {
    /// Deep Inspection: twice the files per archive. The byte limits stay,
    /// because they are what keeps the engine inside its memory limit.
    pub fn deep() -> Self {
        Self {
            max_members: 50,
            ..Self::default()
        }
    }
}

impl Default for UnpackLimits {
    fn default() -> Self {
        Self {
            max_members: 25,
            // Sized for the 224 MB analysis-engine container: the unpacked
            // files are held in memory next to the archive itself.
            max_member_bytes: 24 * 1024 * 1024,
            max_total_bytes: 48 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArchiveFormat {
    Zip,
    SevenZip,
    Tar,
    Gzip,
}

impl ArchiveFormat {
    pub fn name(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::SevenZip => "7z",
            Self::Tar => "tar",
            Self::Gzip => "gzip",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Member {
    /// Path inside the archive.
    pub path: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Unpacked {
    pub format: ArchiveFormat,
    pub members: Vec<Member>,
    /// Files that weren't taken, with the reason.
    pub skipped: Vec<String>,
    /// The common password that opened it, if it was encrypted.
    pub password: Option<&'static str>,
    /// Encrypted, and none of [`COMMON_PASSWORDS`] opened it.
    pub locked: bool,
}

const ZIP_MAGIC: &[u8] = b"PK\x03\x04";
const SEVENZ_MAGIC: &[u8] = b"7z\xBC\xAF\x27\x1C";
const GZIP_MAGIC: &[u8] = &[0x1f, 0x8b];

/// The archive format of `data`, if it is one this module unpacks.
pub fn detect(data: &[u8]) -> Option<ArchiveFormat> {
    if data.starts_with(ZIP_MAGIC) {
        return (!is_structured_zip(data)).then_some(ArchiveFormat::Zip);
    }
    if data.starts_with(SEVENZ_MAGIC) {
        return Some(ArchiveFormat::SevenZip);
    }
    if data.starts_with(GZIP_MAGIC) {
        return Some(ArchiveFormat::Gzip);
    }
    if is_tar(data) {
        return Some(ArchiveFormat::Tar);
    }
    None
}

fn is_tar(data: &[u8]) -> bool {
    data.len() >= 512 && data.get(257..262) == Some(b"ustar".as_slice())
}

/// Office (OOXML), OpenDocument, APK and JAR files are zips with a known
/// layout. They are documents or apps, not archives of independent files.
fn is_structured_zip(data: &[u8]) -> bool {
    let Ok(archive) = zip::ZipArchive::new(Cursor::new(data)) else {
        return false;
    };
    let structured = archive.file_names().any(|name| {
        let Ok(name) = name.as_ref() else {
            return false;
        };
        matches!(
            name.as_ref(),
            "[Content_Types].xml" | "AndroidManifest.xml" | "META-INF/MANIFEST.MF" | "mimetype"
        )
    });
    structured
}

/// Unpack `data`, or `None` if it isn't an archive this module handles or
/// can't be read as one.
pub fn unpack(data: &[u8], limits: UnpackLimits) -> Option<Unpacked> {
    let format = detect(data)?;
    let mut out = Unpacked {
        format,
        members: Vec::new(),
        skipped: Vec::new(),
        password: None,
        locked: false,
    };
    let mut budget = Budget::new(limits);
    let ok = match format {
        ArchiveFormat::Zip => unpack_zip(data, &mut budget, &mut out),
        ArchiveFormat::SevenZip => unpack_7z(data, &mut budget, &mut out),
        ArchiveFormat::Tar => unpack_tar(data, &mut budget, &mut out),
        ArchiveFormat::Gzip => unpack_gzip(data, &mut budget, &mut out),
    };
    ok.then_some(out)
}

struct Budget {
    limits: UnpackLimits,
    used: u64,
}

impl Budget {
    fn new(limits: UnpackLimits) -> Self {
        Self { limits, used: 0 }
    }

    /// Read one member, enforcing every limit while decompressing. `Err` is
    /// the reason it was skipped; `Ok(None)` means the reader failed.
    fn take(&mut self, out: &mut Unpacked, path: &str, reader: &mut dyn Read) -> Take {
        if out.members.len() >= self.limits.max_members {
            return Take::Skipped(format!(
                "{path}: more than {} files",
                self.limits.max_members
            ));
        }
        let room = self
            .limits
            .max_member_bytes
            .min(self.limits.max_total_bytes.saturating_sub(self.used));
        let mut data = Vec::new();
        if reader.take(room + 1).read_to_end(&mut data).is_err() {
            return Take::Failed;
        }
        if data.len() as u64 > room {
            return Take::Skipped(if room < self.limits.max_member_bytes {
                format!("{path}: total unpacked size limit reached")
            } else {
                format!(
                    "{path}: larger than {} MB unpacked",
                    self.limits.max_member_bytes / (1024 * 1024)
                )
            });
        }
        self.used += data.len() as u64;
        out.members.push(Member {
            path: path.to_string(),
            data,
        });
        Take::Taken
    }
}

enum Take {
    Taken,
    Skipped(String),
    Failed,
}

fn unpack_zip(data: &[u8], budget: &mut Budget, out: &mut Unpacked) -> bool {
    let Ok(mut archive) = zip::ZipArchive::new(Cursor::new(data)) else {
        return false;
    };
    let encrypted = (0..archive.len()).any(|i| {
        archive
            .by_index_raw(i)
            .map(|f| f.encrypted())
            .unwrap_or(false)
    });
    let passwords: Vec<Option<&'static str>> = if encrypted {
        COMMON_PASSWORDS.iter().copied().map(Some).collect()
    } else {
        vec![None]
    };

    for password in passwords {
        let mut attempt = Unpacked {
            members: Vec::new(),
            skipped: Vec::new(),
            ..out.clone()
        };
        let mut attempt_budget = Budget::new(budget.limits);
        let mut wrong_password = false;
        for i in 0..archive.len() {
            let entry = match password {
                Some(p) => archive.by_index_decrypt(i, p.as_bytes()),
                None => archive.by_index(i),
            };
            let mut entry = match entry {
                Ok(e) => e,
                Err(zip::result::ZipError::InvalidPassword) => {
                    wrong_password = true;
                    break;
                }
                Err(e) => {
                    attempt.skipped.push(format!("entry {i}: {e}"));
                    continue;
                }
            };
            if !entry.is_file() {
                continue;
            }
            let path = entry.name().map(|n| n.to_string()).unwrap_or_default();
            match attempt_budget.take(&mut attempt, &path, &mut entry) {
                Take::Taken => {}
                Take::Skipped(why) => attempt.skipped.push(why),
                // A ZipCrypto password passes the header check 1 time in 256
                // and then fails the CRC: treat it as the wrong password.
                Take::Failed if password.is_some() => {
                    wrong_password = true;
                    break;
                }
                Take::Failed => attempt.skipped.push(format!("{path}: could not be read")),
            }
        }
        if !wrong_password {
            attempt.password = password;
            *out = attempt;
            budget.used = attempt_budget.used;
            return true;
        }
    }
    out.locked = true;
    true
}

fn unpack_7z(data: &[u8], budget: &mut Budget, out: &mut Unpacked) -> bool {
    use sevenz_rust2::{ArchiveReader, Password};

    let mut tried_password = false;
    for password in std::iter::once(None).chain(COMMON_PASSWORDS.iter().copied().map(Some)) {
        let pw = password.map(Password::new).unwrap_or_else(Password::empty);
        let Ok(mut reader) = ArchiveReader::new(Cursor::new(data), pw) else {
            if password.is_none() {
                // Encrypted headers fail here without a password.
                continue;
            }
            tried_password = true;
            continue;
        };
        let mut attempt = Unpacked {
            members: Vec::new(),
            skipped: Vec::new(),
            ..out.clone()
        };
        let mut attempt_budget = Budget::new(budget.limits);
        let mut failed = false;
        let result = reader.for_each_entries(|entry, r| {
            if entry.is_directory() {
                return Ok(true);
            }
            let path = entry.name().to_string();
            match attempt_budget.take(&mut attempt, &path, r) {
                Take::Taken => {}
                Take::Skipped(why) => attempt.skipped.push(why),
                Take::Failed => {
                    failed = true;
                    return Ok(false);
                }
            }
            Ok(true)
        });
        if result.is_err() || failed {
            tried_password |= password.is_some();
            continue;
        }
        attempt.password = password;
        *out = attempt;
        budget.used = attempt_budget.used;
        return true;
    }
    if tried_password {
        out.locked = true;
        return true;
    }
    false
}

fn unpack_tar(data: &[u8], budget: &mut Budget, out: &mut Unpacked) -> bool {
    let mut archive = tar::Archive::new(Cursor::new(data));
    let Ok(entries) = archive.entries() else {
        return false;
    };
    for entry in entries {
        let Ok(mut entry) = entry else {
            out.skipped.push("an entry could not be read".to_string());
            break;
        };
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        match budget.take(out, &path, &mut entry) {
            Take::Taken => {}
            Take::Skipped(why) => out.skipped.push(why),
            Take::Failed => out.skipped.push(format!("{path}: could not be read")),
        }
    }
    true
}

/// A gzip holds one stream: a tarball (unpacked as tar) or a single file.
fn unpack_gzip(data: &[u8], budget: &mut Budget, out: &mut Unpacked) -> bool {
    let mut decoder = flate2::read::GzDecoder::new(data);
    let name = decoder
        .header()
        .and_then(|h| h.filename())
        .map(|f| String::from_utf8_lossy(f).into_owned())
        .unwrap_or_else(|| "(decompressed)".to_string());
    let mut single = Unpacked {
        members: Vec::new(),
        skipped: Vec::new(),
        ..out.clone()
    };
    match budget.take(&mut single, &name, &mut decoder) {
        Take::Taken => {}
        Take::Skipped(why) => {
            out.skipped.push(why);
            return true;
        }
        Take::Failed => return false,
    }
    let inner = single.members.pop().expect("taken member");
    if is_tar(&inner.data) {
        budget.used = 0;
        return unpack_tar(&inner.data, budget, out);
    }
    out.members.push(inner);
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn zip_of(files: &[(&str, &[u8])], password: Option<&str>) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = zip::ZipWriter::new(Cursor::new(&mut buf));
            for (name, body) in files {
                let mut opts = zip::write::SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Deflated);
                if let Some(p) = password {
                    opts = opts.with_aes_encryption(zip::AesMode::Aes256, p);
                }
                w.start_file(*name, opts).unwrap();
                w.write_all(body).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    #[test]
    fn plain_zip_members_come_out() {
        let z = zip_of(&[("a.txt", b"hello"), ("dir/b.exe", b"MZ....")], None);
        let u = unpack(&z, UnpackLimits::default()).unwrap();
        assert_eq!(u.format, ArchiveFormat::Zip);
        let names: Vec<_> = u.members.iter().map(|m| m.path.as_str()).collect();
        assert_eq!(names, ["a.txt", "dir/b.exe"]);
        assert_eq!(u.members[1].data, b"MZ....");
        assert!(u.password.is_none() && !u.locked);
    }

    #[test]
    fn infected_password_opens_the_zip() {
        let z = zip_of(&[("payload.exe", b"MZ payload")], Some("infected"));
        let u = unpack(&z, UnpackLimits::default()).unwrap();
        assert_eq!(u.password, Some("infected"));
        assert_eq!(u.members[0].data, b"MZ payload");
    }

    #[test]
    fn unknown_password_is_reported_locked() {
        let z = zip_of(&[("payload.exe", b"MZ payload")], Some("s3cret-Unknown"));
        let u = unpack(&z, UnpackLimits::default()).unwrap();
        assert!(u.locked && u.members.is_empty());
    }

    #[test]
    fn a_zip_bomb_is_cut_off_while_decompressing() {
        let big = vec![0u8; 5 * 1024 * 1024];
        let z = zip_of(&[("bomb.bin", &big)], None);
        assert!(z.len() < 64 * 1024, "compresses well");
        let limits = UnpackLimits {
            max_member_bytes: 1024 * 1024,
            ..Default::default()
        };
        let u = unpack(&z, limits).unwrap();
        assert!(u.members.is_empty());
        assert!(u.skipped[0].contains("larger than 1 MB"));
    }

    #[test]
    fn member_count_and_total_size_are_capped() {
        let files: Vec<(String, Vec<u8>)> = (0..30)
            .map(|i| (format!("f{i}.txt"), vec![b'x'; 10]))
            .collect();
        let refs: Vec<(&str, &[u8])> = files
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let u = unpack(&zip_of(&refs, None), UnpackLimits::default()).unwrap();
        assert_eq!(u.members.len(), 25);
        assert_eq!(u.skipped.len(), 5);

        let limits = UnpackLimits {
            max_total_bytes: 25,
            ..Default::default()
        };
        let u = unpack(&zip_of(&refs, None), limits).unwrap();
        assert_eq!(u.members.len(), 2);
        assert!(u.skipped.iter().any(|s| s.contains("total unpacked size")));
    }

    #[test]
    fn office_apk_and_jar_files_are_not_plain_archives() {
        let docx = zip_of(
            &[
                ("[Content_Types].xml", b"<Types/>"),
                ("word/document.xml", b"<w/>"),
            ],
            None,
        );
        let apk = zip_of(
            &[("AndroidManifest.xml", b"x"), ("classes.dex", b"dex")],
            None,
        );
        let jar = zip_of(&[("META-INF/MANIFEST.MF", b"x"), ("A.class", b"x")], None);
        for f in [docx, apk, jar] {
            assert!(detect(&f).is_none());
        }
    }

    #[test]
    fn tar_and_tar_gz_are_unpacked() {
        let mut tar_bytes = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_bytes);
            let body = b"#!/bin/sh\necho hi\n";
            let mut h = tar::Header::new_gnu();
            h.set_size(body.len() as u64);
            h.set_mode(0o755);
            h.set_cksum();
            b.append_data(&mut h, "run.sh", &body[..]).unwrap();
            b.finish().unwrap();
        }
        let u = unpack(&tar_bytes, UnpackLimits::default()).unwrap();
        assert_eq!(u.format, ArchiveFormat::Tar);
        assert_eq!(u.members[0].path, "run.sh");

        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        gz.write_all(&tar_bytes).unwrap();
        let tgz = gz.finish().unwrap();
        let u = unpack(&tgz, UnpackLimits::default()).unwrap();
        assert_eq!(u.format, ArchiveFormat::Gzip);
        assert_eq!(u.members[0].path, "run.sh");
    }

    #[test]
    fn single_file_gzip_is_unpacked() {
        let mut gz = flate2::GzBuilder::new()
            .filename("invoice.js")
            .write(Vec::new(), flate2::Compression::default());
        gz.write_all(b"eval(unescape('%61'))").unwrap();
        let u = unpack(&gz.finish().unwrap(), UnpackLimits::default()).unwrap();
        assert_eq!(u.members[0].path, "invoice.js");
        assert_eq!(u.members[0].data, b"eval(unescape('%61'))");
    }

    fn sevenz_of(name: &str, body: &[u8], password: Option<&str>) -> Vec<u8> {
        use sevenz_rust2::{
            encoder_options::AesEncoderOptions, ArchiveEntry, ArchiveWriter, EncoderMethod,
            Password,
        };
        let mut w = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        if let Some(p) = password {
            w.set_content_methods(vec![
                AesEncoderOptions::new(Password::new(p)).into(),
                EncoderMethod::LZMA2.into(),
            ]);
        }
        w.push_archive_entry(ArchiveEntry::new_file(name), Some(body))
            .unwrap();
        w.finish().unwrap().into_inner()
    }

    #[test]
    fn sevenz_plain_and_infected_are_unpacked() {
        let limits = UnpackLimits::default();
        let u = unpack(&sevenz_of("a.vbs", b"WScript.Echo 1", None), limits).unwrap();
        assert_eq!(u.format, ArchiveFormat::SevenZip);
        assert_eq!(u.members[0].path, "a.vbs");
        assert_eq!(u.members[0].data, b"WScript.Echo 1");

        let u = unpack(&sevenz_of("p.exe", b"MZ inside", Some("infected")), limits).unwrap();
        assert_eq!(u.password, Some("infected"));
        assert_eq!(u.members[0].data, b"MZ inside");

        let u = unpack(
            &sevenz_of("p.exe", b"MZ inside", Some("other-secret")),
            limits,
        )
        .unwrap();
        assert!(u.locked && u.members.is_empty());
    }

    #[test]
    fn non_archives_are_left_alone() {
        assert!(unpack(b"MZ\x90\x00 just a program", UnpackLimits::default()).is_none());
        assert!(unpack(b"PK\x03\x04 truncated", UnpackLimits::default()).is_none());
    }
}
