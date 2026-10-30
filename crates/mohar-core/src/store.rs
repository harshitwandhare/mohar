//! The receipt log on disk: one directory per log.
//!
//! ```text
//! key.ed25519     32-byte signing seed, owner-only on Unix. Belongs to the daemon's OS user.
//! public.key      ed25519:<hex>, for anyone verifying the log.
//! receipts.jsonl  one receipt per line, oldest first, appended and synced before append returns.
//! writer.lock     held exclusively by the one process allowed to append; readers don't need it.
//! checkpoints.jsonl  signed checkpoints, one per line.
//! segments/       closed segments, named by the seq of their first receipt (20 digits), each one
//!                 ended by a signed checkpoint. receipts.jsonl continues where the last one stops.
//! ```
//!
//! With a segment size set, receipts.jsonl is closed once it reaches that size: a checkpoint is signed
//! for the log as it stands, the file moves into `segments/` and a new, empty one takes its place.
//! Segments can be archived oldest first; verification then starts from the checkpoint that closed
//! the last one removed. A missing segment between two present ones is a gap and fails.
//!
//! A log in strict privacy mode (see [`crate::privacy`]) also holds:
//!
//! ```text
//! privacy.key       32-byte secret for the pseudonyms, owner-only on Unix, beside the signing key.
//! identities.jsonl  {"id": pseudonym, "value": clear value}, one per line; outside the chain, erasable.
//! ```
//!
//! Opening a log verifies the whole chain first, one line at a time, so memory use doesn't grow with the
//! log. A log that doesn't verify is never extended.

use std::collections::{HashSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, mpsc};

use serde::{Deserialize, Serialize};

use crate::Prechecked;
use crate::checkpoint::{self, Checkpoint, CheckpointBreak, CheckpointWatcher};
use crate::privacy::{Pseudonyms, is_pseudonym};
use crate::{
    BreakKind, ChainBreak, ChainVerifier, Entry, Error, Receipt, SigningKey, VerifyingKey,
    public_key_string, receipt_hash, seal,
};

const KEY_FILE: &str = "key.ed25519";
const PUBLIC_FILE: &str = "public.key";
const LOG_FILE: &str = "receipts.jsonl";
const CHECKPOINT_FILE: &str = "checkpoints.jsonl";
const LOCK_FILE: &str = "writer.lock";
const PRIVACY_KEY_FILE: &str = "privacy.key";
const IDENTITIES_FILE: &str = "identities.jsonl";
const SEGMENT_DIR: &str = "segments";
const SEGMENT_SUFFIX: &str = ".jsonl";
/// Digits in a segment's name, enough for any u64, so names sort in log order.
const SEGMENT_DIGITS: usize = 20;

/// A checkpoint is signed automatically after every this many receipts.
pub const CHECKPOINT_EVERY: u64 = 1000;

/// Why a log directory couldn't be created or opened.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// A file couldn't be read or written.
    #[error("{path}: {source}")]
    Io {
        /// The file involved.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// Another process has this log open for writing.
    #[error("{0} is open for writing by another process")]
    Locked(PathBuf),
    /// `init` was pointed at a directory that already holds a log.
    #[error("{0} already holds a Mohar log")]
    AlreadyExists(PathBuf),
    /// A key file (the signing seed or the privacy secret) isn't 32 bytes.
    #[error("{0} is not a 32-byte key")]
    BadKey(PathBuf),
    /// The log keeps identities in strict privacy mode but its privacy key is gone. Writing on
    /// without it would put new ids and targets in the clear.
    #[error("{0} is missing; this log is in strict privacy mode")]
    PrivacyKeyMissing(PathBuf),
    /// A line isn't a complete receipt, usually a write cut short by a crash.
    #[error("receipts.jsonl line {line} is not a complete receipt")]
    Unreadable {
        /// 1-based line number.
        line: usize,
    },
    /// The receipts parse but the chain doesn't verify.
    #[error("chain does not verify: {0}")]
    Chain(ChainBreak),
    /// The log no longer holds what a signed checkpoint vouched for.
    #[error("checkpoints do not match: {0}")]
    Checkpoint(CheckpointBreak),
    /// A line of a checkpoints file isn't a complete checkpoint.
    #[error("{} line {line} is not a complete checkpoint", path.display())]
    UnreadableCheckpoint {
        /// The checkpoints file.
        path: PathBuf,
        /// 1-based line number.
        line: usize,
    },
    /// A line of a closed segment isn't a complete receipt.
    #[error("{} line {line} is not a complete receipt", path.display())]
    UnreadableSegment {
        /// The segment file.
        path: PathBuf,
        /// 1-based line number.
        line: usize,
    },
    /// The segments don't fit together, or one isn't closed by a signed checkpoint.
    #[error("segments: {0}")]
    Segment(SegmentBreak),
    /// A rotation moved the full file away but couldn't create the next one. Nothing more is written
    /// until the log is opened again, which finishes the rotation.
    #[error("rotation of {0} did not finish; open the log again")]
    Unfinished(PathBuf),
    /// A receipt couldn't be built or signed.
    #[error(transparent)]
    Receipt(#[from] Error),
}

/// Why the segments of a log don't add up to one verifiable chain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SegmentBreak {
    /// A file in `segments/` isn't named by a 20-digit receipt number.
    #[error("{} is not a segment name", path.display())]
    BadName {
        /// The file.
        path: PathBuf,
    },
    /// A segment doesn't start where the one before it ended: one is missing or was cut short.
    #[error("{} starts at receipt {found}, but the log so far ends at {expected}", path.display())]
    Gap {
        /// The segment, or receipts.jsonl.
        path: PathBuf,
        /// Receipts read before it.
        expected: u64,
        /// Where its name says it starts.
        found: u64,
    },
    /// No signed checkpoint vouches for the log at the end of this closed segment.
    #[error("{} ends at {count} receipts with no signed checkpoint there", path.display())]
    Unclosed {
        /// The segment.
        path: PathBuf,
        /// Receipts in the log at its end.
        count: u64,
    },
    /// Verification starts after receipt 0 (older segments archived, or a starting point asked for),
    /// and no signed checkpoint says what the log held there.
    #[error("no signed checkpoint at {count} receipts to start from")]
    NoAnchor {
        /// Where verification would start.
        count: u64,
    },
}

/// A closed segment of a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Sequence number of its first receipt.
    pub start: u64,
    /// The file.
    pub path: PathBuf,
}

fn segment_name(start: u64) -> String {
    format!("{start:0width$}{SEGMENT_SUFFIX}", width = SEGMENT_DIGITS)
}

/// The closed segments of the log in `dir`, oldest first; none if it never rotated. Anything else in
/// `segments/` is refused, so a misnamed segment can't be silently left out.
pub fn segments(dir: &Path) -> Result<Vec<Segment>, OpenError> {
    let seg_dir = dir.join(SEGMENT_DIR);
    let read = match fs::read_dir(&seg_dir) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(io(&seg_dir)(e)),
    };
    let mut out = Vec::new();
    for item in read {
        let path = item.map_err(io(&seg_dir))?.path();
        let start = path
            .file_name()
            .and_then(|n| n.to_str())
            .and_then(|n| n.strip_suffix(SEGMENT_SUFFIX))
            .filter(|n| n.len() == SEGMENT_DIGITS && n.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|n| n.parse::<u64>().ok());
        match start {
            Some(start) if path.is_file() => out.push(Segment { start, path }),
            _ => return Err(OpenError::Segment(SegmentBreak::BadName { path })),
        }
    }
    out.sort_by_key(|s| s.start);
    Ok(out)
}

/// Every file of the log in order: the closed segments, then receipts.jsonl, which a crash during
/// rotation can leave missing once there are segments.
fn log_files(dir: &Path) -> Result<Vec<(Option<u64>, PathBuf)>, OpenError> {
    let closed = segments(dir)?;
    let active = dir.join(LOG_FILE);
    let keep_active = closed.is_empty() || active.exists();
    let mut files: Vec<(Option<u64>, PathBuf)> = closed
        .into_iter()
        .map(|s| (Some(s.start), s.path))
        .collect();
    if keep_active {
        files.push((None, active));
    }
    Ok(files)
}

/// Where verification of a rotated log must start when every closed segment has been archived, so
/// receipts.jsonl has no name saying where it begins: at its first receipt, or, with no receipts, at
/// the furthest of the log's own checkpoints (rotation always signs one at the boundary). Either way a signed checkpoint
/// must vouch for that point. `None` for a log that never rotated, or one with segments left.
fn archived_start(
    dir: &Path,
    files: &[(Option<u64>, PathBuf)],
    checkpoints: &[Checkpoint],
) -> Result<Option<u64>, OpenError> {
    let [(None, active)] = files else {
        return Ok(None);
    };
    if !dir.join(SEGMENT_DIR).exists() {
        return Ok(None);
    }
    let mut first = None;
    // A crash during rotation can leave it missing; that reads as no receipts.
    if let Ok(file) = File::open(active) {
        for line in BufReader::new(file).lines() {
            let line = line.map_err(io(active))?;
            if !line.trim().is_empty() {
                // A line that doesn't parse is left for the verifier to report.
                first = serde_json::from_str::<Receipt>(&line).ok().map(|r| r.seq);
                break;
            }
        }
    }
    Ok(first.or_else(|| checkpoints.iter().map(|c| c.count).max()))
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), OpenError> {
    File::open(dir).and_then(|d| d.sync_all()).map_err(io(dir))
}

/// Windows has no directory sync; a rename there is made durable by the file system's own journal.
#[cfg(not(unix))]
fn sync_dir(_: &Path) -> Result<(), OpenError> {
    Ok(())
}

fn io(path: &Path) -> impl FnOnce(std::io::Error) -> OpenError + '_ {
    move |source| OpenError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// An open, verified log that appends durably.
pub struct FileLog {
    /// Held for the life of the log; the OS releases it when this is dropped or the process exits.
    _lock: File,
    key: SigningKey,
    file: File,
    dir: PathBuf,
    path: PathBuf,
    checkpoint_path: PathBuf,
    last_hash: String,
    len: u64,
    /// Seq of the first receipt in receipts.jsonl.
    active_start: u64,
    /// Size of receipts.jsonl.
    active_bytes: u64,
    /// Rotate once receipts.jsonl reaches this many bytes; never when `None`.
    segment_bytes: Option<u64>,
    /// Set when a rotation stopped halfway; appends are refused until the log is reopened.
    unfinished: bool,
    /// Set in strict privacy mode.
    identities: Option<Identities>,
}

/// The pseudonyms of a strict-privacy log and the file that maps them back.
struct Identities {
    pseudonyms: Pseudonyms,
    file: File,
    path: PathBuf,
    /// Pseudonyms already in the file, so each is written once.
    known: HashSet<String>,
}

/// One line of `identities.jsonl`.
#[derive(Serialize, Deserialize)]
struct Identity {
    id: String,
    value: String,
}

impl Identities {
    /// The privacy state of the log in `dir`: `None` when it has no privacy key and no identities.
    fn open(dir: &Path) -> Result<Option<Self>, OpenError> {
        let key_path = dir.join(PRIVACY_KEY_FILE);
        let path = dir.join(IDENTITIES_FILE);
        let key = match fs::read(&key_path) {
            Ok(bytes) => bytes
                .try_into()
                .map_err(|_| OpenError::BadKey(key_path.clone()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // With the mapping erased too, the log itself still shows the mode it was made in.
                if path.exists() || first_agent_is_pseudonym(dir)? {
                    return Err(OpenError::PrivacyKeyMissing(key_path));
                }
                return Ok(None);
            }
            Err(e) => return Err(io(&key_path)(e)),
        };
        // Deleting the whole file is a valid way to erase everyone, so it may be missing.
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&path)
            .map_err(io(&path))?;
        let text = fs::read(&path).map_err(io(&path))?;
        // A line cut short by a crash is skipped; its value is written again when next seen.
        let known = text
            .split(|&b| b == b'\n')
            .filter_map(|l| serde_json::from_slice::<Identity>(l).ok())
            .map(|i| i.id)
            .collect();
        if text.last().is_some_and(|&b| b != b'\n') {
            // End the torn line, so the next one isn't glued onto it.
            file.write_all(b"\n").map_err(io(&path))?;
        }
        Ok(Some(Self {
            pseudonyms: Pseudonyms::new(key),
            file,
            path,
            known,
        }))
    }

    /// The pseudonym for `value`, after its mapping back is on disk.
    fn record(&mut self, value: String) -> Result<String, OpenError> {
        let id = self.pseudonyms.pseudonym(&value);
        if id != value && !self.known.contains(&id) {
            let mut line = serde_json::to_vec(&Identity {
                id: id.clone(),
                value,
            })
            .map_err(|e| Error::Canonical(e.to_string()))?;
            line.push(b'\n');
            self.file.write_all(&line).map_err(io(&self.path))?;
            self.file.sync_data().map_err(io(&self.path))?;
            self.known.insert(id.clone());
        }
        Ok(id)
    }
}

/// Whether the log's oldest receipt still present names its agent by a pseudonym: only a
/// strict-privacy log writes one, since the daemon refuses them as input. Called after the chain
/// verified, so the line parses.
fn first_agent_is_pseudonym(dir: &Path) -> Result<bool, OpenError> {
    let mut line = String::new();
    for (_, path) in log_files(dir)? {
        if !path.exists() {
            continue;
        }
        BufReader::new(File::open(&path).map_err(io(&path))?)
            .read_line(&mut line)
            .map_err(io(&path))?;
        if !line.trim().is_empty() {
            break;
        }
    }
    Ok(serde_json::from_str::<Receipt>(&line).is_ok_and(|r| is_pseudonym(&r.agent.id)))
}

impl FileLog {
    /// Create a new log in `dir` with a fresh signing key. Refuses to touch an existing log.
    pub fn init(dir: &Path) -> Result<Self, OpenError> {
        Self::create(dir, false)
    }

    /// Like [`FileLog::init`], in strict privacy mode: agent ids and targets go into the chain only
    /// as keyed hashes (see [`crate::privacy`]).
    pub fn init_strict(dir: &Path) -> Result<Self, OpenError> {
        Self::create(dir, true)
    }

    fn create(dir: &Path, strict: bool) -> Result<Self, OpenError> {
        if dir.join(KEY_FILE).exists()
            || dir.join(LOG_FILE).exists()
            || dir.join(SEGMENT_DIR).exists()
        {
            return Err(OpenError::AlreadyExists(dir.to_path_buf()));
        }
        fs::create_dir_all(dir).map_err(io(dir))?;
        let key = SigningKey::generate()?;

        let key_path = dir.join(KEY_FILE);
        write_private(&key_path, &key.seed()).map_err(io(&key_path))?;
        let pub_path = dir.join(PUBLIC_FILE);
        fs::write(&pub_path, public_key_string(&key.verifying_key()) + "\n")
            .map_err(io(&pub_path))?;
        if strict {
            let mut secret = [0u8; 32];
            getrandom::fill(&mut secret).map_err(|e| Error::Random(e.to_string()))?;
            let privacy_path = dir.join(PRIVACY_KEY_FILE);
            write_private(&privacy_path, &secret).map_err(io(&privacy_path))?;
        }
        let log_path = dir.join(LOG_FILE);
        File::create(&log_path)
            .map_err(io(&log_path))?
            .sync_all()
            .map_err(io(&log_path))?;

        Self::open(dir)
    }

    /// Open an existing log, verifying every receipt against the log's own public key first.
    pub fn open(dir: &Path) -> Result<Self, OpenError> {
        let lock_path = dir.join(LOCK_FILE);
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(io(&lock_path))?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => {
                return Err(OpenError::Locked(dir.to_path_buf()));
            }
            // The OS refused the lock call itself (no locking on this file system): fail, never write
            // without the lock.
            Err(std::fs::TryLockError::Error(e)) => return Err(io(&lock_path)(e)),
        }
        let key_path = dir.join(KEY_FILE);
        let seed = fs::read(&key_path).map_err(io(&key_path))?;
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| OpenError::BadKey(key_path.clone()))?;
        let key = SigningKey::from_seed(&seed);

        let path = dir.join(LOG_FILE);
        let checkpoint_path = dir.join(CHECKPOINT_FILE);
        // The daemon's own log, signed with the key it just read: receipts its checkpoints cover are
        // checked by hash, the rest in full. `mohar verify` checks every signature.
        let files = log_files(dir)?;
        let checkpoints = local_checkpoints(&checkpoint_path, &[])?;
        let from = archived_start(dir, &files, &checkpoints)?;
        let (stats, active_start) = verify_files(
            &files,
            checkpoints,
            &key.verifying_key(),
            SignatureChecks::AfterLastCheckpoint,
            from,
        )?;
        let identities = Identities::open(dir)?;
        // Missing only if a crash came between moving a full file into segments/ and creating its
        // successor; verification has just confirmed the segments end at a checkpoint.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(io(&path))?;
        let active_bytes = file.metadata().map_err(io(&path))?.len();
        Ok(Self {
            _lock: lock,
            key,
            file,
            dir: dir.to_path_buf(),
            path,
            checkpoint_path,
            last_hash: stats.head,
            len: stats.receipts,
            active_start,
            active_bytes,
            segment_bytes: None,
            unfinished: false,
            identities,
        })
    }

    /// Close receipts.jsonl into a segment once it reaches `bytes`, or never with `None` (the
    /// default). The receipt that crosses the limit stays in the segment it was written to.
    pub fn set_segment_bytes(&mut self, bytes: Option<u64>) {
        self.segment_bytes = bytes;
    }

    /// Sign a checkpoint for the log as it stands, move receipts.jsonl into `segments/`, and start
    /// an empty one. A crash at any point leaves a log that opens: before the move nothing changed but
    /// a checkpoint, after it the missing file is recreated on open.
    fn rotate(&mut self, ts: &str) -> Result<(), OpenError> {
        // `append` signs one itself at every CHECKPOINT_EVERY receipts.
        if !self.len.is_multiple_of(CHECKPOINT_EVERY) {
            self.checkpoint(ts)?;
        }
        let seg_dir = self.dir.join(SEGMENT_DIR);
        fs::create_dir_all(&seg_dir).map_err(io(&seg_dir))?;
        let to = seg_dir.join(segment_name(self.active_start));
        fs::rename(&self.path, &to).map_err(io(&to))?;
        self.unfinished = true;
        sync_dir(&seg_dir)?;
        sync_dir(&self.dir)?;
        let file = OpenOptions::new()
            .create_new(true)
            .append(true)
            .open(&self.path)
            .map_err(io(&self.path))?;
        file.sync_all().map_err(io(&self.path))?;
        sync_dir(&self.dir)?;
        self.file = file;
        self.active_start = self.len;
        self.active_bytes = 0;
        self.unfinished = false;
        Ok(())
    }

    /// The seed for review sampling, derived from the signing key so it needs no file of its own and
    /// is as secret as the key. Anyone holding the key can recompute which actions were sampled.
    pub fn review_seed(&self) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::new()
            .chain_update(b"mohar review seed v1")
            .chain_update(self.key.seed())
            .finalize()
            .into()
    }

    /// The log's public key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }

    /// Sign a lesson with the log's key, so a [`crate::lessons::Book`] for this log takes it.
    pub fn sign_lesson(
        &self,
        lesson: crate::lessons::Lesson,
    ) -> Result<crate::lessons::Lesson, Error> {
        crate::lessons::sign(&self.key, lesson)
    }

    /// Whether this log is in strict privacy mode.
    pub fn is_strict(&self) -> bool {
        self.identities.is_some()
    }

    /// How `value` is written into this log as an agent id or a target: its pseudonym in strict
    /// privacy mode, itself otherwise. Anything that compares ids with ones read back from the log
    /// goes through this.
    pub fn pseudonym(&self, value: &str) -> String {
        match &self.identities {
            Some(ids) => ids.pseudonyms.pseudonym(value),
            None => value.to_string(),
        }
    }

    /// Sign `entry`, write it, and sync it to disk before returning the receipt. In strict privacy
    /// mode the agent id and target are replaced by their pseudonyms first, and the mapping back is
    /// synced before the receipt is written.
    pub fn append(&mut self, mut entry: Entry) -> Result<Receipt, OpenError> {
        // Set only when the file system fails between a rename and a create, which tests can't
        // arrange portably.
        if self.unfinished {
            return Err(OpenError::Unfinished(self.path.clone()));
        }
        if let Some(ids) = &mut self.identities {
            entry.agent_id = ids.record(entry.agent_id)?;
            entry.action.target = ids.record(entry.action.target)?;
        }
        let r = seal(&self.key, self.len, self.last_hash.clone(), entry)?;
        let mut line = serde_json::to_vec(&r).map_err(|e| Error::Canonical(e.to_string()))?;
        line.push(b'\n');
        self.file.write_all(&line).map_err(io(&self.path))?;
        self.file.sync_data().map_err(io(&self.path))?;
        self.last_hash = receipt_hash(&r)?;
        self.len += 1;
        self.active_bytes += line.len() as u64;
        if self.len.is_multiple_of(CHECKPOINT_EVERY) {
            self.checkpoint(&r.ts)?;
        }
        if self
            .segment_bytes
            .is_some_and(|max| self.active_bytes >= max)
        {
            self.rotate(&r.ts)?;
        }
        Ok(r)
    }

    /// Sign and durably write a checkpoint for the log as it stands.
    pub fn checkpoint(&mut self, ts: &str) -> Result<Checkpoint, OpenError> {
        let c = checkpoint::sign(&self.key, self.len, self.last_hash.clone(), ts.to_string())?;
        let mut line = serde_json::to_vec(&c).map_err(|e| Error::Canonical(e.to_string()))?;
        line.push(b'\n');
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.checkpoint_path)
            .map_err(io(&self.checkpoint_path))?;
        f.write_all(&line).map_err(io(&self.checkpoint_path))?;
        f.sync_data().map_err(io(&self.checkpoint_path))?;
        Ok(c)
    }

    /// Number of receipts in the log.
    pub fn len(&self) -> u64 {
        self.len
    }

    /// Whether the log has no receipts yet.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Why [`verify_file`] or [`verify_log`] stopped. These are the same cases a failed [`FileLog::open`]
/// reports for the log itself.
pub type VerifyFileError = OpenError;

/// What a successful streaming verification saw.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stats {
    /// Receipts in the log.
    pub receipts: u64,
    /// Checkpoints checked against it.
    pub checkpoints: usize,
    /// Hash of the last receipt, or the all-zero genesis hash for an empty log.
    pub head: String,
    /// Seq of the first receipt checked: 0, unless older segments were archived or verification
    /// was asked to start at a checkpoint.
    pub first: u64,
}

/// Receipts read and checked together. This bounds memory, whatever the size of the log.
const BATCH: usize = 1024;

/// Call `f` on batches of at most [`BATCH`] consecutive receipts, reading one line at a time. A line
/// that doesn't parse is reported by number, but only after the receipts before it have been handed
/// to `f`; `f` can stop the walk by returning an error.
fn each_batch(
    path: &Path,
    mut f: impl FnMut(&mut Vec<Receipt>) -> Result<(), OpenError>,
) -> Result<(), OpenError> {
    let mut reader = BufReader::new(File::open(path).map_err(io(path))?);
    let mut line = String::new();
    let mut batch = Vec::with_capacity(BATCH);
    let mut number = 0;
    loop {
        line.clear();
        let eof = reader.read_line(&mut line).map_err(io(path))? == 0;
        number += 1;
        let mut unreadable = None;
        if !eof && !line.trim().is_empty() {
            match serde_json::from_str(&line) {
                Ok(r) => batch.push(r),
                Err(_) => unreadable = Some(OpenError::Unreadable { line: number }),
            }
        }
        if eof || unreadable.is_some() || batch.len() == BATCH {
            f(&mut batch)?;
            batch.clear();
        }
        if let Some(e) = unreadable {
            return Err(e);
        }
        if eof {
            return Ok(());
        }
    }
}

fn each_receipt(
    path: &Path,
    mut f: impl FnMut(Receipt) -> Result<(), OpenError>,
) -> Result<(), OpenError> {
    each_batch(path, |batch| batch.drain(..).try_for_each(&mut f))
}

/// Lines handed to a worker at once.
const JOB_LINES: usize = 256;

/// What became of one line of the log.
#[allow(clippy::large_enum_variant)] // handed on straight away, never stored; boxing would cost an allocation per receipt
enum Outcome {
    /// A receipt, with its signature and hash already worked out.
    Line(Receipt, Prechecked),
    /// The line (1-based) isn't a complete receipt.
    Unreadable(usize),
    /// A worker died before reporting on the receipts at this point, which fails them.
    Lost,
}

type Reply = Vec<Result<(Receipt, Prechecked), usize>>;

struct Job {
    lines: Vec<(usize, String)>,
    reply: mpsc::Sender<Reply>,
}

fn work(job: Job, key: &VerifyingKey, signed_from: u64) {
    let done = job
        .lines
        .into_iter()
        .map(
            |(number, line)| match serde_json::from_str::<Receipt>(&line) {
                Ok(r) => {
                    // A receipt claiming a position it doesn't hold fails the sequence check in the
                    // chain, so deciding by its own `seq` here can't skip a signature that counts.
                    let checked = if r.seq < signed_from {
                        Prechecked::hash_only(&r)
                    } else {
                        Prechecked::of(&r, key)
                    };
                    Ok((r, checked))
                }
                Err(_) => Err(number),
            },
        )
        .collect();
    // The reader has gone if this fails, and then nobody needs the answer.
    let _ = job.reply.send(done);
}

/// Parse and pre-check every line of the log on a pool of worker threads that lives for the whole
/// walk, handing the results to `f` strictly in file order. At most a few jobs per worker are in
/// flight, so memory doesn't depend on the length of the log. `f` stops the walk by returning an error.
fn verify_lines(
    path: &Path,
    key: &VerifyingKey,
    signed_from: u64,
    mut f: impl FnMut(Outcome) -> Result<(), OpenError>,
) -> Result<(), OpenError> {
    let mut reader = BufReader::new(File::open(path).map_err(io(path))?);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let (jobs, queue) = mpsc::channel::<Job>();
    let queue = Mutex::new(queue);
    let queue = &queue;
    std::thread::scope(move |s| {
        for _ in 0..threads {
            s.spawn(move || {
                loop {
                    let next = queue.lock().ok().and_then(|q| q.recv().ok());
                    match next {
                        Some(job) => work(job, key, signed_from),
                        None => break,
                    }
                }
            });
        }
        let result = feed(&mut reader, path, &jobs, threads * 4, &mut f);
        // Workers leave once the queue is closed.
        drop(jobs);
        result
    })
}

/// Read lines, hand them to workers in jobs, and settle finished jobs in order.
fn feed(
    reader: &mut BufReader<File>,
    path: &Path,
    jobs: &mpsc::Sender<Job>,
    window: usize,
    f: &mut impl FnMut(Outcome) -> Result<(), OpenError>,
) -> Result<(), OpenError> {
    let mut pending: VecDeque<mpsc::Receiver<Reply>> = VecDeque::new();
    let mut settle = |pending: &mut VecDeque<mpsc::Receiver<Reply>>| -> Result<(), OpenError> {
        // Only called with jobs pending; an empty queue has nothing to settle.
        let Some(rx) = pending.pop_front() else {
            return Ok(());
        };
        match rx.recv() {
            Ok(done) => done.into_iter().try_for_each(|item| match item {
                Ok((r, c)) => f(Outcome::Line(r, c)),
                Err(line) => f(Outcome::Unreadable(line)),
            }),
            // A worker that died (it can only panic) sends nothing; its receipts count as unverified.
            Err(_) => f(Outcome::Lost),
        }
    };
    let mut submit = |lines: Vec<(usize, String)>,
                      pending: &mut VecDeque<mpsc::Receiver<Reply>>|
     -> Result<(), OpenError> {
        let (reply, rx) = mpsc::channel();
        pending.push_back(rx);
        // Workers only stop once `jobs` is dropped, so a send doesn't fail while we feed them.
        let _ = jobs.send(Job { lines, reply });
        while pending.len() > window {
            settle(pending)?;
        }
        Ok(())
    };
    let mut lines = Vec::with_capacity(JOB_LINES);
    let mut number = 0;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).map_err(io(path))? == 0 {
            break;
        }
        number += 1;
        if line.trim().is_empty() {
            continue;
        }
        lines.push((number, line));
        if lines.len() == JOB_LINES {
            submit(std::mem::take(&mut lines), &mut pending)?;
        }
    }
    if !lines.is_empty() {
        submit(lines, &mut pending)?;
    }
    while !pending.is_empty() {
        settle(&mut pending)?;
    }
    Ok(())
}

/// Call `f` on each receipt in a log file, oldest first, without holding the others in memory.
pub fn for_each_receipt(path: &Path, mut f: impl FnMut(Receipt)) -> Result<(), OpenError> {
    each_receipt(path, |r| {
        f(r);
        Ok(())
    })
}

/// Read every receipt in a log file into memory. Prefer [`for_each_receipt`] or [`verify_file`] for
/// anything that may be large. A line that doesn't parse is reported by number.
pub fn read_receipts(path: &Path) -> Result<Vec<Receipt>, OpenError> {
    let mut out = Vec::new();
    for_each_receipt(path, |r| out.push(r))?;
    Ok(out)
}

/// Which receipts get their signature checked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureChecks {
    /// Every receipt. The default, and what an auditor should use.
    Every,
    /// Only receipts after the furthest checkpoint, once every checkpoint's signature has verified.
    /// The receipts before it are still parsed, hashed and linked, and that checkpoint signs the
    /// hash they lead to, so changing one without the key still fails. What this can't catch is a
    /// receipt the key holder wrote with a bad signature before a checkpoint.
    AfterLastCheckpoint,
}

/// Verify the chain in a receipts file line by line. Memory use doesn't depend on the log's length.
pub fn verify_file(path: &Path, key: &VerifyingKey) -> Result<Stats, VerifyFileError> {
    verify_files(
        &[(None, path.to_path_buf())],
        Vec::new(),
        key,
        SignatureChecks::Every,
        None,
    )
    .map(|(s, _)| s)
}

/// Verify the chain in `receipts`, and every checkpoint in `checkpoints` (which may not exist yet)
/// against it, line by line. A broken chain is reported in preference to a checkpoint mismatch.
pub fn verify_log(
    receipts: &Path,
    checkpoints: &Path,
    key: &VerifyingKey,
) -> Result<Stats, VerifyFileError> {
    verify_log_with(receipts, checkpoints, &[], key, SignatureChecks::Every)
}

/// [`verify_log`], plus the checkpoints in each `external` file, kept somewhere the log's operator
/// can't rewrite, and choosing which receipts get their signature checked. A log cut short together
/// with its own checkpoints still fails against the external ones. Each external file must exist: one
/// that was named but can't be read is an error, never an empty list.
pub fn verify_log_with(
    receipts: &Path,
    checkpoints: &Path,
    external: &[&Path],
    key: &VerifyingKey,
    checks: SignatureChecks,
) -> Result<Stats, VerifyFileError> {
    let all = local_checkpoints(checkpoints, external)?;
    verify_files(&[(None, receipts.to_path_buf())], all, key, checks, None).map(|(s, _)| s)
}

/// Verify the whole log in `dir`, every segment and receipts.jsonl, against its checkpoints and those
/// in `external`. With `from`, verification starts at the signed checkpoint for that many receipts
/// and nothing before it is read; without it, it starts at the oldest segment still present, which
/// must be receipt 0 or a signed checkpoint.
pub fn verify_dir(
    dir: &Path,
    external: &[&Path],
    key: &VerifyingKey,
    checks: SignatureChecks,
    from: Option<u64>,
) -> Result<Stats, VerifyFileError> {
    let local = dir.join(CHECKPOINT_FILE);
    let all = local_checkpoints(&local, external)?;
    let files = log_files(dir)?;
    // Where an emptied, rotated log starts is the log's own business: published checkpoints only
    // confirm it.
    let from = from.max(archived_start(
        dir,
        &files,
        &local_checkpoints(&local, &[])?,
    )?);
    verify_files(&files, all, key, checks, from).map(|(s, _)| s)
}

/// Call `f` on each receipt of the log in `dir`, across every segment still present, oldest first.
/// Nothing is verified; use [`verify_dir`] for that.
pub fn for_each_log_receipt(dir: &Path, mut f: impl FnMut(Receipt)) -> Result<(), OpenError> {
    for (_, path) in log_files(dir)? {
        for_each_receipt(&path, &mut f)?;
    }
    Ok(())
}

fn local_checkpoints(local: &Path, external: &[&Path]) -> Result<Vec<Checkpoint>, OpenError> {
    let mut all = if local.exists() {
        read_checkpoints(local)?
    } else {
        Vec::new()
    };
    for path in external {
        all.extend(read_checkpoints(path)?);
    }
    Ok(all)
}

/// Append `checkpoint` to `path`, outside the log directory, and sync it to disk. Existing lines are
/// never rewritten.
pub fn publish_checkpoint(path: &Path, checkpoint: &Checkpoint) -> Result<(), OpenError> {
    let mut line = serde_json::to_vec(checkpoint).map_err(|e| Error::Canonical(e.to_string()))?;
    line.push(b'\n');
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(io(path))?;
    f.write_all(&line).map_err(io(path))?;
    f.sync_data().map_err(io(path))
}

/// Verify `files` as one chain, in order. A closed segment carries the seq its name says it starts
/// at; the last file may be receipts.jsonl, which carries none. Returns the stats and the seq at which
/// the last file started.
fn verify_files(
    files: &[(Option<u64>, PathBuf)],
    checkpoints: Vec<Checkpoint>,
    key: &VerifyingKey,
    checks: SignatureChecks,
    from: Option<u64>,
) -> Result<(Stats, u64), VerifyFileError> {
    // Every checkpoint's signature is checked here, before any of them is trusted.
    let mut watcher = CheckpointWatcher::new(&checkpoints, key).map_err(OpenError::Checkpoint)?;
    let signed_from = match checks {
        SignatureChecks::Every => 0,
        SignatureChecks::AfterLastCheckpoint => {
            checkpoints.iter().map(|c| c.count).max().unwrap_or(0)
        }
    };
    let oldest = files.first().and_then(|(s, _)| *s).unwrap_or(0);
    let start = from.unwrap_or(0).max(oldest);
    let mut chain = if start == 0 {
        ChainVerifier::new(key)
    } else {
        // Every checkpoint at `start` must agree on the head; the signatures were checked above.
        let mut at = checkpoints
            .iter()
            .enumerate()
            .filter(|(_, c)| c.count == start);
        let Some((_, anchor)) = at.next() else {
            return Err(OpenError::Segment(SegmentBreak::NoAnchor { count: start }));
        };
        // Two signed checkpoints for the same count with different heads mean the key signed two
        // histories; only the key holder can make that, so no test log here has one.
        if let Some((checkpoint, _)) = at.find(|(_, c)| c.head != anchor.head) {
            return Err(OpenError::Checkpoint(CheckpointBreak::HeadMismatch {
                checkpoint,
                seq: start - 1,
            }));
        }
        ChainVerifier::resume(key, start, anchor.head.clone())
    };
    watcher.skip_before(start);
    let closed_at = |count: u64| checkpoints.iter().any(|c| c.count == count);
    // Until the first receipt at or after `start` is accepted, older ones are passed over. After
    // that every line counts, so an old receipt copied in later still breaks the chain.
    let mut started = start == 0;
    let mut active_start = 0;
    for (i, (named, path)) in files.iter().enumerate() {
        // A closed segment wholly before the start isn't read.
        if files
            .get(i + 1)
            .and_then(|(next, _)| *next)
            .is_some_and(|next| next <= start)
        {
            continue;
        }
        active_start = chain.count();
        verify_lines(path, key, signed_from, |outcome| match outcome {
            Outcome::Line(r, checked) => {
                if !started && r.seq < start {
                    return Ok(());
                }
                started = true;
                let seq = chain.count();
                chain
                    .push_prechecked(&r, checked)
                    .map_err(OpenError::Chain)?;
                watcher.observe(seq, chain.head());
                Ok(())
            }
            Outcome::Unreadable(line) => Err(match named {
                Some(_) => OpenError::UnreadableSegment {
                    path: path.clone(),
                    line,
                },
                None => OpenError::Unreadable { line },
            }),
            Outcome::Lost => Err(OpenError::Chain(ChainBreak {
                index: chain.count() as usize,
                kind: BreakKind::BadSignature,
            })),
        })?;
        if named.is_some() {
            let count = chain.count();
            // The next segment must start where this one ended. receipts.jsonl has no name to
            // check, so a segment cut short before it shows up as an end with no checkpoint. The
            // first file read needs no check: verification starts inside it.
            if let Some((Some(next), next_path)) = files.get(i + 1)
                && *next != count
            {
                return Err(OpenError::Segment(SegmentBreak::Gap {
                    path: next_path.clone(),
                    expected: count,
                    found: *next,
                }));
            }
            if !closed_at(count) {
                return Err(OpenError::Segment(SegmentBreak::Unclosed {
                    path: path.clone(),
                    count,
                }));
            }
            started = true;
        }
    }
    let receipts = chain.count();
    watcher.finish(receipts).map_err(OpenError::Checkpoint)?;
    // With receipts.jsonl missing, the one recreated in its place starts after the last segment.
    if files.last().is_none_or(|(named, _)| named.is_some()) {
        active_start = receipts;
    }
    Ok((
        Stats {
            receipts,
            checkpoints: checkpoints.len(),
            head: chain.head().to_string(),
            first: start,
        },
        active_start,
    ))
}

#[cfg(test)]
mod stream_tests;

/// Read every checkpoint in a checkpoints file.
pub fn read_checkpoints(path: &Path) -> Result<Vec<Checkpoint>, OpenError> {
    let file = File::open(path).map_err(io(path))?;
    let mut out = Vec::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(io(path))?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(
            serde_json::from_str(&line).map_err(|_| OpenError::UnreadableCheckpoint {
                path: path.to_path_buf(),
                line: i + 1,
            })?,
        );
    }
    Ok(out)
}

#[cfg(unix)]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}

/// On Windows the file inherits the directory's ACL; the daemon's own user directory is the boundary.
#[cfg(not(unix))]
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    f.write_all(bytes)?;
    f.sync_all()
}
