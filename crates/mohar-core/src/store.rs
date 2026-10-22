//! The receipt log on disk: one directory per log.
//!
//! ```text
//! key.ed25519     32-byte signing seed, owner-only on Unix. Belongs to the daemon's OS user.
//! public.key      ed25519:<hex>, for anyone verifying the log.
//! receipts.jsonl  one receipt per line, oldest first, appended and synced before append returns.
//! writer.lock     held exclusively by the one process allowed to append; readers don't need it.
//! ```
//!
//! Opening a log verifies the whole chain first, one line at a time, so memory use doesn't grow with the
//! log. A log that doesn't verify is never extended.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::Prechecked;
use crate::checkpoint::{self, Checkpoint, CheckpointBreak, CheckpointWatcher};
use crate::{
    ChainBreak, ChainVerifier, Entry, Error, Receipt, SigningKey, VerifyingKey, public_key_string,
    receipt_hash, seal,
};

const KEY_FILE: &str = "key.ed25519";
const PUBLIC_FILE: &str = "public.key";
const LOG_FILE: &str = "receipts.jsonl";
const CHECKPOINT_FILE: &str = "checkpoints.jsonl";
const LOCK_FILE: &str = "writer.lock";

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
    /// The key file isn't a 32-byte seed.
    #[error("{0} is not a 32-byte signing key")]
    BadKey(PathBuf),
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
    /// A line of checkpoints.jsonl isn't a complete checkpoint.
    #[error("checkpoints.jsonl line {line} is not a complete checkpoint")]
    UnreadableCheckpoint {
        /// 1-based line number.
        line: usize,
    },
    /// A receipt couldn't be built or signed.
    #[error(transparent)]
    Receipt(#[from] Error),
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
    path: PathBuf,
    checkpoint_path: PathBuf,
    last_hash: String,
    len: u64,
}

impl FileLog {
    /// Create a new log in `dir` with a fresh signing key. Refuses to touch an existing log.
    pub fn init(dir: &Path) -> Result<Self, OpenError> {
        if dir.join(KEY_FILE).exists() || dir.join(LOG_FILE).exists() {
            return Err(OpenError::AlreadyExists(dir.to_path_buf()));
        }
        fs::create_dir_all(dir).map_err(io(dir))?;
        let key = SigningKey::generate()?;

        let key_path = dir.join(KEY_FILE);
        write_private(&key_path, &key.seed()).map_err(io(&key_path))?;
        let pub_path = dir.join(PUBLIC_FILE);
        fs::write(&pub_path, public_key_string(&key.verifying_key()) + "\n")
            .map_err(io(&pub_path))?;
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
        let stats = verify_log(&path, &checkpoint_path, &key.verifying_key())?;
        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(io(&path))?;
        Ok(Self {
            _lock: lock,
            key,
            file,
            path,
            checkpoint_path,
            last_hash: stats.head,
            len: stats.receipts,
        })
    }

    /// Sign `entry`, write it, and sync it to disk before returning the receipt.
    pub fn append(&mut self, entry: Entry) -> Result<Receipt, OpenError> {
        let r = seal(&self.key, self.len, self.last_hash.clone(), entry)?;
        let mut line = serde_json::to_vec(&r).map_err(|e| Error::Canonical(e.to_string()))?;
        line.push(b'\n');
        self.file.write_all(&line).map_err(io(&self.path))?;
        self.file.sync_data().map_err(io(&self.path))?;
        self.last_hash = receipt_hash(&r)?;
        self.len += 1;
        if self.len.is_multiple_of(CHECKPOINT_EVERY) {
            self.checkpoint(&r.ts)?;
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

/// Work out the position-independent part of each receipt, spread over the available cores.
fn precheck(batch: &[Receipt], key: &VerifyingKey) -> Vec<Prechecked> {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    if threads == 1 || batch.len() < 64 {
        return batch.iter().map(|r| Prechecked::of(r, key)).collect();
    }
    std::thread::scope(|s| {
        let workers: Vec<_> = batch
            .chunks(batch.len().div_ceil(threads))
            .map(|chunk| {
                let work = s.spawn(move || {
                    chunk
                        .iter()
                        .map(|r| Prechecked::of(r, key))
                        .collect::<Vec<_>>()
                });
                (chunk.len(), work)
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|(len, work)| {
                // A worker that died leaves its receipts unchecked, which fails them.
                work.join()
                    .unwrap_or_else(|_| (0..len).map(|_| Prechecked::failed()).collect())
            })
            .collect()
    })
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

/// Verify the chain in a receipts file line by line. Memory use doesn't depend on the log's length.
pub fn verify_file(path: &Path, key: &VerifyingKey) -> Result<Stats, VerifyFileError> {
    verify_stream(path, None, key)
}

/// Verify the chain in `receipts`, and every checkpoint in `checkpoints` (which may not exist yet)
/// against it, line by line. A broken chain is reported in preference to a checkpoint mismatch.
pub fn verify_log(
    receipts: &Path,
    checkpoints: &Path,
    key: &VerifyingKey,
) -> Result<Stats, VerifyFileError> {
    verify_stream(receipts, Some(checkpoints), key)
}

fn verify_stream(
    path: &Path,
    checkpoint_path: Option<&Path>,
    key: &VerifyingKey,
) -> Result<Stats, VerifyFileError> {
    let checkpoints = match checkpoint_path {
        Some(p) if p.exists() => read_checkpoints(p)?,
        _ => Vec::new(),
    };
    let mut watcher = CheckpointWatcher::new(&checkpoints, key).map_err(OpenError::Checkpoint)?;
    let mut chain = ChainVerifier::new(key);
    each_batch(path, |batch| {
        let checked = precheck(batch, key);
        for (r, c) in batch.iter().zip(checked) {
            let seq = chain.count();
            chain.push_prechecked(r, c).map_err(OpenError::Chain)?;
            watcher.observe(seq, chain.head());
        }
        Ok(())
    })?;
    let receipts = chain.count();
    watcher.finish(receipts).map_err(OpenError::Checkpoint)?;
    Ok(Stats {
        receipts,
        checkpoints: checkpoints.len(),
        head: chain.head().to_string(),
    })
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
            serde_json::from_str(&line)
                .map_err(|_| OpenError::UnreadableCheckpoint { line: i + 1 })?,
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
