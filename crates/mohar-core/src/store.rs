//! The receipt log on disk: one directory per log.
//!
//! ```text
//! key.ed25519     32-byte signing seed, owner-only on Unix. Belongs to the daemon's OS user.
//! public.key      ed25519:<hex>, for anyone verifying the log.
//! receipts.jsonl  one receipt per line, oldest first, appended and synced before append returns.
//! ```
//!
//! Opening a log verifies the whole chain first. A log that doesn't verify is never extended.

use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::checkpoint::{self, Checkpoint, CheckpointBreak, verify_checkpoints};
use crate::{
    ChainBreak, Entry, Error, Receipt, SigningKey, genesis, public_key_string, receipt_hash, seal,
    verify,
};

const KEY_FILE: &str = "key.ed25519";
const PUBLIC_FILE: &str = "public.key";
const LOG_FILE: &str = "receipts.jsonl";
const CHECKPOINT_FILE: &str = "checkpoints.jsonl";

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
        let key_path = dir.join(KEY_FILE);
        let seed = fs::read(&key_path).map_err(io(&key_path))?;
        let seed: [u8; 32] = seed
            .try_into()
            .map_err(|_| OpenError::BadKey(key_path.clone()))?;
        let key = SigningKey::from_seed(&seed);

        let path = dir.join(LOG_FILE);
        let receipts = read_receipts(&path)?;
        verify(&receipts, &key.verifying_key()).map_err(OpenError::Chain)?;
        let checkpoint_path = dir.join(CHECKPOINT_FILE);
        let checkpoints = if checkpoint_path.exists() {
            read_checkpoints(&checkpoint_path)?
        } else {
            Vec::new()
        };
        verify_checkpoints(&checkpoints, &receipts, &key.verifying_key())
            .map_err(OpenError::Checkpoint)?;
        let last_hash = match receipts.last() {
            Some(r) => receipt_hash(r)?,
            None => genesis(),
        };
        let file = OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(io(&path))?;
        Ok(Self {
            key,
            file,
            path,
            checkpoint_path,
            last_hash,
            len: receipts.len() as u64,
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

/// Read every receipt in a log file. A line that doesn't parse is reported by number.
pub fn read_receipts(path: &Path) -> Result<Vec<Receipt>, OpenError> {
    let file = File::open(path).map_err(io(path))?;
    let mut out = Vec::new();
    for (i, line) in BufReader::new(file).lines().enumerate() {
        let line = line.map_err(io(path))?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line).map_err(|_| OpenError::Unreadable { line: i + 1 })?);
    }
    Ok(out)
}

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
