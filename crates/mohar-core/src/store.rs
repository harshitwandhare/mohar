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

use std::collections::VecDeque;
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, mpsc};

use crate::Prechecked;
use crate::checkpoint::{self, Checkpoint, CheckpointBreak, CheckpointWatcher};
use crate::{
    BreakKind, ChainBreak, ChainVerifier, Entry, Error, Receipt, SigningKey, VerifyingKey,
    public_key_string, receipt_hash, seal,
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
    /// A line of a checkpoints file isn't a complete checkpoint.
    #[error("{} line {line} is not a complete checkpoint", path.display())]
    UnreadableCheckpoint {
        /// The checkpoints file.
        path: PathBuf,
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

fn work(job: Job, key: &VerifyingKey) {
    let done = job
        .lines
        .into_iter()
        .map(
            |(number, line)| match serde_json::from_str::<Receipt>(&line) {
                Ok(r) => {
                    let checked = Prechecked::of(&r, key);
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
                        Some(job) => work(job, key),
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
        let Some(rx) = pending.pop_front() else {
            return Ok(());
        };
        match rx.recv() {
            Ok(done) => done.into_iter().try_for_each(|item| match item {
                Ok((r, c)) => f(Outcome::Line(r, c)),
                Err(line) => f(Outcome::Unreadable(line)),
            }),
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

/// Verify the chain in a receipts file line by line. Memory use doesn't depend on the log's length.
pub fn verify_file(path: &Path, key: &VerifyingKey) -> Result<Stats, VerifyFileError> {
    verify_stream(path, Vec::new(), key)
}

/// Verify the chain in `receipts`, and every checkpoint in `checkpoints` (which may not exist yet)
/// against it, line by line. A broken chain is reported in preference to a checkpoint mismatch.
pub fn verify_log(
    receipts: &Path,
    checkpoints: &Path,
    key: &VerifyingKey,
) -> Result<Stats, VerifyFileError> {
    verify_log_against(receipts, checkpoints, &[], key)
}

/// [`verify_log`], plus the checkpoints in each `external` file, kept somewhere the log's operator
/// can't rewrite. A log cut short together with its own checkpoints still fails against them. Each
/// external file must exist: one that was named but can't be read is an error, never an empty list.
pub fn verify_log_against(
    receipts: &Path,
    checkpoints: &Path,
    external: &[&Path],
    key: &VerifyingKey,
) -> Result<Stats, VerifyFileError> {
    let mut all = if checkpoints.exists() {
        read_checkpoints(checkpoints)?
    } else {
        Vec::new()
    };
    for path in external {
        all.extend(read_checkpoints(path)?);
    }
    verify_stream(receipts, all, key)
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

fn verify_stream(
    path: &Path,
    checkpoints: Vec<Checkpoint>,
    key: &VerifyingKey,
) -> Result<Stats, VerifyFileError> {
    let mut watcher = CheckpointWatcher::new(&checkpoints, key).map_err(OpenError::Checkpoint)?;
    let mut chain = ChainVerifier::new(key);
    verify_lines(path, key, |outcome| match outcome {
        Outcome::Line(r, checked) => {
            let seq = chain.count();
            chain
                .push_prechecked(&r, checked)
                .map_err(OpenError::Chain)?;
            watcher.observe(seq, chain.head());
            Ok(())
        }
        Outcome::Unreadable(line) => Err(OpenError::Unreadable { line }),
        Outcome::Lost => Err(OpenError::Chain(ChainBreak {
            index: chain.count() as usize,
            kind: BreakKind::BadSignature,
        })),
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
