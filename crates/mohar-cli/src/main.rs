//! `mohar`: create, append to, read and verify a receipt log.

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use mohar_core::checkpoint::verify_checkpoints;
use mohar_core::store::{FileLog, read_checkpoints, read_receipts};
use mohar_core::{Action, Decision, Entry, parse_public_key, verify};

#[derive(Parser)]
#[command(
    name = "mohar",
    version,
    about = "Signed, hash-chained receipts for AI agent decisions"
)]
struct Cli {
    /// Log directory.
    #[arg(long, global = true, default_value = ".mohar")]
    dir: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create a new log with a fresh signing key.
    Init,
    /// Record a decision.
    Append {
        /// Agent identifier.
        #[arg(long)]
        agent: String,
        /// Capability, such as fs.edit.docs.
        #[arg(long)]
        capability: String,
        /// Host tool name.
        #[arg(long)]
        tool: String,
        /// Path, branch or host acted on.
        #[arg(long)]
        target: String,
        /// SHA-256 of the exact arguments.
        #[arg(long)]
        args_sha256: String,
        /// allow, escalate or deny.
        #[arg(long)]
        result: String,
        /// Trust level at decision time.
        #[arg(long, default_value_t = 0)]
        level: u8,
        /// gate, score, human or predicted.
        #[arg(long, default_value = "human")]
        by: String,
    },
    /// Print receipts, oldest first.
    Log {
        /// Only the last N receipts.
        #[arg(long)]
        last: Option<usize>,
    },
    /// Sign a checkpoint for the log as it stands.
    Checkpoint,
    /// Check the whole chain and every checkpoint against the log's public key. Exits 1 on the first break.
    Verify {
        /// Public key file to check against instead of the one in the log directory.
        #[arg(long)]
        public_key: Option<PathBuf>,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("mohar: {msg}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Command::Init => {
            FileLog::init(&cli.dir).map_err(|e| e.to_string())?;
            println!("created {}", cli.dir.display());
        }
        Command::Append {
            agent,
            capability,
            tool,
            target,
            args_sha256,
            result,
            level,
            by,
        } => {
            let mut log = FileLog::open(&cli.dir).map_err(|e| e.to_string())?;
            let r = log
                .append(Entry {
                    ts: now_rfc3339(),
                    agent_id: agent,
                    action: Action {
                        capability,
                        tool,
                        target,
                        args_sha256,
                    },
                    decision: Decision { result, level, by },
                })
                .map_err(|e| e.to_string())?;
            println!("{}", r.seq);
        }
        Command::Checkpoint => {
            let mut log = FileLog::open(&cli.dir).map_err(|e| e.to_string())?;
            let c = log.checkpoint(&now_rfc3339()).map_err(|e| e.to_string())?;
            println!("checkpoint at {} receipts", c.count);
        }
        Command::Log { last } => {
            let receipts =
                read_receipts(&cli.dir.join("receipts.jsonl")).map_err(|e| e.to_string())?;
            let skip = last.map_or(0, |n| receipts.len().saturating_sub(n));
            for r in &receipts[skip..] {
                println!(
                    "{:>6}  {}  {:<8} {:<20} {}  level {} by {}",
                    r.seq,
                    r.ts,
                    r.decision.result,
                    r.action.capability,
                    r.action.target,
                    r.decision.level,
                    r.decision.by
                );
            }
        }
        Command::Verify { public_key } => {
            let key_path = public_key.unwrap_or_else(|| cli.dir.join("public.key"));
            let text = std::fs::read_to_string(&key_path)
                .map_err(|e| format!("{}: {e}", key_path.display()))?;
            let key = parse_public_key(&text)
                .ok_or_else(|| format!("{} is not an ed25519 public key", key_path.display()))?;
            let receipts = match read_receipts(&cli.dir.join("receipts.jsonl")) {
                Ok(r) => r,
                Err(e) => {
                    println!("broken: {e}");
                    return Ok(ExitCode::from(1));
                }
            };
            if let Err(b) = verify(&receipts, &key) {
                println!("broken: receipt {}: {:?}", b.index, b.kind);
                return Ok(ExitCode::from(1));
            }
            let ckpt_path = cli.dir.join("checkpoints.jsonl");
            let checkpoints = if ckpt_path.exists() {
                match read_checkpoints(&ckpt_path) {
                    Ok(c) => c,
                    Err(e) => {
                        println!("broken: {e}");
                        return Ok(ExitCode::from(1));
                    }
                }
            } else {
                Vec::new()
            };
            if let Err(b) = verify_checkpoints(&checkpoints, &receipts, &key) {
                println!("broken: {b}");
                return Ok(ExitCode::from(1));
            }
            println!(
                "ok: {} receipts and {} checkpoints verified",
                receipts.len(),
                checkpoints.len()
            );
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// UTC now as RFC 3339 with milliseconds, without a date-time dependency.
fn now_rfc3339() -> String {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    // Civil date from days since 1970-01-01, after Howard Hinnant's days_from_civil inverse.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3_600,
        (rem % 3_600) / 60,
        rem % 60,
        d.subsec_millis()
    )
}
