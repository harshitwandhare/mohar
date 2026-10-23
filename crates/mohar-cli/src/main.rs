//! `mohar`: create, append to, read and verify a receipt log, serve decisions to agent hosts, and run
//! as a host's hook.

mod daemon;
mod hook;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand, ValueEnum};
use mohar_core::store::{FileLog, OpenError, for_each_receipt, verify_log};
use mohar_core::{Action, Decision, Entry, Receipt, parse_public_key};

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
    /// Serve decisions and outcomes to agent hosts on this machine.
    Daemon {
        /// Loopback address to listen on.
        #[arg(long, default_value = "127.0.0.1:7878")]
        addr: std::net::SocketAddr,
        /// Requests handled at once; past this the daemon answers 503.
        #[arg(long, default_value_t = 64)]
        max_inflight: usize,
        /// Exit when stdin closes, for a parent process that starts and stops the daemon.
        #[arg(long)]
        exit_on_stdin_eof: bool,
    },
    /// Run as an agent host's hook: read its payload on stdin, ask the daemon, print the answer.
    Hook {
        /// The host calling this hook.
        host: Host,
        /// The daemon to ask.
        #[arg(long, default_value = "http://127.0.0.1:7878")]
        daemon: String,
    },
    /// Check the whole chain and every checkpoint against the log's public key. Exits 1 on the first break.
    Verify {
        /// Public key file to check against instead of the one in the log directory.
        #[arg(long)]
        public_key: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Host {
    /// Claude Code PreToolUse and PostToolUse hooks.
    ClaudeCode,
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
                    verification: None,
                })
                .map_err(|e| e.to_string())?;
            println!("{}", r.seq);
        }
        Command::Daemon {
            addr,
            max_inflight,
            exit_on_stdin_eof,
        } => {
            daemon::serve(
                &cli.dir,
                daemon::Config {
                    addr,
                    max_inflight,
                    io_timeout: std::time::Duration::from_secs(5),
                    exit_on_stdin_eof,
                },
            )?;
        }
        Command::Hook {
            host: Host::ClaudeCode,
            daemon,
        } => {
            print!("{}", hook::claude_code(&daemon, &mut std::io::stdin()));
        }
        Command::Checkpoint => {
            let mut log = FileLog::open(&cli.dir).map_err(|e| e.to_string())?;
            let c = log.checkpoint(&now_rfc3339()).map_err(|e| e.to_string())?;
            println!("checkpoint at {} receipts", c.count);
        }
        Command::Log { last } => {
            let print = |r: &Receipt| {
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
            };
            let path = cli.dir.join("receipts.jsonl");
            match last {
                None => for_each_receipt(&path, |r| print(&r)),
                Some(n) => {
                    // Only the last `n` receipts are ever held.
                    let mut tail = VecDeque::new();
                    for_each_receipt(&path, |r| {
                        if n == 0 {
                            return;
                        }
                        if tail.len() == n {
                            tail.pop_front();
                        }
                        tail.push_back(r);
                    })
                    .map(|()| tail.iter().for_each(print))
                }
            }
            .map_err(|e| e.to_string())?;
        }
        Command::Verify { public_key } => {
            let key_path = public_key.unwrap_or_else(|| cli.dir.join("public.key"));
            let text = std::fs::read_to_string(&key_path)
                .map_err(|e| format!("{}: {e}", key_path.display()))?;
            let key = parse_public_key(&text)
                .ok_or_else(|| format!("{} is not an ed25519 public key", key_path.display()))?;
            match verify_log(
                &cli.dir.join("receipts.jsonl"),
                &cli.dir.join("checkpoints.jsonl"),
                &key,
            ) {
                Ok(stats) => println!(
                    "ok: {} receipts and {} checkpoints verified",
                    stats.receipts, stats.checkpoints
                ),
                Err(OpenError::Chain(b)) => {
                    println!("broken: receipt {}: {:?}", b.index, b.kind);
                    return Ok(ExitCode::from(1));
                }
                Err(OpenError::Checkpoint(b)) => {
                    println!("broken: {b}");
                    return Ok(ExitCode::from(1));
                }
                Err(e) => {
                    println!("broken: {e}");
                    return Ok(ExitCode::from(1));
                }
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// UTC now as RFC 3339 with milliseconds, without a date-time dependency.
pub(crate) fn now_rfc3339() -> String {
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
