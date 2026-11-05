mod actions;
mod aur;
mod cmdcheck;
mod jev;
mod llm;
mod logs;
mod news;
mod resolve;
mod rules;
mod sandbox;
mod setup;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use rules::{Finding, Severity};
use serde_json::{json, Map, Value};
use std::collections::HashSet;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

#[derive(Parser)]
#[command(name = "buzzard", version, about = "Review AUR packages (rules + Jev + sandbox) and install them")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Jev model (pin a version for reproducible thresholds)
    #[arg(long, global = true, default_value = "jev-latest")]
    model: String,
    /// Do not use Jev (rules only); installs then always ask for confirmation
    #[arg(long, global = true)]
    offline: bool,
    /// Skip the local LLM second opinion
    #[arg(long, global = true)]
    no_llm: bool,
}

static LLM: std::sync::OnceLock<Option<llm::Llm>> = std::sync::OnceLock::new();

#[derive(Subcommand)]
enum Cmd {
    /// Find, review, build in a sandbox and install ("buzzard install apple music")
    #[command(visible_alias = "i")]
    Install {
        /// Package name or description; separate several with commas
        #[arg(required = true)]
        query: Vec<String>,
        /// Install without asking, but only if every check is clean
        #[arg(long, short)]
        yes: bool,
    },
    /// Review only, do not build or install
    #[command(visible_alias = "c")]
    Check {
        #[arg(required = true)]
        query: Vec<String>,
    },
    /// Search the repos and the AUR
    #[command(visible_alias = "s")]
    Search {
        #[arg(required = true)]
        query: Vec<String>,
    },
    /// Full system upgrade: Arch news check, pacman -Syu, then reviewed AUR updates
    #[command(visible_alias = "u")]
    Upgrade {
        #[arg(long, short)]
        yes: bool,
        /// Only upgrade AUR packages (skip news and pacman -Syu)
        #[arg(long)]
        aur_only: bool,
    },
    /// Re-review all installed AUR packages (changes nothing)
    Audit,
    /// Check a shell command before running it ("buzzard run 'curl … | sh'")
    Run {
        /// Run without asking, but only if every check is clean
        #[arg(long, short)]
        yes: bool,
        /// Only check, do not run
        #[arg(long)]
        dry: bool,
        /// The command; quote it so your shell does not interpret it first
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Show new Arch Linux news and flag posts that need manual steps
    News,
    /// Do a task described in plain words, e.g. "buzzard do free up disk space"
    Do {
        #[arg(required = true, trailing_var_arg = true)]
        request: Vec<String>,
    },
    /// List the actions "buzzard do" can pick from
    Actions,
    /// Set up Buzzard: API key, GPU detection, Ollama and a fitting local model
    Setup {
        /// Accept the plan without asking
        #[arg(long, short)]
        yes: bool,
        /// Use the CPU even if a GPU is found
        #[arg(long)]
        cpu: bool,
        /// Only show what would be done
        #[arg(long)]
        dry: bool,
        /// Use this Ollama model instead of the automatic choice
        #[arg(long = "llm-model")]
        llm_model: Option<String>,
    },
    /// Sort recent log warnings into harmless / needs attention / security
    Logs {
        /// Time range, as understood by journalctl
        #[arg(long, default_value = "1 hour ago", allow_hyphen_values = true)]
        since: String,
        /// Also list harmless messages
        #[arg(long)]
        all: bool,
        /// Send a desktop notification if something needs a look
        #[arg(long)]
        notify: bool,
    },
    /// List custom commands from ~/.config/buzzard/commands
    Commands,
}

const BUILTIN: &[&str] = &[
    "install",
    "i",
    "check",
    "c",
    "search",
    "s",
    "upgrade",
    "u",
    "audit",
    "commands",
    "run",
    "news",
    "do",
    "actions",
    "logs",
    "setup",
    "help",
    "-h",
    "--help",
    "-V",
    "--version",
];

fn config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("/etc"))
        .join("buzzard")
}

fn commands_file() -> PathBuf {
    config_dir().join("commands")
}

/// Read `~/.config/buzzard/env` (`KEY=value` or `export KEY=value` per line).
/// Variables already set in the environment win. This lets Buzzard work from any
/// shell and from systemd timers without extra shell setup.
fn load_env_file() {
    let Ok(text) = std::fs::read_to_string(config_dir().join("env")) else { return };
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else { continue };
        let k = k.trim();
        let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
        if !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') && std::env::var_os(k).is_none() {
            std::env::set_var(k, v);
        }
    }
}

/// The local LLM, if enabled and reachable.
fn local_llm() -> Option<&'static llm::Llm> {
    let l = LLM.get()?.as_ref()?;
    if l.available() {
        Some(l)
    } else {
        println!(
            "(local LLM not reachable at {}; start it with: sudo systemctl start ollama, or pass --no-llm)",
            l.url
        );
        None
    }
}

/// One per line: `name = install apple music`  or  `name = !shell-command "$@"`
fn load_commands() -> Vec<(String, String)> {
    let Ok(text) = std::fs::read_to_string(commands_file()) else { return vec![] };
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| l.split_once('=').map(|(k, v)| (k.trim().to_string(), v.trim().to_string())))
        .filter(|(k, v)| !k.is_empty() && !v.is_empty())
        .collect()
}

/// Expand custom commands. Built-in commands cannot be overridden.
fn expand_args() -> Result<Vec<String>> {
    let args: Vec<String> = std::env::args().collect();
    let Some(first) = args.get(1) else { return Ok(args) };
    if BUILTIN.contains(&first.as_str()) || first.starts_with('-') {
        return Ok(args);
    }
    let Some((_, exp)) = load_commands().into_iter().find(|(k, _)| k == first) else { return Ok(args) };
    if let Some(sh) = exp.strip_prefix('!') {
        let st = Command::new("sh").arg("-c").arg(sh.trim()).arg("buzzard").args(&args[2..]).status()?;
        std::process::exit(st.code().unwrap_or(1));
    }
    let mut out = vec![args[0].clone()];
    out.extend(exp.split_whitespace().map(String::from));
    out.extend(args[2..].iter().cloned());
    Ok(out)
}

/// "apple music" -> one query; "firefox, apple music" -> two;
/// "htop btop" -> two, if every word is an exact package name.
fn queries(words: &[String]) -> Vec<String> {
    let joined = words.join(" ");
    if joined.contains(',') {
        return joined.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
    }
    if words.len() > 1 && words.iter().all(|w| matches!(resolve::exact(w), Ok(Some(_)))) {
        return words.to_vec();
    }
    vec![joined]
}

#[derive(PartialEq, Clone, Copy)]
enum Decision {
    Clean,    // nothing suspicious
    Confirm,  // human must type y
    TypeName, // human must type the package name
    Stop,     // hard stop
}

struct Report {
    files: Vec<(String, String)>,
    findings: Vec<Finding>,
    jev_lines: Vec<String>,
    decision: Decision,
    reasons: Vec<String>,
}

fn main() {
    if let Err(e) = run() {
        eprintln!("\x1b[31mError:\x1b[0m {e:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    load_env_file();
    let cli = Cli::parse_from(expand_args()?);
    let needs_jev = !matches!(cli.cmd, Cmd::Search { .. } | Cmd::Commands | Cmd::Actions | Cmd::Setup { .. });
    let jev = if cli.offline || !needs_jev { None } else { Some(jev::Jev::from_env(&cli.model)?) };
    let _ = LLM.set(if cli.no_llm { None } else { Some(llm::Llm::from_env()) });
    match cli.cmd {
        Cmd::Install { query, yes } => {
            sandbox::require_bwrap()?;
            let mut done = HashSet::new();
            for q in queries(&query) {
                match resolve::resolve(&q, jev.as_ref())? {
                    resolve::Target::Repo(n) => repo_install(&n)?,
                    resolve::Target::Aur(n) => install(&n, jev.as_ref(), yes, &mut done)?,
                }
            }
            Ok(())
        }
        Cmd::Check { query } => {
            let mut seen = HashSet::new();
            for q in queries(&query) {
                match resolve::resolve(&q, jev.as_ref())? {
                    resolve::Target::Repo(n) => {
                        println!("\n== {n} ==\nOfficial repo package, signed by Arch. No AUR review needed.")
                    }
                    resolve::Target::Aur(n) => {
                        let (_, mut rep) = analyze(&n, jev.as_ref(), &mut seen)?;
                        print_report(&n, &rep);
                        second_opinion(&n, &mut rep);
                    }
                }
            }
            Ok(())
        }
        Cmd::Search { query } => resolve::print_search(&query.join(" ")),
        Cmd::Upgrade { yes, aur_only } => {
            if !aur_only {
                system_upgrade(jev.as_ref())?;
            }
            aur_upgrade(jev.as_ref(), yes)
        }
        Cmd::Run { yes, dry, command } => cmdcheck::run(&command.join(" "), jev.as_ref(), yes, dry),
        Cmd::News => news::check(jev.as_ref()).map(|_| ()),
        Cmd::Do { request } => actions::run(&request.join(" "), jev.as_ref()),
        Cmd::Actions => {
            actions::list();
            Ok(())
        }
        Cmd::Setup { yes, cpu, dry, llm_model } => {
            setup::run(setup::Options { yes, cpu, no_llm: cli.no_llm, dry, model: llm_model })
        }
        Cmd::Logs { since, all, notify } => logs::run(jev.as_ref(), &since, all, notify),
        Cmd::Audit => audit(jev.as_ref()),
        Cmd::Commands => {
            let cmds = load_commands();
            println!("File: {}", commands_file().display());
            if cmds.is_empty() {
                println!("(no custom commands)");
            }
            for (k, v) in cmds {
                println!("  {k:<14} = {v}");
            }
            Ok(())
        }
    }
}

fn repo_install(name: &str) -> Result<()> {
    println!("{name}: official repo package (signed), installing with pacman.");
    let st = Command::new("sudo").args(["pacman", "-S", "--needed", "--", name]).status()?;
    if !st.success() {
        bail!("pacman -S {name} failed");
    }
    Ok(())
}

/// Locally installed packages not from the repos (usually AUR).
fn foreign() -> Result<Vec<(String, String)>> {
    let out = Command::new("pacman").arg("-Qm").output().context("pacman not found")?;
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_once(' ').map(|(n, v)| (n.to_string(), v.trim().to_string())))
        .collect())
}

fn aur_infos(names: &[String]) -> Result<Vec<aur::Info>> {
    let mut all = Vec::new();
    for chunk in names.chunks(100) {
        all.extend(aur::info(chunk)?);
    }
    Ok(all)
}

fn vercmp(a: &str, b: &str) -> i32 {
    Command::new("vercmp")
        .args([a, b])
        .output()
        .ok()
        .and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok())
        .unwrap_or(0)
}

fn system_upgrade(jev: Option<&jev::Jev>) -> Result<()> {
    match news::check(jev) {
        Ok(n) if n > 0 => {
            if ask("Read the news above first. Continue with the system upgrade? [y/N] ")?.to_lowercase() != "y" {
                bail!("cancelled");
            }
        }
        Ok(_) => {}
        Err(e) => eprintln!("warning: could not check the Arch news: {e:#}"),
    }
    let st = Command::new("sudo").args(["pacman", "-Syu"]).status()?;
    if !st.success() {
        bail!("pacman -Syu failed");
    }
    Ok(())
}

fn aur_upgrade(jev: Option<&jev::Jev>, yes: bool) -> Result<()> {
    sandbox::require_bwrap()?;
    let local = foreign()?;
    let infos = aur_infos(&local.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>())?;
    let todo: Vec<String> = local
        .iter()
        .filter(|(n, v)| infos.iter().any(|i| &i.name == n && vercmp(&i.version, v) > 0))
        .map(|(n, _)| n.clone())
        .collect();
    if todo.is_empty() {
        println!("All AUR packages are up to date.");
        return Ok(());
    }
    println!("Updates: {}", todo.join(" "));
    let mut done = HashSet::new();
    let mut failed = Vec::new();
    for n in &todo {
        if let Err(e) = install(n, jev, yes, &mut done) {
            eprintln!("\x1b[31m{n}:\x1b[0m {e:#}");
            failed.push(n.clone());
        }
    }
    if !failed.is_empty() {
        bail!("not upgraded: {}", failed.join(" "));
    }
    Ok(())
}

fn audit(jev: Option<&jev::Jev>) -> Result<()> {
    let local = foreign()?;
    let infos = aur_infos(&local.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>())?;
    let mut flagged = Vec::new();
    let mut seen = HashSet::new();
    for (n, _) in &local {
        if !infos.iter().any(|i| &i.name == n) {
            println!("\n== {n} ==\nno longer in the AUR, skipped");
            continue;
        }
        match analyze(n, jev, &mut seen) {
            Ok((_, rep)) => {
                print_report(n, &rep);
                if rep.decision.rank() >= Decision::TypeName.rank() {
                    flagged.push(n.clone());
                }
            }
            Err(e) => eprintln!("{n}: {e:#}"),
        }
    }
    println!("\nFlagged: {}", if flagged.is_empty() { "nothing".into() } else { flagged.join(" ") });
    Ok(())
}

// ---------------------------------------------------------------- Analysis

struct Prepared {
    pkgbase: String,
    repo: PathBuf,
    build: PathBuf,
    srcinfo: sandbox::SrcInfo,
}

fn analyze(name: &str, jev: Option<&jev::Jev>, seen: &mut HashSet<String>) -> Result<(Prepared, Report)> {
    seen.insert(name.to_string());
    let info =
        aur::info(&[name.to_string()])?.into_iter().next().with_context(|| format!("{name} not found in the AUR"))?;
    let (repo, reviewed) = aur::fetch(&info.package_base)?;
    let build = aur::cache_dir().join("build").join(&info.package_base);
    aur::export(&repo, &build)?;

    let files = aur::text_files(&build);
    if !files.iter().any(|(n, _)| n == "PKGBUILD") {
        bail!("no PKGBUILD in the repo");
    }

    // 1) Static rules, before anything is executed
    let mut findings: Vec<Finding> = Vec::new();
    for (n, t) in &files {
        findings.extend(rules::scan(n, t));
    }

    // 2) Generate our own .SRCINFO in the sandbox (the shipped one may differ)
    sandbox::require_bwrap()?;
    let srcinfo_text = sandbox::printsrcinfo(&build)?;
    let srcinfo = sandbox::parse_srcinfo(&srcinfo_text);
    findings.extend(rules::scan_sources(&srcinfo.sources, &srcinfo.checksums));

    // 3) Metadata
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs() as i64;
    let age_days = (now - info.first_submitted) / 86_400;
    if info.maintainer.is_none() {
        findings.push(Finding {
            severity: Severity::Warn,
            rule: "orphaned",
            detail: "package has no maintainer (takeover risk)".into(),
        });
    }
    if age_days < 14 {
        findings.push(Finding {
            severity: Severity::Warn,
            rule: "new-package",
            detail: format!("package is only {age_days} days old"),
        });
    }
    if info.num_votes == 0 {
        findings.push(Finding { severity: Severity::Info, rule: "no-votes", detail: "no votes".into() });
    }

    // 4) Jev
    let diff = aur::diff_since(&repo, &reviewed);
    let (jev_lines, mut decision, mut reasons, truncated) = match jev {
        Some(j) => judge(j, &info, &files, &diff, age_days)?,
        None => (vec![], Decision::Confirm, vec!["Jev is disabled (--offline)".to_string()], false),
    };
    if truncated {
        decision = decision.max(Decision::TypeName);
        reasons.push("state was too large and got truncated".into());
    }
    if findings.iter().any(|f| f.severity == Severity::Critical) {
        decision = decision.max(Decision::TypeName);
        reasons.push("critical rule matches".into());
    }
    if findings.iter().any(|f| f.severity == Severity::Warn) {
        decision = decision.max(Decision::Confirm);
        reasons.push("rule warnings".into());
    }
    if reviewed.is_none() {
        decision = decision.max(Decision::Confirm);
        reasons.push("first install: never reviewed before".into());
    }
    reasons.dedup();

    Ok((
        Prepared { pkgbase: info.package_base.clone(), repo, build, srcinfo },
        Report { files, findings, jev_lines, decision, reasons },
    ))
}

impl Decision {
    fn rank(self) -> u8 {
        match self {
            Decision::Clean => 0,
            Decision::Confirm => 1,
            Decision::TypeName => 2,
            Decision::Stop => 3,
        }
    }
    fn max(self, o: Decision) -> Decision {
        if o.rank() > self.rank() {
            o
        } else {
            self
        }
    }
}

fn cut(s: &str, n: usize) -> (String, bool) {
    if s.chars().count() <= n {
        (s.to_string(), false)
    } else {
        (s.chars().take(n).collect::<String>() + "\n[… truncated …]", true)
    }
}

fn judge(
    j: &jev::Jev,
    info: &aur::Info,
    files: &[(String, String)],
    diff: &str,
    age_days: i64,
) -> Result<(Vec<String>, Decision, Vec<String>, bool)> {
    // Budget: diff first, then PKGBUILD, *.install, the rest
    let mut budget = jev::MAX_STATE_CHARS.saturating_sub(4_000);
    let mut truncated = false;
    let (d, t) = cut(diff, budget.min(15_000));
    truncated |= t;
    budget = budget.saturating_sub(d.chars().count());

    let mut ordered: Vec<&(String, String)> = files.iter().collect();
    ordered.sort_by_key(|(n, _)| {
        if n == "PKGBUILD" {
            0
        } else if n.ends_with(".install") {
            1
        } else {
            2
        }
    });
    let mut fmap = Map::new();
    for (n, text) in ordered {
        let (c, t) = cut(text, budget);
        truncated |= t;
        budget = budget.saturating_sub(c.chars().count());
        fmap.insert(n.clone(), Value::String(c));
    }

    let state = json!({
        "package": info.name,
        "version": info.version,
        "aur_metadata": {
            "maintainer": info.maintainer,
            "votes": info.num_votes,
            "popularity": info.popularity,
            "age_days": age_days,
            "flagged_out_of_date": info.out_of_date.is_some(),
        },
        "files": fmap,
        "diff_since_last_reviewed_version": d,
    });

    let reply = j.evaluate(&state, &jev::questions())?;
    let mut lines = Vec::new();
    let mut decision = Decision::Clean;
    let mut reasons = Vec::new();

    for (qid, ans) in &reply.answers {
        match ans {
            jev::Answer::Choice { choice, probabilities, confidence } if qid == "verdict" => {
                let pm = probabilities.get("malicious").copied().unwrap_or(0.0);
                lines.push(format!("verdict: {choice} (confidence {confidence:.2}, P(malicious)={pm:.2})"));
                if pm >= 0.5 || choice == "malicious" {
                    decision = decision.max(Decision::Stop);
                    reasons.push("Jev rates the package as malicious".into());
                } else if choice != "safe" {
                    decision = decision.max(Decision::TypeName);
                    reasons.push("Jev recommends manual review".into());
                } else if *confidence < 0.6 {
                    decision = decision.max(Decision::TypeName);
                    reasons.push(format!("Jev is unsure (confidence {confidence:.2})"));
                }
            }
            jev::Answer::Noul { noul } => {
                lines.push(format!("{qid}: {noul:.2}"));
                if *noul >= 0.5 {
                    decision = decision.max(Decision::TypeName);
                    reasons.push(format!("Jev: {qid} likely ({noul:.2})"));
                } else if *noul >= 0.2 {
                    decision = decision.max(Decision::Confirm);
                    reasons.push(format!("Jev: {qid} not ruled out ({noul:.2})"));
                }
            }
            _ => {}
        }
    }
    lines.sort();
    if !reply.answers.contains_key("verdict") {
        decision = decision.max(Decision::TypeName);
        reasons.push("Jev returned no verdict".into());
    }
    Ok((lines, decision, reasons, truncated))
}

fn decision_label(d: Decision) -> &'static str {
    match d {
        Decision::Clean => "\x1b[32mclean\x1b[0m",
        Decision::Confirm => "\x1b[33mconfirmation needed\x1b[0m",
        Decision::TypeName => "\x1b[31mcareful review needed\x1b[0m",
        Decision::Stop => "\x1b[31mBLOCKED\x1b[0m",
    }
}

/// Ask the local LLM to explain flagged packages. It may raise the decision, never lower it.
fn second_opinion(name: &str, rep: &mut Report) {
    if LLM.get().and_then(|o| o.as_ref()).is_none() {
        return;
    }
    let mut flags: Vec<String> = rep
        .findings
        .iter()
        .filter(|f| f.severity >= Severity::Warn)
        .map(|f| format!("rule {}: {}", f.rule, f.detail))
        .collect();
    flags.extend(rep.reasons.iter().filter(|r| r.starts_with("Jev")).cloned());
    if flags.is_empty() {
        return;
    }
    let Some(l) = local_llm() else { return };
    // Only what matters: PKGBUILD, install scripts, and files a rule pointed at.
    let mut files: Vec<(String, String)> = rep
        .files
        .iter()
        .filter(|(n, _)| {
            n == "PKGBUILD"
                || n.ends_with(".install")
                || rep.findings.iter().any(|f| f.detail.starts_with(&format!("{n}:")) || f.detail.ends_with(n.as_str()))
        })
        .cloned()
        .collect();
    files.sort_by_key(|(n, _)| {
        if n == "PKGBUILD" {
            0
        } else if n.ends_with(".install") {
            1
        } else {
            2
        }
    });

    println!("\n-- local LLM review ({}, advisory) --", l.model);
    let before = rep.decision;
    match l.review(name, &flags, &files) {
        Ok(llm::Verdict::Malicious) => {
            rep.decision = rep.decision.max(Decision::TypeName);
            rep.reasons.push("local LLM rates it malicious".into());
        }
        Ok(llm::Verdict::Suspicious) => {
            rep.decision = rep.decision.max(Decision::Confirm);
            rep.reasons.push("local LLM rates it suspicious".into());
        }
        Ok(llm::Verdict::Benign) => {
            println!("(LLM thinks the flags are harmless. It only explains; the result stays as it is.)")
        }
        Ok(llm::Verdict::Unknown) => println!("(LLM gave no clear verdict)"),
        Err(e) => eprintln!("local LLM failed: {e:#}"),
    }
    if rep.decision != before {
        println!("Result after LLM review: {}", decision_label(rep.decision));
    }
}

fn print_report(name: &str, r: &Report) {
    println!("\n== {name} ==");
    if r.findings.is_empty() {
        println!("Rules: no matches");
    } else {
        for f in &r.findings {
            let tag = match f.severity {
                Severity::Critical => "\x1b[31mCRITICAL\x1b[0m",
                Severity::Warn => "\x1b[33mWARNING \x1b[0m",
                Severity::Info => "INFO    ",
            };
            println!("  {tag} [{}] {}", f.rule, f.detail);
        }
    }
    for l in &r.jev_lines {
        println!("  jev  {l}");
    }
    let d = match r.decision {
        Decision::Clean => "\x1b[32mclean\x1b[0m",
        Decision::Confirm => "\x1b[33mconfirmation needed\x1b[0m",
        Decision::TypeName => "\x1b[31mcareful review needed\x1b[0m",
        Decision::Stop => "\x1b[31mBLOCKED\x1b[0m",
    };
    println!("Result: {d}");
    for x in &r.reasons {
        println!("  - {x}");
    }
}

// ---------------------------------------------------------------- Install

fn ask(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

fn show_diff_hint(p: &Prepared) {
    println!("Read the PKGBUILD: less {}/PKGBUILD", p.repo.display());
}

fn install(name: &str, jev: Option<&jev::Jev>, yes: bool, done: &mut HashSet<String>) -> Result<()> {
    if !done.insert(name.to_string()) {
        return Ok(());
    }
    let mut seen = HashSet::new();
    let (p, mut rep) = analyze(name, jev, &mut seen)?;
    print_report(name, &rep);
    second_opinion(name, &mut rep);
    show_diff_hint(&p);

    match rep.decision {
        Decision::Stop => bail!(
            "{name}: install blocked. If this is a false alarm, review the PKGBUILD yourself and build it manually."
        ),
        Decision::TypeName => {
            let a = ask(&format!("Continue anyway? Type '{name}' to confirm: "))?;
            if a != name {
                bail!("cancelled");
            }
        }
        Decision::Confirm => {
            if ask("Continue? [y/N] ")?.to_lowercase() != "y" {
                bail!("cancelled");
            }
        }
        Decision::Clean => {
            if !yes && ask("All clean. Install? [y/N] ")?.to_lowercase() != "y" {
                bail!("cancelled");
            }
        }
    }

    // Dependencies: repo packages via pacman, AUR packages recursively through the same review
    let deps: Vec<String> =
        p.srcinfo.depends.iter().chain(&p.srcinfo.makedepends).map(|d| sandbox::dep_name(d)).collect();
    let missing = unsatisfied(&deps)?;
    let mut repo_deps = Vec::new();
    let mut aur_deps = Vec::new();
    for d in missing {
        if Command::new("pacman").args(["-Si", &d]).output().map(|o| o.status.success()).unwrap_or(false) {
            repo_deps.push(d);
        } else {
            aur_deps.push(d);
        }
    }
    for d in &aur_deps {
        println!("\nAUR dependency of {name}: {d}");
        install(d, jev, yes, done)?;
    }
    if !repo_deps.is_empty() {
        println!("Installing repo dependencies: {}", repo_deps.join(" "));
        let st = Command::new("sudo").args(["pacman", "-S", "--needed", "--asdeps"]).args(&repo_deps).status()?;
        if !st.success() {
            bail!("could not install dependencies");
        }
    }

    sandbox::download_sources(&p.build)?;
    sandbox::build(&p.build)?;

    let mut pkgs: Vec<PathBuf> = std::fs::read_dir(&p.build)?
        .flatten()
        .map(|e| e.path())
        .filter(|f| {
            let n = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            n.contains(".pkg.tar") && !n.ends_with(".sig") && !n.contains("-debug-")
        })
        .collect();
    pkgs.sort();
    if pkgs.is_empty() {
        bail!("no built package found");
    }
    let st = Command::new("sudo").args(["pacman", "-U"]).args(&pkgs).status()?;
    if !st.success() {
        bail!("pacman -U failed");
    }
    aur::mark_reviewed(&p.repo)?;
    println!("\x1b[32m{name} installed.\x1b[0m ({})", p.pkgbase);
    Ok(())
}

/// `pacman -T` prints the unsatisfied dependencies.
fn unsatisfied(deps: &[String]) -> Result<Vec<String>> {
    if deps.is_empty() {
        return Ok(vec![]);
    }
    let out = Command::new("pacman").arg("-T").args(deps).output().context("pacman not found")?;
    Ok(String::from_utf8_lossy(&out.stdout).lines().map(sandbox::dep_name).filter(|l| !l.is_empty()).collect())
}
