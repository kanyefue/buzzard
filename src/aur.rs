//! AUR access: metadata via RPC, sources via git.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "PascalCase")]
pub struct Info {
    pub name: String,
    pub package_base: String,
    pub version: String,
    pub maintainer: Option<String>,
    pub num_votes: u32,
    pub popularity: f64,
    pub first_submitted: i64,
    #[allow(dead_code)]
    pub last_modified: i64,
    pub out_of_date: Option<i64>,
}

#[derive(Deserialize)]
struct Rpc {
    results: Vec<Info>,
}

pub fn info(names: &[String]) -> Result<Vec<Info>> {
    let mut url = String::from("https://aur.archlinux.org/rpc/v5/info?");
    for (i, n) in names.iter().enumerate() {
        if i > 0 {
            url.push('&');
        }
        url.push_str("arg[]=");
        url.push_str(&urlenc(n));
    }
    let rpc: Rpc = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(15))
        .call()
        .context("AUR RPC unreachable")?
        .into_json()
        .context("could not parse AUR RPC response")?;
    Ok(rpc.results)
}

pub fn urlenc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => (b as char).to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

pub fn cache_dir() -> PathBuf {
    let base = std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join("buzzard")
}

fn git(dir: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .context("git not found")?;
    if !out.status.success() {
        bail!("git {:?} failed: {}", args, String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Clone or update the repo. Returns (path, last reviewed commit).
/// The last reviewed commit is stored in `.git/buzzard-reviewed` and only
/// written after a successful install.
pub fn fetch(pkgbase: &str) -> Result<(PathBuf, Option<String>)> {
    if !pkgbase.chars().all(|c| c.is_ascii_alphanumeric() || "-_.+@".contains(c)) || pkgbase.starts_with('-') {
        bail!("invalid package name: {pkgbase}");
    }
    let dir = cache_dir().join(pkgbase);
    let reviewed =
        std::fs::read_to_string(dir.join(".git").join("buzzard-reviewed")).ok().map(|s| s.trim().to_string());
    if dir.join(".git").exists() {
        git(&dir, &["fetch", "--quiet", "origin"])?;
        git(&dir, &["reset", "--hard", "--quiet", "origin/master"])?;
    } else {
        std::fs::create_dir_all(cache_dir())?;
        let status = Command::new("git")
            .args(["clone", "--quiet", &format!("https://aur.archlinux.org/{pkgbase}.git")])
            .arg(&dir)
            .env("GIT_TERMINAL_PROMPT", "0")
            .status()
            .context("git not found")?;
        if !status.success() {
            bail!("cloning {pkgbase} failed");
        }
    }
    Ok((dir, reviewed))
}

pub fn head(dir: &Path) -> Result<String> {
    Ok(git(dir, &["rev-parse", "HEAD"])?.trim().to_string())
}

pub fn mark_reviewed(dir: &Path) -> Result<()> {
    let h = head(dir)?;
    std::fs::write(dir.join(".git").join("buzzard-reviewed"), h)?;
    Ok(())
}

/// Diff since the last confirmed version (empty on first install).
pub fn diff_since(dir: &Path, reviewed: &Option<String>) -> String {
    match reviewed {
        Some(c) => git(dir, &["diff", c, "HEAD", "--", ".", ":(exclude).SRCINFO"]).unwrap_or_default(),
        None => String::new(),
    }
}

/// All text-like files in the repo except .git (PKGBUILD, *.install, patches, scripts).
pub fn text_files(dir: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if name == ".git" || name == ".SRCINFO" {
                continue;
            }
            if let Ok(md) = e.metadata() {
                if md.is_file() && md.len() < 400_000 {
                    if let Ok(t) = std::fs::read_to_string(e.path()) {
                        out.push((name, t));
                    }
                }
            }
        }
    }
    out.sort();
    out
}

/// Export only tracked files (without .git) into a fresh build directory,
/// so a PKGBUILD cannot touch .git or the review marker.
pub fn export(dir: &Path, dest: &Path) -> Result<()> {
    if dest.exists() {
        std::fs::remove_dir_all(dest)?;
    }
    std::fs::create_dir_all(dest)?;
    let prefix = format!("--prefix={}/", dest.display());
    git(dir, &["checkout-index", "-a", "-f", &prefix])?;
    Ok(())
}
