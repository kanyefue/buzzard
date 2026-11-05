//! Sandbox via bubblewrap. Everything that executes PKGBUILD code runs in here.
//! A PKGBUILD is executed as bash when sourced (including for --printsrcinfo).

use anyhow::{bail, Context, Result};
use std::path::Path;
use std::process::Command;

pub fn require_bwrap() -> Result<()> {
    if Command::new("bwrap").arg("--version").output().is_err() {
        bail!("bubblewrap (bwrap) is missing: sudo pacman -S bubblewrap");
    }
    Ok(())
}

/// Base: root read-only, only `workdir` writable, no network, no access to $HOME.
fn base(workdir: &Path, net: bool) -> Command {
    let mut c = Command::new("bwrap");
    c.args([
        "--ro-bind",
        "/",
        "/",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/home",
        "--tmpfs",
        "/root",
    ])
    .args(["--unshare-pid", "--unshare-ipc", "--unshare-uts", "--die-with-parent", "--new-session"]);
    if !net {
        c.arg("--unshare-net");
    }
    let w = workdir.to_string_lossy();
    c.args(["--bind", &w, &w, "--chdir", &w]);
    c
}

/// Generate .SRCINFO ourselves: the shipped one may differ from the PKGBUILD.
pub fn printsrcinfo(workdir: &Path) -> Result<String> {
    let out =
        base(workdir, false).args(["makepkg", "--printsrcinfo"]).output().context("could not start bwrap/makepkg")?;
    if !out.status.success() {
        bail!("makepkg --printsrcinfo failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Download sources and verify checksums. Needs network, but only runs download code.
pub fn download_sources(workdir: &Path) -> Result<()> {
    let st = base(workdir, true)
        .args(["makepkg", "--verifysource", "--noconfirm"])
        .status()
        .context("could not start makepkg")?;
    if !st.success() {
        bail!("downloading/verifying sources failed");
    }
    Ok(())
}

/// Build without network. Dependencies must be installed beforehand.
pub fn build(workdir: &Path) -> Result<()> {
    let st = base(workdir, false)
        .args(["makepkg", "--noextract", "--force", "--noconfirm", "--nodeps"])
        .status()
        .context("could not start makepkg")?;
    if !st.success() {
        bail!("build failed");
    }
    Ok(())
}

pub struct SrcInfo {
    pub sources: Vec<String>,
    pub checksums: Vec<String>,
    pub depends: Vec<String>,
    pub makedepends: Vec<String>,
    pub install: Option<String>,
}

pub fn parse_srcinfo(s: &str) -> SrcInfo {
    let mut r = SrcInfo { sources: vec![], checksums: vec![], depends: vec![], makedepends: vec![], install: None };
    for line in s.lines() {
        let Some((k, v)) = line.trim().split_once(" = ") else { continue };
        let v = v.trim().to_string();
        match k {
            "source" => r.sources.push(v),
            "depends" => r.depends.push(v),
            "makedepends" | "checkdepends" => r.makedepends.push(v),
            "install" => r.install = Some(v),
            k if k.starts_with("sha") || k.starts_with("md5") || k.starts_with("b2sums") || k.starts_with("cksums") => {
                r.checksums.push(v)
            }
            _ => {}
        }
    }
    r
}

/// "foo>=1.2: description" -> "foo"
pub fn dep_name(d: &str) -> String {
    d.split(':').next().unwrap_or(d).split(|c| "<>=".contains(c)).next().unwrap_or(d).trim().to_string()
}
