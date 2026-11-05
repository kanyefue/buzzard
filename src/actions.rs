//! `buzzard do "free up disk space"`: Jev picks one action from a fixed list.
//! Jev can only choose; it never writes commands. Every action is confirmed.

use crate::ask;
use crate::jev::{Answer, Jev};
use anyhow::{bail, Result};
use serde_json::{json, Map, Value};
use std::process::Command;

#[derive(Clone)]
pub struct Action {
    pub name: String,
    pub desc: String,
    pub cmd: String,
}

const DEFAULTS: &[(&str, &str, &str)] = &[
    (
        "disk-usage",
        "Show how full the disks are and which folders in your home are the biggest",
        r#"df -h -x tmpfs -x devtmpfs; echo; du -xsh ~/* ~/.cache ~/.local 2>/dev/null | sort -h | tail -n 15"#,
    ),
    (
        "clean-pkg-cache",
        "Free disk space by removing old package versions from the pacman cache (keeps the last 2)",
        r#"if command -v paccache >/dev/null; then sudo paccache -rk2; sudo paccache -ruk0; else sudo pacman -Sc; fi"#,
    ),
    (
        "remove-orphans",
        "Free disk space by removing packages that were installed as dependencies and are no longer needed",
        r#"o=$(pacman -Qdtq); if [ -n "$o" ]; then sudo pacman -Rns $o; else echo "No orphaned packages."; fi"#,
    ),
    (
        "vacuum-journal",
        "Free disk space by shrinking the systemd log journal to the last 2 weeks",
        r#"journalctl --disk-usage; sudo journalctl --vacuum-time=2weeks"#,
    ),
    (
        "clean-user-cache",
        "Free disk space by deleting your user cache in ~/.cache (thumbnails, browser and app caches)",
        r#"du -sh ~/.cache; read -r -p "Delete everything in ~/.cache except Buzzard's own data? [y/N] " a; [ "$a" = y ] && find ~/.cache -mindepth 1 -maxdepth 1 ! -name buzzard -exec rm -rf {} + && echo done"#,
    ),
    (
        "big-packages",
        "List the 20 largest installed packages",
        r#"LC_ALL=C pacman -Qi | awk '/^Name/{n=$3} /^Installed Size/{s=$4; u=$5; m=(u=="GiB")?1024:(u=="MiB")?1:(u=="KiB")?1/1024:1/1048576; printf "%10.1f MiB  %s\n", s*m, n}' | sort -n | tail -n 20"#,
    ),
    (
        "failed-services",
        "Show systemd services that failed to start or crashed",
        r#"systemctl --failed; systemctl --user --failed"#,
    ),
    (
        "recent-errors",
        "Show error messages from the system log since the last boot",
        r#"journalctl -b -p err --no-pager | tail -n 40"#,
    ),
    (
        "refresh-mirrors",
        "Make downloads faster by refreshing the pacman mirror list with fast, up-to-date mirrors (needs reflector)",
        r#"command -v reflector >/dev/null || { echo "Install it first: sudo pacman -S reflector"; exit 1; }; sudo reflector --latest 20 --protocol https --sort rate --save /etc/pacman.d/mirrorlist"#,
    ),
    (
        "update-system",
        "Update the whole system: Arch news check, repo packages, then reviewed AUR packages",
        "buzzard upgrade",
    ),
];

fn actions_file() -> std::path::PathBuf {
    crate::config_dir().join("actions")
}

/// Built-in actions plus `~/.config/buzzard/actions` (one per line: `name | description | command`).
/// A user action with the same name replaces the built-in one.
pub fn load() -> Vec<Action> {
    merge(defaults(), &std::fs::read_to_string(actions_file()).unwrap_or_default())
}

fn defaults() -> Vec<Action> {
    DEFAULTS.iter().map(|(n, d, c)| Action { name: n.to_string(), desc: d.to_string(), cmd: c.to_string() }).collect()
}

/// Add the user's actions (`name | description | command` per line) to `v`.
fn merge(mut v: Vec<Action>, user: &str) -> Vec<Action> {
    for l in user.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#')) {
        let mut p = l.splitn(3, '|').map(str::trim);
        if let (Some(n), Some(d), Some(c)) = (p.next(), p.next(), p.next()) {
            if n.is_empty() || c.is_empty() {
                continue;
            }
            v.retain(|a| a.name != n);
            v.push(Action { name: n.into(), desc: d.into(), cmd: c.into() });
        }
    }
    v
}

pub fn list() {
    println!("File for your own actions: {}", actions_file().display());
    for a in load() {
        println!("  {:<18} {}", a.name, a.desc);
    }
}

fn pick_from_list(acts: &[Action]) -> Result<Action> {
    for (i, a) in acts.iter().enumerate() {
        println!("  {:>2}) {:<18} {}", i + 1, a.name, a.desc);
    }
    let n: usize = ask("Pick a number (Enter = cancel): ")?.parse().map_err(|_| anyhow::anyhow!("cancelled"))?;
    acts.get(n.wrapping_sub(1)).cloned().ok_or_else(|| anyhow::anyhow!("invalid number"))
}

pub fn run(request: &str, jev: Option<&Jev>) -> Result<()> {
    let acts = load();
    let mut chosen: Option<Action> = None;
    if let Some(j) = jev {
        let mut criteria = Map::new();
        for a in &acts {
            criteria.insert(a.name.clone(), Value::String(a.desc.clone()));
        }
        criteria.insert("__none__".into(), Value::String("None of the actions does what the user asks for.".into()));
        let q = json!({ "action": {
            "type": "choice",
            "instructions": "A Linux user describes in their own words what they want done (user_request). Which action fits best?",
            "criteria": criteria
        }});
        let r = j.evaluate(&json!({ "user_request": request }), &q)?;
        if let Some(Answer::Choice { choice, confidence, .. }) = r.answers.get("action") {
            if choice == "__none__" {
                println!("No action fits '{request}'. Available actions:");
            } else if *confidence < 0.4 {
                println!("Not sure what you mean (confidence {confidence:.2}). Available actions:");
            } else {
                chosen = acts.iter().find(|a| &a.name == choice).cloned();
                if let Some(a) = &chosen {
                    println!("'{request}' → \x1b[1m{}\x1b[0m (match confidence {confidence:.2})", a.name);
                }
            }
        }
    }
    let a = match chosen {
        Some(a) => a,
        None => pick_from_list(&acts)?,
    };
    println!("  {}\n  $ {}", a.desc, a.cmd);
    match ask("Run it? [y/N/l = list] ")?.to_lowercase().as_str() {
        "y" | "yes" => {}
        "l" => {
            let b = pick_from_list(&acts)?;
            println!("  $ {}", b.cmd);
            if ask("Run it? [y/N] ")?.to_lowercase() != "y" {
                bail!("cancelled");
            }
            return exec(&b.cmd);
        }
        _ => bail!("cancelled"),
    }
    exec(&a.cmd)
}

fn exec(cmd: &str) -> Result<()> {
    let st = Command::new("bash").arg("-c").arg(cmd).status()?;
    if !st.success() {
        bail!("action exited with {}", st.code().unwrap_or(1));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_have_unique_names() {
        let mut n: Vec<_> = defaults().into_iter().map(|a| a.name).collect();
        n.sort();
        n.dedup();
        assert_eq!(n.len(), DEFAULTS.len());
    }

    #[test]
    fn user_actions_add_and_replace() {
        let user = "# comment\nbattery | Show battery | upower -d\ndisk-usage | My disk check | df -h | grep sd\nbroken line\n";
        let v = merge(defaults(), user);
        assert_eq!(v.len(), DEFAULTS.len() + 1);
        let d = v.iter().find(|a| a.name == "disk-usage").unwrap();
        assert_eq!(d.cmd, "df -h | grep sd");
    }
}
