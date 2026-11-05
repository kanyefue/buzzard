//! Arch Linux news check before a system upgrade.
//! New posts are shown; Jev flags the ones that need manual intervention.

use crate::jev::{Answer, Jev};
use anyhow::{Context, Result};
use regex::Regex;
use serde_json::json;
use std::collections::HashSet;
use std::process::Command;

const FEED: &str = "https://archlinux.org/feeds/news/";

struct Item {
    guid: String,
    title: String,
    link: String,
    date: String,
    text: String,
}

fn unescape(s: &str) -> String {
    s.replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&#39;", "'").replace("&amp;", "&")
}

fn clean(s: &str) -> String {
    let s = s.replace("<![CDATA[", "").replace("]]>", "");
    let s = unescape(&s);
    let tags = Regex::new(r"<[^>]+>").unwrap();
    let s = tags.replace_all(&s, " ");
    let s = unescape(&s);
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn field(block: &str, name: &str) -> String {
    let re = Regex::new(&format!(r"(?s)<{name}[^>]*>(.*?)</{name}>")).unwrap();
    re.captures(block).map(|c| clean(&c[1])).unwrap_or_default()
}

fn fetch() -> Result<Vec<Item>> {
    let xml = ureq::get(FEED)
        .timeout(std::time::Duration::from_secs(15))
        .call()
        .context("archlinux.org unreachable")?
        .into_string()?;
    let item = Regex::new(r"(?s)<item>(.*?)</item>").unwrap();
    Ok(item
        .captures_iter(&xml)
        .map(|c| {
            let b = &c[1];
            let link = field(b, "link");
            let guid = Some(field(b, "guid")).filter(|g| !g.is_empty()).unwrap_or_else(|| link.clone());
            Item { guid, title: field(b, "title"), link, date: field(b, "pubDate"), text: field(b, "description") }
        })
        .collect())
}

fn seen_file() -> std::path::PathBuf {
    crate::aur::cache_dir().join("news-seen")
}

fn installed() -> HashSet<String> {
    Command::new("pacman")
        .arg("-Qq")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().map(String::from).collect())
        .unwrap_or_default()
}

/// Shows new news posts. Returns how many need attention before upgrading.
pub fn check(jev: Option<&Jev>) -> Result<usize> {
    let items = fetch()?;
    let seen_text = std::fs::read_to_string(seen_file()).ok();
    let first_run = seen_text.is_none();
    let seen: HashSet<String> = seen_text.unwrap_or_default().lines().map(String::from).collect();
    let mut new: Vec<&Item> = items.iter().filter(|i| !seen.contains(&i.guid)).collect();
    if first_run {
        new.truncate(3);
    }
    if new.is_empty() {
        println!("Arch news: nothing new.");
        return Ok(0);
    }

    let pkgs = installed();
    let word = Regex::new(r"[a-z0-9][a-z0-9+_.-]*").unwrap();
    let mut important = 0;
    println!("\n== Arch news ({} new) ==", new.len());
    for it in &new {
        let lower = format!("{} {}", it.title, it.text).to_lowercase();
        let mut mentioned: Vec<String> = word
            .find_iter(&lower)
            .map(|m| m.as_str().trim_end_matches('.').to_string())
            .filter(|w| w.len() >= 3 && pkgs.contains(w))
            .collect();
        mentioned.sort();
        mentioned.dedup();

        let (manual, affects) = match jev {
            Some(j) => {
                let text: String = it.text.chars().take(6000).collect();
                let state = json!({ "title": it.title, "text": text, "installed_packages_mentioned": mentioned });
                let q = json!({
                    "manual": { "type": "noul", "instructions": "This Arch Linux news post says users must take a manual step before or during the next system upgrade (for example replacing a package, editing a config file, or running a command)." },
                    "affects": { "type": "noul", "instructions": "The post concerns packages that are installed on this system (see installed_packages_mentioned)." }
                });
                let r = j.evaluate(&state, &q)?;
                let get = |k: &str| match r.answers.get(k) {
                    Some(Answer::Noul { noul }) => *noul,
                    _ => 1.0,
                };
                (get("manual"), get("affects"))
            }
            None => {
                let m = if lower.contains("manual intervention") { 1.0 } else { 0.0 };
                (m, if mentioned.is_empty() { 0.0 } else { 1.0 })
            }
        };
        let needs_action = manual >= 0.5 && (affects >= 0.5 || !mentioned.is_empty());
        let tag = if needs_action {
            important += 1;
            "\x1b[31mACTION NEEDED\x1b[0m"
        } else if manual >= 0.5 {
            "\x1b[33mmanual step, probably not for you\x1b[0m"
        } else {
            "info"
        };
        println!("\n[{tag}] {}\n  {}  {}", it.title, it.date, it.link);
        if !mentioned.is_empty() {
            println!("  installed packages mentioned: {}", mentioned.join(" "));
        }
        if needs_action {
            let snippet: String = it.text.chars().take(700).collect();
            println!("  {snippet}{}", if it.text.chars().count() > 700 { " …" } else { "" });
        }
    }

    std::fs::create_dir_all(crate::aur::cache_dir())?;
    let all: Vec<&str> = items.iter().map(|i| i.guid.as_str()).collect();
    std::fs::write(seen_file(), all.join("\n"))?;
    Ok(important)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleans_rss_html() {
        assert_eq!(
            clean("&lt;p&gt;Run &lt;code&gt;pacman -Syu&lt;/code&gt; &amp;amp; reboot&lt;/p&gt;"),
            "Run pacman -Syu & reboot"
        );
        let b =
            "<title>foo &gt;= 2.0 requires manual intervention</title><guid isPermaLink=\"true\">https://x/1</guid>";
        assert_eq!(field(b, "title"), "foo >= 2.0 requires manual intervention");
        assert_eq!(field(b, "guid"), "https://x/1");
    }
}
