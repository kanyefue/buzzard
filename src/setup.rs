//! `buzzard setup`: detect the GPU, install the matching Ollama build, pick a model
//! that fits, verify it runs on the GPU, and write ~/.config/buzzard/env.

use crate::{ask, config_dir};
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Vendor {
    Nvidia,
    Amd,
    Intel,
    Other,
}

#[derive(Debug, Clone)]
pub struct Gpu {
    pub vendor: Vendor,
    pub name: String,
    pub vram_mib: Option<u64>,
    /// NVIDIA: nvidia-smi works. AMD: the amdgpu driver is bound.
    pub driver_ok: bool,
}

#[derive(Debug, PartialEq)]
pub struct Plan {
    pub package: &'static str,
    pub model: &'static str,
    pub on_gpu: bool,
}

fn read(p: &Path) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

/// Display controllers from sysfs. Works even when no GPU driver is loaded yet.
pub fn detect_gpus() -> Vec<Gpu> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir("/sys/bus/pci/devices") else { return out };
    for e in rd.flatten() {
        let d = e.path();
        let class = read(&d.join("class")).unwrap_or_default();
        // 0x0300xx VGA, 0x0302xx 3D controller (many NVIDIA laptop GPUs)
        if !(class.starts_with("0x0300") || class.starts_with("0x0302")) {
            continue;
        }
        let vendor = match read(&d.join("vendor")).as_deref() {
            Some("0x10de") => Vendor::Nvidia,
            Some("0x1002") => Vendor::Amd,
            Some("0x8086") => Vendor::Intel,
            _ => Vendor::Other,
        };
        let driver = std::fs::read_link(d.join("driver"))
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_default();
        let vram_mib =
            read(&d.join("mem_info_vram_total")).and_then(|b| b.parse::<u64>().ok()).map(|b| b / 1024 / 1024);
        let name = match vendor {
            Vendor::Nvidia => "NVIDIA GPU",
            Vendor::Amd => "AMD GPU",
            Vendor::Intel => "Intel GPU",
            Vendor::Other => "GPU",
        };
        out.push(Gpu { vendor, name: name.into(), vram_mib, driver_ok: vendor == Vendor::Amd && driver == "amdgpu" });
    }
    // nvidia-smi knows the real name and memory, and proves the driver works.
    if out.iter().any(|g| g.vendor == Vendor::Nvidia) {
        if let Ok(o) =
            Command::new("nvidia-smi").args(["--query-gpu=name,memory.total", "--format=csv,noheader,nounits"]).output()
        {
            if o.status.success() {
                let text = String::from_utf8_lossy(&o.stdout).into_owned();
                let mut lines = text.lines();
                for g in out.iter_mut().filter(|g| g.vendor == Vendor::Nvidia) {
                    if let Some((n, m)) = lines.next().and_then(|l| l.rsplit_once(',')) {
                        g.name = n.trim().to_string();
                        g.vram_mib = m.trim().parse().ok();
                        g.driver_ok = true;
                    }
                }
            }
        }
    }
    out
}

pub fn ram_mib() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|t| {
            t.lines()
                .find(|l| l.starts_with("MemTotal:"))
                .and_then(|l| l.split_whitespace().nth(1)?.parse::<u64>().ok())
        })
        .map(|kib| kib / 1024)
        .unwrap_or(8192)
}

/// The GPU worth using: a working NVIDIA card, else an AMD card with at least 4 GB of its own memory
/// (integrated AMD graphics report a few hundred MB and are slower than the CPU path).
pub fn usable_gpu(gpus: &[Gpu]) -> Option<&Gpu> {
    gpus.iter()
        .filter(|g| g.driver_ok && g.vram_mib.unwrap_or(0) >= 3500)
        .filter(|g| matches!(g.vendor, Vendor::Nvidia | Vendor::Amd))
        .max_by_key(|g| (g.vendor == Vendor::Nvidia, g.vram_mib))
}

/// The model Buzzard always installs. It works on the CPU and on any GPU with ~4 GB or more.
pub const MODEL: &str = "qwen3.5:4b";

/// Pick the Ollama build. The model is always `MODEL`; only the backend depends on the hardware.
pub fn choose(gpu: Option<&Gpu>) -> Plan {
    match gpu {
        Some(g) if g.vendor == Vendor::Nvidia => Plan { package: "ollama-cuda", model: MODEL, on_gpu: true },
        Some(_) => Plan { package: "ollama-rocm", model: MODEL, on_gpu: true },
        None => Plan { package: "ollama", model: MODEL, on_gpu: false },
    }
}

fn yes_no(prompt: &str, default_yes: bool, assume: bool) -> Result<bool> {
    if assume {
        return Ok(default_yes);
    }
    let a = ask(prompt)?.to_lowercase();
    Ok(if a.is_empty() { default_yes } else { a == "y" || a == "yes" })
}

fn read_secret(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let _ = Command::new("stty").arg("-echo").status();
    let mut s = String::new();
    let r = std::io::stdin().read_line(&mut s);
    let _ = Command::new("stty").arg("echo").status();
    println!();
    r?;
    Ok(s.trim().to_string())
}

/// Set KEY=value in ~/.config/buzzard/env, keeping every other line. File mode 600.
pub fn set_env_var(key: &str, value: &str) -> Result<()> {
    set_env_var_in(&config_dir(), key, value)
}

fn set_env_var_in(dir: &Path, key: &str, value: &str) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::create_dir_all(dir)?;
    let path = dir.join("env");
    let old = std::fs::read_to_string(&path).unwrap_or_default();
    let mut lines: Vec<String> = old
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            let t = t.strip_prefix("export ").unwrap_or(t);
            !t.starts_with(&format!("{key}="))
        })
        .map(String::from)
        .collect();
    lines.push(format!("{key}={value}"));
    std::fs::write(&path, lines.join("\n") + "\n")?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn sudo(args: &[&str]) -> Result<()> {
    println!("$ sudo {}", args.join(" "));
    let st = Command::new("sudo").args(args).status().context("sudo not found")?;
    if !st.success() {
        bail!("'sudo {}' failed", args.join(" "));
    }
    Ok(())
}

fn ollama_up(url: &str) -> bool {
    ureq::AgentBuilder::new().timeout(Duration::from_secs(2)).build().get(&format!("{url}/api/tags")).call().is_ok()
}

/// Load the model once and ask Ollama how much of it sits in video memory.
fn gpu_share(url: &str, model: &str) -> Result<f64> {
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(600)).build();
    agent
        .post(&format!("{url}/api/generate"))
        .send_json(json!({ "model": model, "prompt": "Reply with OK.", "stream": false,
                           "options": { "num_ctx": 8192, "num_predict": 4 } }))
        .context("could not load the model")?;
    let ps: Value = agent.get(&format!("{url}/api/ps")).call()?.into_json()?;
    let m = ps["models"]
        .as_array()
        .and_then(|a| a.iter().find(|m| m["name"].as_str() == Some(model) || m["model"].as_str() == Some(model)));
    let Some(m) = m else { return Ok(0.0) };
    let size = m["size"].as_f64().unwrap_or(0.0);
    Ok(if size > 0.0 { m["size_vram"].as_f64().unwrap_or(0.0) / size } else { 0.0 })
}

const UNIT_SERVICE: &str = include_str!("../contrib/systemd/buzzard-logs.service");
const UNIT_TIMER: &str = include_str!("../contrib/systemd/buzzard-logs.timer");
const EX_COMMANDS: &str = include_str!("../examples/commands");
const EX_ACTIONS: &str = include_str!("../examples/actions");

fn user_unit_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("/tmp"))
        .join("systemd/user")
}

pub struct Options {
    pub yes: bool,
    pub cpu: bool,
    pub no_llm: bool,
    pub dry: bool,
    pub model: Option<String>,
}

pub fn run(o: Options) -> Result<()> {
    println!("== Buzzard setup ==\n");

    // 1) Hardware
    let gpus = detect_gpus();
    let ram = ram_mib();
    println!("RAM: {:.1} GB", ram as f64 / 1024.0);
    if gpus.is_empty() {
        println!("GPU: none found");
    }
    for g in &gpus {
        let vram = g
            .vram_mib
            .map(|v| format!("{:.1} GB video memory", v as f64 / 1024.0))
            .unwrap_or_else(|| "video memory unknown".into());
        let drv = match (g.vendor, g.driver_ok) {
            (Vendor::Nvidia, false) => ", \x1b[33mNVIDIA driver not working (nvidia-smi failed)\x1b[0m",
            (Vendor::Amd, false) => ", \x1b[33mamdgpu driver not loaded\x1b[0m",
            _ => "",
        };
        println!("GPU: {} ({vram}{drv})", g.name);
    }
    if gpus.iter().any(|g| g.vendor == Vendor::Nvidia && !g.driver_ok) {
        println!(
            "\nYour NVIDIA card can make the local LLM much faster, but its driver is not working yet.\n\
             Install it (for most cards: sudo pacman -S nvidia-open, or nvidia-open-dkms for non-standard kernels),\n\
             reboot, and run 'buzzard setup' again. Continuing with the CPU for now."
        );
    }
    let gpu = if o.cpu { None } else { usable_gpu(&gpus) };
    let plan = choose(gpu);
    let model = o.model.clone().unwrap_or_else(|| plan.model.to_string());

    // 2) Plan
    println!("\nPlan:");
    println!("  config folder:  {}", config_dir().display());
    if o.no_llm {
        println!("  local LLM:      skipped (--no-llm)");
    } else {
        println!(
            "  Ollama package: {}  ({})",
            plan.package,
            if plan.on_gpu { "runs the model on your GPU" } else { "runs the model on the CPU" }
        );
        println!("  model:          {model}");
    }
    if o.dry {
        return Ok(());
    }
    if !yes_no("\nContinue? [Y/n] ", true, o.yes)? {
        bail!("cancelled");
    }

    // 3) Config files
    let dir = config_dir();
    std::fs::create_dir_all(&dir)?;
    for (name, text) in [("commands", EX_COMMANDS), ("actions", EX_ACTIONS)] {
        let p = dir.join(name);
        if !p.exists() {
            std::fs::write(&p, text)?;
            println!("created {}", p.display());
        }
    }
    if std::env::var("TYPESAFE_API_KEY").map(|k| k.trim().is_empty()).unwrap_or(true) {
        if o.yes {
            println!("No TypeSafe API key set. Add it later with: buzzard setup");
        } else {
            let k = read_secret("TypeSafe API key (input hidden, Enter to skip): ")?;
            if k.is_empty() {
                println!("Skipped. Without a key only '--offline' mode works.");
            } else {
                set_env_var("TYPESAFE_API_KEY", &k)?;
                println!("saved to {} (mode 600)", dir.join("env").display());
            }
        }
    } else {
        println!("TypeSafe API key: already set");
    }

    // 4) Ollama + model
    if !o.no_llm {
        let url = std::env::var("BUZZARD_LLM_URL").unwrap_or_else(|_| "http://127.0.0.1:11434".into());
        let installed =
            |p: &str| Command::new("pacman").args(["-Q", p]).output().map(|x| x.status.success()).unwrap_or(false);
        let was_running = ollama_up(&url);
        let mut on_gpu = plan.on_gpu;
        if installed(plan.package) {
            println!("{} is already installed", plan.package);
        } else if let Err(e) = sudo(&["pacman", "-S", "--needed", plan.package]) {
            if plan.package == "ollama" {
                return Err(e);
            }
            // The GPU build is optional: plain Ollama on the CPU works too.
            println!(
                "\x1b[33m{} could not be installed ({e:#}); using the normal ollama package instead.\x1b[0m",
                plan.package
            );
            sudo(&["pacman", "-S", "--needed", "ollama"])?;
            on_gpu = false;
        }
        if was_running {
            // restart so a newly installed GPU backend is picked up
            sudo(&["systemctl", "restart", "ollama"])?;
        } else {
            sudo(&["systemctl", "enable", "--now", "ollama"])?;
        }
        print!("waiting for Ollama");
        let mut up = false;
        for _ in 0..30 {
            if ollama_up(&url) {
                up = true;
                break;
            }
            print!(".");
            std::io::stdout().flush().ok();
            std::thread::sleep(Duration::from_secs(1));
        }
        println!();
        if !up {
            bail!("Ollama did not start. Check: systemctl status ollama");
        }
        // MODEL is always installed; a model chosen with --llm-model comes on top.
        let mut pulls = vec![MODEL.to_string()];
        if model != MODEL {
            pulls.push(model.clone());
        }
        for m in &pulls {
            let ok = (0..2).any(|attempt| {
                if attempt > 0 {
                    println!("retrying ollama pull {m}…");
                }
                Command::new("ollama").args(["pull", m]).status().map(|s| s.success()).unwrap_or(false)
            });
            if !ok {
                bail!("ollama pull {m} failed. Check your internet connection and run 'buzzard setup' again");
            }
        }
        set_env_var("BUZZARD_LLM_MODEL", &model)?;
        println!("default model: {model}");

        println!("checking where the model runs…");
        match gpu_share(&url, &model) {
            Ok(s) if on_gpu && s >= 0.99 => println!("\x1b[32m{model} runs 100% on the GPU.\x1b[0m"),
            Ok(s) if on_gpu && s > 0.0 => println!(
                "{model} runs {:.0}% on the GPU and the rest on the CPU. It works, just a bit slower.",
                s * 100.0
            ),
            Ok(_) if on_gpu => println!(
                "\x1b[33m{model} runs on the CPU, the GPU is not used.\x1b[0m\n\
                 Check 'journalctl -u ollama' for GPU errors. Older AMD cards are not supported by ROCm."
            ),
            Ok(_) => println!("{model} runs on the CPU."),
            Err(e) => println!("could not check ({e:#})"),
        }
    }

    // 5) Hourly log check
    if yes_no("\nEnable the hourly log check with desktop notifications? [y/N] ", false, o.yes)? {
        let packaged = Path::new("/usr/lib/systemd/user/buzzard-logs.timer").exists();
        if !packaged {
            let d = user_unit_dir();
            std::fs::create_dir_all(&d)?;
            std::fs::write(d.join("buzzard-logs.service"), UNIT_SERVICE)?;
            std::fs::write(d.join("buzzard-logs.timer"), UNIT_TIMER)?;
        }
        let _ = Command::new("systemctl").args(["--user", "daemon-reload"]).status();
        let st = Command::new("systemctl").args(["--user", "enable", "--now", "buzzard-logs.timer"]).status()?;
        if st.success() {
            println!("enabled. Check it with: systemctl --user list-timers buzzard-logs.timer");
        }
    }

    println!("\n\x1b[32mSetup done.\x1b[0m Try: buzzard check yay");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gpu(vendor: Vendor, vram: u64, ok: bool) -> Gpu {
        Gpu { vendor, name: "x".into(), vram_mib: Some(vram), driver_ok: ok }
    }

    #[test]
    fn picks_backend_and_model() {
        let n8 = gpu(Vendor::Nvidia, 8192, true);
        assert_eq!(choose(Some(&n8)), Plan { package: "ollama-cuda", model: "qwen3.5:4b", on_gpu: true });
        let a16 = gpu(Vendor::Amd, 16_368, true);
        assert_eq!(choose(Some(&a16)), Plan { package: "ollama-rocm", model: "qwen3.5:4b", on_gpu: true });
        assert_eq!(choose(None), Plan { package: "ollama", model: "qwen3.5:4b", on_gpu: false });
    }

    #[test]
    fn ignores_unusable_gpus() {
        let igpu = gpu(Vendor::Amd, 512, true);
        let broken = gpu(Vendor::Nvidia, 8192, false);
        let intel = gpu(Vendor::Intel, 8192, true);
        assert!(usable_gpu(&[igpu.clone(), broken, intel]).is_none());
        let dgpu = gpu(Vendor::Amd, 8176, true);
        assert_eq!(usable_gpu(&[igpu, dgpu]).unwrap().vram_mib, Some(8176));
    }

    #[test]
    fn env_file_update_keeps_other_lines() {
        let tmp = std::env::temp_dir().join(format!("buzzard-test-{}", std::process::id()));
        std::fs::create_dir_all(tmp.join("buzzard")).unwrap();
        std::fs::write(tmp.join("buzzard/env"), "export TYPESAFE_API_KEY=abc\nBUZZARD_LLM_MODEL=old\n").unwrap();
        set_env_var_in(&tmp.join("buzzard"), "BUZZARD_LLM_MODEL", "qwen3.5:4b").unwrap();
        let t = std::fs::read_to_string(tmp.join("buzzard/env")).unwrap();
        assert_eq!(t, "export TYPESAFE_API_KEY=abc\nBUZZARD_LLM_MODEL=qwen3.5:4b\n");
        std::fs::remove_dir_all(&tmp).ok();
    }
}
