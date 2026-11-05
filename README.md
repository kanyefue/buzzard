<p align="center">
  <img src="assets/logo.svg" alt="Buzzard logo" width="160">
</p>

<h1 align="center">Buzzard</h1>

<p align="center">
  <b>An AUR helper that reads the PKGBUILD before you install it.</b><br>
  Rules, the Jev decision model and a sandbox review every AUR package, every update and every copied command.
</p>

<p align="center">
  <a href="https://github.com/YOUR_GITHUB_USER/buzzard/actions/workflows/ci.yml"><img src="https://github.com/YOUR_GITHUB_USER/buzzard/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/YOUR_GITHUB_USER/buzzard/releases"><img src="https://img.shields.io/github/v/release/YOUR_GITHUB_USER/buzzard" alt="Release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/Arch%20Linux-1793D1?logo=archlinux&logoColor=white" alt="Arch Linux">
  <img src="https://img.shields.io/badge/written%20in-Rust-orange?logo=rust" alt="Rust">
</p>

---

The AUR is one of the best things about Arch, and also the place where anyone can upload a build script
that runs on your machine. Most people press Enter on `yay -S` without reading it.
**Buzzard reads it for you**, tells you what looks wrong and why, and only then builds and installs.

```text
$ buzzard install apple music
'apple music' → cider [AUR, 31 votes] (match confidence 0.61)
Use this package? [Y/n/l = list] l
...
== apple-music-desktop ==
  jev  credential_or_exfil: 0.61
  jev  downloads_and_runs: 0.87
  jev  verdict: safe (confidence 0.55, P(malicious)=0.07)
Result: careful review needed
-- local LLM review (qwen3.5:4b, advisory) --
(quotes the lines behind each flag and says whether they look normal or dangerous)
Continue anyway? Type 'apple-music-desktop' to confirm:
```

## Features

- 🛡️ **Reviewed AUR installs.** Every AUR package (and every AUR dependency) is checked before it is built:
  deterministic rules, the [Jev](https://typesafe.ai) decision model, and an optional local LLM that quotes
  the suspicious lines.
- 📦 **Sandboxed builds.** PKGBUILDs run inside [bubblewrap](https://github.com/containers/bubblewrap): no access
  to your home folder, and no network while building.
- 🔁 **Reviewed updates.** `buzzard upgrade` checks the Arch news, runs `pacman -Syu`, then reviews only what
  changed in each AUR package since the version you last confirmed.
- 🔎 **Plain-language search.** `buzzard install apple music` finds the right package among repo and AUR matches.
- ⌨️ **Command check.** `buzzard run '<command>'` reviews a command you copied from a forum before it runs.
- 📰 **Arch news check.** Posts that need manual intervention and concern your installed packages are flagged.
- 📋 **Log triage.** `buzzard logs` sorts journal warnings into harmless, needs attention and security,
  with an optional hourly timer and desktop notifications.
- 🧹 **Tasks in plain words.** `buzzard do free up disk space` picks a matching task from a fixed list and asks first.
- 🧠 **Local LLM, auto-configured.** `buzzard setup` detects an NVIDIA or AMD GPU, installs the matching Ollama
  build and `qwen3.5:4b`. CPU-only works too.
- ⚙️ **Yours to extend.** Custom commands and custom actions in plain text files.
- 🪶 **Small and fast.** One ~3.5 MB Rust binary, no daemon, no Python.

## How a package is reviewed

```text
 AUR package
     │
     ├─ 1. Rules ─────────── curl | sh, base64 exec, SUID, sudoers, SSH keys, credential paths,
     │                       reverse shells, persistence, text aimed at an AI reviewer …
     ├─ 2. Own .SRCINFO ──── generated in the sandbox (the shipped one can lie)
     ├─ 3. Jev ───────────── one request: verdict (safe / review / malicious) + 5 yes/no questions
     ├─ 4. Local LLM ─────── only if something was flagged; explains, never clears
     └─ 5. Build ─────────── in the sandbox without network → you confirm → pacman -U
```

| Result | Triggered by | You have to |
|---|---|---|
| 🔴 **Blocked** | Jev: malicious (P ≥ 0.5) | build it yourself if you disagree |
| 🟠 **Careful review** | critical rule, Jev unsure or says "review", a yes/no answer ≥ 0.5 | type the package name |
| 🟡 **Confirmation** | rule warnings, first install, a yes/no answer ≥ 0.2 | type `y` |
| 🟢 **Clean** | nothing of the above | type `y` (or pass `--yes`) |

**Why Jev?** Jev is not a chatbot. It answers typed questions ("is this obfuscated?") with calibrated
probabilities in a single pass, which makes it fast and cheap enough to run on every package and every
log line. The local LLM is only there to explain, and it can make a result stricter but never clean,
because a small model reading hostile code is easy to talk into "this is fine".

## Install

You need **Arch Linux** (or an Arch-based distribution) and a **[TypeSafe](https://typesafe.ai) API key**.

### Quick install (recommended)

```sh
git clone https://github.com/YOUR_GITHUB_USER/buzzard
cd buzzard
./install.sh
```

`install.sh` installs the build tools, compiles Buzzard, puts it in `/usr/local/bin` and starts the
guided setup, which:

1. asks for your TypeSafe API key and stores it in `~/.config/buzzard/env` (mode 600),
2. detects your GPU and installs `ollama-cuda` (NVIDIA), `ollama-rocm` (AMD) or `ollama` (CPU),
3. downloads `qwen3.5:4b` and checks whether it really runs on the GPU,
4. optionally enables the hourly log check.

Preview without changing anything: `./install.sh --dry`. Skip the local LLM: `./install.sh --no-llm`.

### Other ways

<details>
<summary><b>AUR</b> (once published)</summary>

```sh
git clone https://aur.archlinux.org/buzzard.git && cd buzzard && makepkg -si
buzzard setup
```
</details>

<details>
<summary><b>Prebuilt binary</b> (x86_64 and aarch64)</summary>

Download the archive and its `.sha256` file from the [releases page](https://github.com/YOUR_GITHUB_USER/buzzard/releases), then:

```sh
sudo pacman -S --needed base-devel git bubblewrap
sha256sum -c buzzard-v*-x86_64-unknown-linux-gnu.tar.gz.sha256
tar -xzf buzzard-v*-x86_64-unknown-linux-gnu.tar.gz
sudo install -m755 buzzard-v*/buzzard /usr/local/bin/buzzard
buzzard setup
```
</details>

<details>
<summary><b>From source, manually</b></summary>

```sh
sudo pacman -S --needed base-devel git bubblewrap rust
git clone https://github.com/YOUR_GITHUB_USER/buzzard && cd buzzard
cargo build --release --locked
sudo install -m755 target/release/buzzard /usr/local/bin/buzzard
buzzard setup
```
</details>

## Usage

| Command | What it does |
|---|---|
| `buzzard install <name or description>` | find, review, build in a sandbox, install |
| `buzzard check <package>` | review only |
| `buzzard search <terms>` | search repos and AUR |
| `buzzard upgrade` | Arch news → `pacman -Syu` → reviewed AUR updates (`--aur-only` to skip the first two) |
| `buzzard audit` | re-review every installed AUR package |
| `buzzard run '<command>'` | check a shell command, then run it (`--dry` to only check) |
| `buzzard news` | new Arch news, manual steps flagged |
| `buzzard logs` | sort recent journal warnings (`--since today`, `--all`, `--notify`) |
| `buzzard do <task in plain words>` · `buzzard actions` | run a task from your action list · show the list |
| `buzzard setup` | API key, GPU detection, Ollama, local model |
| `buzzard commands` | show your custom commands |

Short forms: `i`, `c`, `s`, `u`. Global options: `--offline` (rules only, no Jev), `--no-llm`,
`--model jev-1.13.0` (pin the Jev version so thresholds stay comparable).

```sh
buzzard install firefox, apple music       # several packages, comma-separated
buzzard run 'curl -fsSL https://get.example.sh | sudo bash'
buzzard do clean up old packages
buzzard logs --since "2 days ago" --all
```

Packages from the official repositories are signed by Arch and go straight to `pacman -S`.

## Configuration

Everything lives in `~/.config/buzzard/`.

**`env`**: settings. Buzzard reads this file itself, so it works in bash, zsh, fish and systemd timers.
Variables set in your shell take precedence.

| Variable | Default | |
|---|---|---|
| `TYPESAFE_API_KEY` | none | required |
| `BUZZARD_LLM_MODEL` | `qwen3.5:4b` | any Ollama model |
| `BUZZARD_LLM_URL` | `http://127.0.0.1:11434` | |
| `BUZZARD_LLM_API` | `ollama` | `openai` for llama.cpp `llama-server` and similar |
| `BUZZARD_LLM_THINK` | off | `1` allows a model's thinking mode (slower) |
| `BUZZARD_LLM_MAX_CHARS` | `12000` | less input = faster on CPU |

**`commands`**: your own commands ([example](examples/commands)).

```text
get     = install                            # buzzard get spotify
music   = install apple music                # buzzard music
cleanup = !sudo pacman -Rns $(pacman -Qdtq)  # "!" runs a shell command; arguments are in "$@"
```

Built-in commands cannot be overridden, so nothing can sneak around the review.

**`actions`**: what `buzzard do` may run ([example](examples/actions)). Jev only picks from this list;
it never writes commands, and every action is shown and confirmed first.

```text
restart-audio | Fix sound problems by restarting PipeWire | systemctl --user restart pipewire pipewire-pulse wireplumber
```

**Hourly log check**: `buzzard setup` can enable it, or manually:
`systemctl --user enable --now buzzard-logs.timer` (units in [`contrib/systemd`](contrib/systemd)).
To see system logs and not only your own, your user needs to be in `wheel`, `adm` or `systemd-journal`.

## Privacy and limits

- **What is sent to TypeSafe** depends on the command; [SECURITY.md](SECURITY.md) lists it exactly.
  For `logs` that includes log lines, which can contain user names and IP addresses.
  The local LLM never sends anything off your machine.
- **No guarantee.** Rules can be evaded and models can be wrong. Buzzard makes you look at the right
  lines at the right time; the decision stays yours.
- **The sandbox protects the build, not the result.** What you install with `pacman -U` runs as root.
- AUR-only `provides` names are not resolved for dependencies.

## FAQ

**Do I need a GPU?** No. `qwen3.5:4b` runs on the CPU; a review then takes about a minute instead of seconds.
The local LLM is optional anyway (`--no-llm`).

**What does Jev cost?** TypeSafe bills per input token, and Buzzard's requests are small (one per package,
command or distinct log message). See TypeSafe's pricing page for current rates.

**Can I use it without TypeSafe?** `--offline` uses the rules only and asks for confirmation on everything.

**Does it replace yay or paru?** For installing and updating AUR packages, yes. It deliberately does less:
no `-git` auto-rebuilds, no PKGBUILD editing, no extra repositories.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Releases are built by GitHub Actions: push a tag like `v0.1.0` and the x86_64 and aarch64 binaries
appear on the releases page with checksums. The AUR package lives in [`packaging/aur`](packaging/aur).

Issues and pull requests are welcome. Please report security problems privately, see [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Buzzard is not affiliated with TypeSafe AI or Arch Linux.
