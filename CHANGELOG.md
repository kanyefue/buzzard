# Changelog

## 0.1.0 (unreleased)

First release.

- `install`, `check`, `search`: find packages by name or description, review AUR packages with rules, Jev and a bubblewrap sandbox, then install.
- `upgrade`: Arch news check, `pacman -Syu`, then reviewed AUR updates (diff since the last confirmed version).
- `audit`: re-review every installed AUR package.
- `run`: check a shell command before running it.
- `do` / `actions`: pick a task from a fixed list of actions using plain words.
- `news`: show new Arch news and flag posts that need manual steps.
- `logs`: sort journal warnings into harmless / needs attention / security; hourly systemd user timer included.
- Optional local LLM second opinion via Ollama or any OpenAI-compatible server (default `qwen3.5:4b`).
- `setup` and `install.sh`: guided setup that detects NVIDIA/AMD GPUs, installs the matching Ollama build (falls back to plain `ollama`) and always installs `qwen3.5:4b`.
- Custom commands in `~/.config/buzzard/commands`.
