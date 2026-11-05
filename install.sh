#!/usr/bin/env bash
# Build Buzzard from this folder, install it to /usr/local/bin, then run the guided setup
# (API key, NVIDIA/AMD GPU detection, Ollama, local model). Arguments go to "buzzard setup",
# e.g. ./install.sh --cpu   or   ./install.sh --no-llm
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

if ! command -v pacman >/dev/null; then
  echo "Buzzard needs Arch Linux or an Arch-based distribution (pacman)." >&2
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  echo "Run this as your normal user, not as root. It asks for sudo when needed." >&2
  exit 1
fi

echo "==> Installing build tools and runtime dependencies"
pkgs=(base-devel git bubblewrap)
command -v cargo >/dev/null || pkgs+=(rust)
sudo pacman -S --needed "${pkgs[@]}"

echo "==> Building Buzzard"
cargo build --release --locked

echo "==> Installing to /usr/local/bin/buzzard"
sudo install -Dm755 target/release/buzzard /usr/local/bin/buzzard

echo "==> Guided setup"
exec /usr/local/bin/buzzard setup "$@"
