# Security

## Reporting a vulnerability

Please report security problems privately through GitHub's
"Report a vulnerability" button on the repository's Security tab, not in a public issue.

## What Buzzard is and is not

Buzzard lowers the risk of installing AUR packages and running copied commands. It is not a guarantee:
rules can be evaded, and Jev and the local LLM are models that can be wrong or manipulated.
The local LLM can only make a result stricter, never mark something as clean.

## What leaves your computer

Sent to the TypeSafe API (Jev), only for the command you run:

| Command | Data sent |
|---|---|
| `install`, `check`, `upgrade`, `audit` | the AUR package's files (PKGBUILD, install scripts, patches), the diff since your last confirmed version, AUR metadata |
| `install`/`check` with a description | your search words and the names/descriptions of matching packages |
| `run` | the command text |
| `do` | your request text |
| `news` | Arch news posts and which of your installed packages they mention |
| `logs` | journal warning messages (these can contain user names, host names and IP addresses) |

The local LLM runs on your machine; nothing is sent elsewhere. Your API key is read from
`TYPESAFE_API_KEY` or `~/.config/buzzard/env` (keep that file at mode 600).
