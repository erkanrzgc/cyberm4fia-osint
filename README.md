# cyberm4fia Open Source Intelligence

```
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗  ██╗███████╗██╗ █████╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║  ██║██╔════╝██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║███████║█████╗  ██║███████║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║╚════██║██╔══╝  ██║██╔══██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║     ██║██║     ██║██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
                    Open Source Intelligence by cyberm4fia
```

A terminal-first OSINT username reconnaissance framework. `cyberm4fia-osint` hunts a single username across **1,900+ platforms** — social, dating, dev, gaming, professional, community forums, and more — then enriches the findings with deep profile scraping, cross-referencing, breach checks, WHOIS, DNS, subdomain enumeration, recursive pivot discovery, and an optional **local LLM analyst** that writes a cybersecurity-aware report on the target.

Every check, profile parser, and email-side enrichment is implemented natively in Python — no subprocess wrappers, no external CLIs to install.

No parameters. No tuning. Just:

```bash
cyberm4fia <username>
```

---

## Features

- **1,900+ platforms** checked in parallel
- **Zero-flag full scan** by default — everything on unless you opt out with `--quick`
- **Deep profile scraping** for GitHub, GitLab, Reddit, Steam, Chess.com, Lichess, Keybase, Hacker News, Dev.to, and more
- **Opportunistic profile parsing** — pulls names, emails, locations, and linked accounts out of any HTML we fetched (200+ site schemes, optional install)
- **Cross-reference engine** with confidence scoring across names, locations, and profile photos
- **Smart search** — generates username variations and discovers linked accounts from scraped bios
- **Email discovery** + Gravatar detection + free breach lookup + public credential-leak search
- **Email → site enumeration** — pivot any discovered email through 120+ site registration probes (`--holehe`)
- **Google account lookup** — resolve emails to Google accounts (Gaia ID, name, services) (`--ghunt`)
- **Instagram profile OSINT** — optional `IG_SESSION_ID` for richer data (`--toutatis`)
- **Recursive pivot discovery** — usernames found inside profile data are fed back into the platform sweep (`--recursive`)
- **Profile photo matching** via perceptual hashing
- **WHOIS / DNS / subdomain enumeration** (crt.sh)
- **Wayback Machine** and paste-site presence
- **Scan history** with SQLite + diff mode (`--diff` shows what changed between runs)
- **Local LLM analysis** — plug in an OpenAI-compatible endpoint (LM Studio, llama.cpp, Ollama, vLLM) and get an AI-written identity / exposure report
- **HTML + JSON + DOT graph** exports
- **Tor / SOCKS / HTTP proxy** support
- **MCP server** for Claude Desktop and other MCP-compatible clients
- **CI-ready** — 500+ tests with ruff, mypy, bandit, and coverage checks

---

## Installation

Requires Python **3.10+**.

```bash
git clone https://github.com/erkanrzgc/cyberm4fia-osint.git
cd cyberm4fia-osint
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

After the editable install, the `cyberm4fia` command is available on your `$PATH`.

Optional extras:

```bash
pip install -e '.[ai]'        # local LLM via llama-cpp-python
pip install -e '.[photo]'     # profile photo hashing (Pillow, imagehash)
pip install -e '.[extract]'   # socid-extractor — auto-parse 200+ profile pages
pip install -e '.[holehe]'    # 120+ site email registration probes
pip install -e '.[ghunt]'     # Google account lookup (run `ghunt login` once after install)
pip install -e '.[toutatis]'  # Instagram profile OSINT
pip install -e '.[socks]'     # SOCKS / Tor support (aiohttp-socks)
pip install -e '.[api]'       # FastAPI REST server + web UI
pip install -e '.[report]'    # PDF/XLSX report exporters
pip install -e '.[dev]'       # pytest, ruff, mypy, coverage
```

---

## Quick Start

Full scan (everything on):

```bash
cyberm4fia johndoe
```

Fast sweep — platform check only:

```bash
cyberm4fia johndoe --quick
```

Only a specific category:

```bash
cyberm4fia johndoe --category social,dev
```

Export an HTML report:

```bash
cyberm4fia johndoe --output reports/johndoe.html
```

Run it behind Tor:

```bash
cyberm4fia johndoe --tor
```

Diff against the previous run for the same username:

```bash
cyberm4fia johndoe --diff
```

---

## AI Analysis (Local LLM)

`cyberm4fia` ships with an optional local-LLM analyst. It takes the structured scan result and generates a concise cybersecurity report: identity summary, strong linkages, exposures, and next steps — all as JSON, parsed and displayed inline.

Bring your own model — any cybersecurity-tuned 7B/8B GGUF that fits on an 8 GB GPU works well. The default loader points at a Q4_K_M quant.

### Option A — LM Studio / OpenAI-compatible HTTP (default)

1. Install [LM Studio](https://lmstudio.ai), download the model, and start the local server.
2. In **Developer → Server Settings**, enable **Serve on Local Network**.
3. Point `cyberm4fia` at the endpoint:

```bash
export CYBERM4FIA_LLM_URL="http://<host-ip>:1234/v1/chat/completions"
export CYBERM4FIA_LLM_MODEL="<your-loaded-model-id>"
cyberm4fia johndoe --ai
```

For a VMware / WSL VM talking to an LM Studio instance on the Windows host, use the host adapter IP (e.g. `192.168.6.1` for VMnet8) instead of `localhost`.

### Option B — Embedded `llama-cpp-python`

```bash
pip install -e '.[ai]'
export CYBERM4FIA_LLM_BACKEND=llama_cpp
python -m core.analysis.download   # fetches the default GGUF
cyberm4fia johndoe --ai
```

### Environment variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `CYBERM4FIA_LLM_BACKEND` | `http` | `http` or `llama_cpp` |
| `CYBERM4FIA_LLM_URL` | `http://localhost:1234/v1/chat/completions` | HTTP endpoint |
| `CYBERM4FIA_LLM_MODEL` | `""` | Model ID for the HTTP request |
| `CYBERM4FIA_LLM_API_KEY` | `lm-studio` | Bearer token |
| `CYBERM4FIA_LLM_TIMEOUT` | `120` | HTTP timeout (seconds) |
| `CYBERM4FIA_LLM_REPO` | _(your HF repo)_ | HF repo for `llama_cpp` backend |
| `CYBERM4FIA_LLM_FILE` | _(your GGUF file)_ | GGUF filename |
| `CYBERM4FIA_LLM_CTX` | `4096` | Context window |
| `CYBERM4FIA_LLM_MAX_TOKENS` | `768` | Max output tokens |
| `CYBERM4FIA_LLM_TEMPERATURE` | `0.2` | Sampling temperature |
| `CYBERM4FIA_LLM_GPU_LAYERS` | `-1` | llama.cpp GPU offload layers |

---

## CLI Reference

| Flag | Alias | Description |
| --- | --- | --- |
| `username` | — | Target username (positional) |
| `--quick` | `-q` | Quick mode — platform sweep only |
| `--full` | `-f` | Full scan (kept for backward compatibility; already the default) |
| `--smart` | `-s` | Username variations + discovered linked accounts |
| `--deep` / `--no-deep` | `-d` | Deep profile scraping (default: on) |
| `--email` | `-e` | Email discovery + Gravatar |
| `--breach` | — | Free breach lookup + public credential-leak search (auto-enables `--email`) |
| `--holehe` | — | Probe ~120 sites for each discovered email (requires `[holehe]` extra) |
| `--ghunt` | — | Google account lookup for each email (requires `[ghunt]` extra + `ghunt login`) |
| `--toutatis` | — | Instagram OSINT for the username (requires `[toutatis]` extra; set `IG_SESSION_ID` for richer data) |
| `--recursive` | — | Feed discovered usernames back into the platform sweep |
| `--recursive-depth N` | — | Recursive pivot depth (default `1`) |
| `--photo` | — | Profile photo perceptual-hash comparison |
| `--web` | `-w` | Wayback / paste / domain presence |
| `--whois` | — | WHOIS across 9 TLDs |
| `--dns` | — | DNS record lookup |
| `--subdomain` | — | crt.sh subdomain enumeration |
| `--category` | `-c` | Restrict to categories (`social,dev,gaming,...`) |
| `--tor` | `-toor` | Route through `socks5://127.0.0.1:9050` |
| `--proxy` | — | Custom HTTP/SOCKS proxy |
| `--output` | `-o` | Save report to `.json`, `.html`, or `.dot` |
| `--timeout` | `-t` | Per-request timeout (seconds) |
| `--history` | — | List prior scans for the username and exit |
| `--diff` | — | Diff against the previous scan after running |
| `--no-history` | — | Do not persist this scan |
| `--ai` | — | Run local-LLM analysis on the result |
| `--log-level` | — | `DEBUG`, `INFO`, `WARNING`, `ERROR` |

---

## Platform Coverage

**1,900+ platforms** across seven categories. Highlights:

- **Social:** Instagram, X / Twitter, TikTok, Facebook, Snapchat, Threads, Bluesky, Mastodon, Reddit, Tumblr, VK, Telegram, Weibo, MySpace, Gab, Truth Social, Flipboard, Matrix, Clubhouse, Quora, Pinterest, Ask.fm, Badoo
- **Dating:** Tinder, Badoo, MeetMe, Mamba, Hily, Tagged
- **Dev:** GitHub, GitLab, Bitbucket, Dev.to, Stack Overflow, HackerOne, TryHackMe, HackTheBox, Kaggle, Hugging Face, Codeforces, LeetCode, Replit, CodePen, npm, PyPI, crates.io, Docker Hub
- **Gaming:** Steam, Twitch, Chess.com, Lichess, Roblox, Xbox, NameMC, osu!, Speedrun.com, Fortnite Tracker
- **Content:** YouTube, Medium, Substack, WordPress, Hashnode, SoundCloud, Spotify, Bandcamp, Vimeo, Dailymotion, Rumble, Kick
- **Professional:** LinkedIn, Keybase, Behance, Dribbble, About.me, Gravatar, Wellfound, Crunchbase, Xing, ResearchGate, Academia.edu, Fiverr, Patreon
- **Community & other:** Hacker News, Product Hunt, Ko-fi, BuyMeACoffee, Venmo, Cash App, PayPal.me, Strava, Untappd, Letterboxd, MyAnimeList, Goodreads, Tripadvisor, Couchsurfing, Meetup, Wattpad, Itch.io

Want to add a platform? Edit `modules/platforms.yaml` — no code changes needed.

---

## Output Formats

- **Console** — rich, color-coded panels and tables (default)
- **JSON** — `cyberm4fia user --output out.json`
- **HTML** — `cyberm4fia user --output out.html` (self-contained, CSP-hardened)
- **Graphviz DOT** — `cyberm4fia user --output out.dot`

---

## Scan History

Every run is persisted to a local SQLite database (`history.db`). Disable with `--no-history`.

```bash
cyberm4fia johndoe --history   # list prior scans
cyberm4fia johndoe --diff      # diff against the last run
```

---

## Docker

```bash
docker build -t cyberm4fia-osint .
docker run --rm cyberm4fia-osint johndoe --quick
```

The compose API service binds to `127.0.0.1:8000` by default. If you expose it
outside localhost, enable the auth gate first:

```bash
docker compose run --rm cli --create-user analyst:change-me
OSINT_AUTH_REQUIRED=1 OSINT_AUTH_SECRET="$(openssl rand -hex 32)" docker compose up api
```

---

## Development

```bash
pip install -e '.[dev,api,report,socks,whois,photo,dns]'
pytest
pytest --cov=core --cov=modules     # coverage report
ruff check main.py core modules utils tests
mypy --ignore-missing-imports core modules utils
```

GitHub Actions runs the full matrix on every push.

---

## Legal & Ethical Use

This tool queries **public** profile endpoints — the same information anyone can view in a browser. Use it for:

- Security research and defensive OSINT
- CTF challenges and red-team exercises with written authorization
- Your own digital-footprint audit
- Journalism and investigative research within applicable law

**Do not** use it for harassment, stalking, doxing, or any activity that violates local law or the target platform's terms of service. The authors accept no responsibility for misuse.

---

## License

MIT — see [LICENSE](LICENSE).
