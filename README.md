# DorkHunter
Advanced SQL Injection vulnerability scanner using Google dorking techniques, powered by [Serper.dev](https://serper.dev) (free, no credit card required).

### 🚀 Features

- **Serper.dev Search Integration**: Find vulnerable URLs using Google dorks — e.g., `inurl:product?id=`
- **Three-Stage SQLi Testing**: Comprehensive checks for error-based, boolean-based, and time-based blind SQLi
- **Per-Parameter Dynamic Gate**: Each parameter is dynamism-checked independently — static params are skipped, active params are fully tested
- **Baseline-Aware Time Detection**: Measures baseline response time before injecting sleep payloads; avoids false positives on slow networks
- **robots.txt Enforcement**: Automatically fetches and caches `/robots.txt` for every target; disallowed URLs are skipped
- **Scanned URL Memory with Auto-Trim**: Remembers previously scanned URLs across runs; trims to last 10 000 entries to prevent unbounded growth
- **Concurrent Scanning**: Multi-threaded architecture for efficient scanning (configurable `MAX_WORKERS`)
- **Broad Parameter Coverage**: 50+ commonly injectable parameter names recognised (id, q, search, sort, type, keyword, …)
- **Secure API Key Input**: Key hidden while typing via `getpass`; never stored or logged
- **Verbose / Quiet CLI Flags**: `-v` for per-URL status + debug logging; `-q` for silent mode
- **CSV Reporting**: Export results for further analysis
- **Stealth Mode**: Randomised delays and user-agent rotation

---

## 📋 Requirements

### 1. Python 3.8+
[Download Python](https://www.python.org/downloads/)

### 2. Serper.dev API Key (Free)
- Sign up at [https://serper.dev](https://serper.dev) — no credit card required
- You get **2,500 free queries** on signup
- Copy your API key from the dashboard

---

## ⚙️ Setup

### 1. Clone Repository
```bash
git clone https://github.com/xfnx-17/DorkHunter.git
cd DorkHunter
```

### 2. Create Virtual Environment
#### Linux / macOS
```bash
python3 -m venv venv
source venv/bin/activate
```
#### Windows
```
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🎮 Usage

```bash
python DorkHunter.py [OPTIONS]
```

### CLI Options

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Show per-URL status (CLEAN / SKIPPED / robots.txt blocks) and enable DEBUG-level file logging |
| `-q`, `--quiet` | Suppress all output except VULNERABLE findings |

### Workflow
1. Run the script (optionally with `-v` or `-q`)
2. Enter your Serper.dev API key (input is hidden)
3. Input a search dork (e.g., `inurl:login.php?id=`)
4. Set the maximum number of vulnerable URLs to find
5. Choose whether to save results to a CSV report

### Example
```bash
# Standard run
python DorkHunter.py

# Verbose — see every URL result + debug log entries
python DorkHunter.py -v

# Quiet — only print VULNERABLE hits
python DorkHunter.py -q
```

---

## 📂 File Structure

```
📂 DorkHunter/
├── 📄 DorkHunter.py      — Main scanner script
├── 📄 payloads.txt       — SQL injection payload database
├── 📄 user_agents.txt    — Browser User-Agent strings for rotation
├── 📄 requirements.txt   — Pinned Python dependencies
├── 📄 README.md          — This file
├── 📄 LICENSE            — License
├── 📄 scanner.log        — Auto-created: warnings, errors, debug entries
├── 📄 scanned_urls.txt   — Auto-created: deduplication log (capped at 10 000 entries)
└── 📄 report.csv         — Auto-created when you choose to save results
```

---

## 🔐 Security & Ethics

- 🔒 API key input is hidden — never visible in terminal or shell history
- 🔒 API keys are **never** stored on disk or written to logs
- 🤖 **robots.txt is enforced automatically** — URLs disallowed by the target's robots.txt are skipped
- ⚖️ **Use only on systems you own or have explicit written permission to test**
- 📉 Polite random delays between requests minimise Serper.dev quota usage and reduce server load

---

## ⚙️ Configuration

Key tunable constants at the top of `DorkHunter.py`:

| Constant | Default | Description |
|---|---|---|
| `MAX_WORKERS` | `5` | Concurrent scanning threads |
| `MAX_API_PAGES` | `10` | Maximum Serper.dev result pages to consume per dork |
| `DEFAULT_MAX_VULNERABLE_URLS` | `10` | Default cap on vulnerable URLs to find |
| `MAX_SCANNED_URLS` | `10 000` | Maximum entries kept in `scanned_urls.txt` |
| `BOOLEAN_RATIO_THRESHOLD` | `0.15` | SequenceMatcher ratio delta to flag boolean SQLi |
| `BOOLEAN_LENGTH_THRESHOLD` | `50` | Byte-length delta to flag boolean SQLi |
| `TIME_BASED_DELAY` | `5` | Sleep seconds injected into time-based payloads |
| `TIME_BASED_EXTRA_MARGIN` | `2` | Seconds above baseline required to confirm time-based SQLi |
| `DELAY_BETWEEN_REQUESTS` | `(1, 3)` | Random polite delay range between API pages |

---

## 🛠️ Tech Stack

<div align="center"> <img src="https://skillicons.dev/icons?i=py,vscode,github,git" alt="Tech Stack" width="240"/> </div>

---

## 🌟 Contributing

Found a bug? Have an improvement?
1. Fork the repository
2. Create your feature branch
3. Submit a pull request

---

## 📜 License

This project is for **educational purposes only**. Use responsibly and only on systems you are authorised to test.

---

## 📋 Changelog

### Latest
- 🔒 **robots.txt enforcement** — each target's `/robots.txt` is fetched, cached, and respected; disallowed URLs are skipped
- 🔒 **Scanned URL auto-trim** — `scanned_urls.txt` is automatically capped at 10 000 entries on startup to prevent unbounded file growth
- 🐛 **Fixed per-parameter dynamic gate** — `_is_parameter_dynamic()` now runs inside `_test_payloads()` for *each* parameter independently, so a static first param no longer causes an entire URL to be skipped
- 🐛 **Fixed time-based false positives** — baseline response time is measured before injecting sleep payloads; the threshold is `baseline + TIME_BASED_EXTRA_MARGIN` rather than a fixed 4 s
- ⚙️ **Wired verbose / quiet mode** — `-v`/`--verbose` and `-q`/`--quiet` CLI flags control output granularity and DEBUG logging
- ⚙️ **argparse CLI** — proper flag parsing replaces ad-hoc `sys.argv` usage
- ⚙️ **Widened injectable parameter set** — 50+ params now recognised (q, query, keyword, sort, type, lang, ref, …)
- ⚙️ **Configurable detection thresholds** — `BOOLEAN_RATIO_THRESHOLD`, `BOOLEAN_LENGTH_THRESHOLD`, `TIME_BASED_DELAY`, `TIME_BASED_EXTRA_MARGIN` are top-level constants
- ⚙️ **Pinned requirements** — all dependencies now have `>=` version bounds
- 🧹 **Cleaned payloads.txt** — removed irrelevant NoSQL/JSON/LDAP/DOM entries; added stacked-query, PostgreSQL, SQLite, more WAF bypass, and boolean-blind payloads
- 🐛 **Fixed**: `payloads.txt` comment/section-header lines were being sent as live SQL payloads
- 🐛 **Fixed**: SSL fallback used invalid `ssl_context` kwarg — now uses `verify=False` correctly
- 🐛 **Fixed**: `_check_boolean_based()` and `_check_time_based()` called inside payload loop causing massive redundant requests — now once per parameter
- 🐛 **Fixed**: Boolean/time-based payload construction used brittle `split("=", 1)` — now uses `_with_param()` throughout
- 🔄 **Switched search backend** from Google Custom Search API (paid) to Serper.dev (free, no credit card)
- 🔒 **Secure API key input** via `getpass`
- ⚙️ **Added** `MAX_WORKERS` constant for configurable thread pool size
