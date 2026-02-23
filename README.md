# DorkHunter
Advanced SQL Injection vulnerability scanner using Google dorking techniques, powered by [Serper.dev](https://serper.dev) (free, no credit card required).

### 🚀 Features

- **Serper.dev Search Integration**: Find vulnerable URLs using Google dorks via Serper.dev (free, no credit card) — e.g., `inurl:product?id=`
- **Automated SQLi Testing**: Comprehensive checks for error-based, boolean-based, and time-based SQLi
- **Concurrent Scanning**: Multi-threaded architecture for efficient scanning (configurable `MAX_WORKERS`)
- **Smart Detection**: Dynamic parameter analysis and payload rotation
- **Secure API Key Input**: Key is hidden while typing (uses `getpass`)
- **CSV Reporting**: Export results for further analysis
- **Stealth Mode**: Randomized delays and user-agent rotation
---
## 📋 Requirements

### 1. Python 3.8+
- [Download Python](https://www.python.org/downloads/)

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
#### Linux/macOS
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

### 4. Configure API Key
1. Sign up at [https://serper.dev](https://serper.dev) (free, no credit card)
2. Copy your API key from the Serper.dev dashboard
3. Run the script and paste your key when prompted

## 🎮 Usage

```bash
python DorkHunter.py
```

**Workflow:**
1. Enter your Serper.dev API key (input is hidden for security)
2. Input search dork (e.g., `inurl:login.php?id=`)
3. Set maximum vulnerable URLs to find
4. Choose to save results (CSV report)
5. Review detected vulnerabilities

**Example Output:**
```text
██████╗  ██████╗ ██████╗ ██╗  ██╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
██╔══██╗██╔═══██╗██╔══██╗██║ ██╔╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██║  ██║██║   ██║██████╔╝█████╔╝ ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██║  ██║██║   ██║██╔══██╗██╔═██╗ ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██████╔╝╚██████╔╝██║  ██║██║  ██╗██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

DorkHunter by xfnx

[+] Found 2 vulnerable URLs:
1. http://vuln-site.com/product?id=1'--
2. http://test-store.com/user?id=2' WAITFOR DELAY '0:0:5'--
```

### 📂 File Structure

```
📂 DorkHunter/
├── 📄 DorkHunter.py                             - Main scanner script
├── 📄 LICENSE                                   - MIT/GPL? License file  
├── 📄 README.md                                 - Documentation
├── 📄 payloads.txt                              - SQLi payload database
├── 📄 requirements.txt                          - Python dependencies
└── 📄 user_agents.txt                           - Browser signature rotations
```

## 🔐 Security Notes

- 🔒 API key input is hidden (never visible in terminal history)
- 🔒 API keys are never stored or logged to disk
- ⚠️ Respect robots.txt and website terms of service
- ⚖️ Use only on authorized targets
- 📉 API requests are minimized to reduce Serper.dev quota usage

## 🛠️ Tech Stack

<div align="center"> <img src="https://skillicons.dev/icons?i=py,vscode,github,git" alt="Tech Stack" width="240"/> </div>

## 📊 GitHub Stats

<div align="center"> <img width="300" src="https://github-readme-stats.vercel.app/api/top-langs/?username=xfnx-17&layout=compact&theme=transparent&hide_border=true" alt="Top Languages"> </div>

## 🌟 Contributing

Found a bug? Have an improvement?  
1. Fork the repository  
2. Create your feature branch  
3. Submit a pull request

## 📜 License

This project is for educational purposes only. Use responsibly.

---

## 📋 Changelog

### Latest
- 🔄 **Switched search backend** from Google Custom Search API (paid) to [Serper.dev](https://serper.dev) (free, no credit card)
- 🔒 **Secure API key input** — key is now hidden while typing using `getpass`
- 🐛 **Fixed**: `payloads.txt` comment/section-header lines were being sent as live SQL payloads
- 🐛 **Fixed**: SSL fallback request used an invalid `ssl_context` kwarg that caused a silent `TypeError` — now uses `verify=False` correctly
- 🐛 **Fixed**: `_check_boolean_based()` and `_check_time_based()` were called inside the payload loop, causing massive redundant requests — now called once per parameter
- 🐛 **Fixed**: Boolean and time-based payload construction used brittle `split("=", 1)` that broke on URLs with `=` in values — now uses `_with_param()` directly
- 🐛 **Fixed**: Dead code `_build_test_url()` removed
- 🐛 **Fixed**: `from difflib import SequenceMatcher` was nested inside a method — moved to top-level imports
- ⚙️ **Added** `MAX_WORKERS` constant for configurable thread pool size


