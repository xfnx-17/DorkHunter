### DorkHunter
Advanced SQL Injection vulnerability scanner using Google dorking techniques

### 🚀 Features

- **Google Custom Search Integration**: Find vulnerable URLs using search dorks (e.g., `inurl:product?id=`)
- **Automated SQLi Testing**: Comprehensive checks for error-based, boolean-based, and time-based SQLi
- **Concurrent Scanning**: Multi-threaded architecture for efficient scanning
- **Smart Detection**: Dynamic parameter analysis and payload rotation
- **CSV Reporting**: Export results for further analysis
- **Stealth Mode**: Randomized delays and user-agent rotation
---
### 📋 Requirements

### 1. Python 3.8+
- [Download Python](https://www.python.org/downloads/)

### 2. Google API Credentials
- Custom Search JSON API Key
- Custom Search Engine (CSE) ID
---
###⚙️ Setup

### 1. Clone Repository
```bash
git clone https://github.com/xfnx-17/DorkHunter.git
cd DorkHunter
```

### 2. Create Virtual Environment
```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows
python -m venv venv
venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure API Credentials
1. Get [Google API Key](https://console.cloud.google.com/)
2. Create [Custom Search Engine](https://cse.google.com/cse/)
3. Run script and enter credentials when prompted

### 🎮 Usage

```bash
python DorkHunter.py
```

**Workflow:**
1. Enter Google API credentials
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

## 📂 File Structure

```
DorkHunter/
├── DorkHunter.py          # Main application
├── requirements.txt       # Dependency list
├── user_agents.txt        # [Optional] User-agent database
├── scanned_urls.txt       # [Optional] Scan history
└── report.csv             # Generated vulnerability report
```

## 🔐 Security Notes

- 🔒 API keys are never stored or transmitted
- ⚠️ Respect robots.txt and website terms of service
- ⚖️ Use only on authorized targets
- 📉 API requests are minimized to reduce Google quota usage

## 🌟 Contributing

Found a bug? Have an improvement?  
1. Fork the repository  
2. Create your feature branch  
3. Submit a pull request

## 📜 License

This project is for educational purposes only. Use responsibly.

**Disclaimer:** The maintainers are not responsible for any misuse of this tool.
---
