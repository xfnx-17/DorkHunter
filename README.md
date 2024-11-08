# SQLi Search Tool

## 🚀 Features

- **Google Custom Search Integration**: Use Google's Custom Search API to find potentially vulnerable URLs via dorks (e.g., `inurl:product?id=`).
- **Automated SQL Injection Testing**: Automatically checks URLs for common SQL injection vulnerabilities.
- **Multi-threading Support**: Speeds up the scanning process by testing multiple URLs concurrently.
- **DNS Resolution**: Validates domain names using Google's public DNS servers.
- **CSV Report Generation**: Optionally save the list of vulnerable URLs to a CSV file.
- **User-Agent Rotation**: Prevents detection by rotating user-agent strings for each request.

## 📋 Requirements

To run this tool, you'll need the following:

1. **Python 3.x**
   - Download and install Python from [python.org/downloads](https://python.org/downloads).

2. **Create a Python Virtual Environment (Recommended)**
   To isolate dependencies:
   ```bash
   cd /path/to/your/project
   python3 -m venv (name) 
   ex.=> python3 -m venv test

    Activate the Virtual Environment:
        On Windows:

venv\Scripts\activate

On Linux/macOS:

        source (name)/bin/activate 
        ex.=> source test/bin/activate

    Install Required Libraries

pip install -r requirements.txt

Or manually:

    pip install requests dnspython

    Google Custom Search API Key & CSE ID
    #You can get these from the GOOGLE CUSTOM SEARCH ENGINE and the GOOGLE CLOUD CONSOLE.
        Get your API key.
        Create a Custom Search Engine (CSE) and get your CSE ID.

    Optional Files for Enhanced Functionality:
        user_agents.txt: List of user-agents for rotation (optional).
        scanned_urls.txt: Track scanned URLs (optional).

⚙️ Setup
1. Clone or Download the Repository

Clone the repo using Git:

git clone <repository-url>
cd SQLiS

Alternatively, you can download the Python script directly and place it in your desired directory.
2. Configure API Key and CSE ID

On first run, you'll be prompted to input your Google API key and CSE ID.
🎮 Usage
Running the Tool

To start the tool, run:

python SQLiS.py

Steps:

    Enter API Key and CSE ID: You'll be asked to provide your Google API key and Custom Search Engine ID.

    Enter Dork: Enter the search dork to find potential vulnerable URLs (e.g., inurl:login.php?id=).

    Set Maximum Vulnerable URLs: Specify the maximum number of vulnerable URLs to find.

    Save the Report (Optional): You can choose to save the results to a CSV file.

    View Results: Vulnerable URLs will be displayed in the terminal. If you chose to save the results, they will be saved in report.csv.

    Re-run or Exit: After the scan, choose to run another search or exit.

Example Output:

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

      SQLi Search Tool
      by => xfnx

xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

Before using the tool, you must provide your Google Custom Search API key and Custom Search Engine ID.

Your Google Custom Search API key: <input>
Your Google Custom Search Engine ID: <input>

Dork (example="inurl:product?id="): inurl:login.php?id=
Max Vuln (Number): 5
Want the result to be saved (Y/N): Y

Scanning started...
[VULNERABLE] Vulnerable URLs found:
http://example.com/login.php?id=1
http://example.com/login.php?id=2

Results saved to report.csv


📂 Files

    SQLiS.py: Main script for SQLi Search.
    requirements.txt: List of required Python libraries.
    user_agents.txt: (Optional) List of user-agent strings for rotating requests.
    scanned_urls.txt: (Optional) Track URLs already scanned.
    report.csv: (Optional) Saved CSV report of vulnerable URLs.

🔐 Security Considerations

    API Key Protection: To avoid exposing your API key in the code, store sensitive credentials in environment variables instead of hardcoding them in the script.
    Google API Limits: Be mindful of rate limits for Google Custom Search API. Check your usage in the Google Cloud Console.

🌱 Contributing

We welcome contributions! If you find bugs or would like to suggest improvements, feel free to open an issue or create a pull request.
📜 License

This tool is provided as-is for educational and testing purposes. The author assumes no responsibility for any misuse or legal consequences from using this tool. Always ensure you have permission before scanning any website.

    No warranty: This tool is provided with no warranty, expressed or implied.
    Responsible use: Please follow ethical guidelines and laws while using this tool.

💡 Tips for Customizing or Extending the Program

    Custom Dorks: Modify the search queries to target other types of vulnerabilities or weaknesses.
    Extend Payloads: Add more SQL injection payloads in the check_vulnerability function.
    Enhanced Reporting: Include more details in reports, such as payloads used, server responses, etc.

🛠️ Troubleshooting

    API Limits: If the Google API fails, ensure you're within the usage limits. Check the Google Cloud Console.
    No Vulnerable URLs Found: Double-check your dork query to ensure it's valid and applicable to the target website.
