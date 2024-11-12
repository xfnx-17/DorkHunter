# DorkHunter

## 🚀 Features

- **Google Custom Search Integration**: Utilizes Google's Custom Search API to find potentially vulnerable URLs using search dorks (e.g., `inurl:product?id=`).
- **Automated SQL Injection Testing**: Automatically checks URLs for common SQL injection vulnerabilities.
- **Multi-threading Support**: Speeds up the scanning process by testing multiple URLs concurrently.
- **DNS Resolution**: Verifies domain names using Google's public DNS servers to ensure the validity of URLs.
- **CSV Report Generation**: Optionally saves the list of vulnerable URLs to a CSV file for further analysis.
- **User-Agent Rotation**: Prevents detection by rotating user-agent strings for each request.

## 📋 Requirements

Before running the tool, ensure you have the following:

1. **Python 3.x**
   - Download and install Python from [python.org/downloads](https://python.org/downloads).

Sure! Here's just **step 2** from the **`README.md`**, where I provide the separate setup instructions for **Windows** and **Linux/macOS**:

---

### 2. Set Up Python Virtual Environment(Recommended)

#### **For Linux/macOS:**

In your terminal, create a virtual environment and activate it:

```bash
python3 -m venv Dorkhunter
source Dorkhunter/bin/activate  # On Linux/macOS
```

#### **For Windows:**

In your Command Prompt or PowerShell, create a virtual environment and activate it:

```bash
python -m venv Dorkhunter
Dorkhunter\Scripts\activate  # On Windows
```

---

This should help users set up the virtual environment depending on their operating system! Let me know if you need any further changes.

   ```

3. **Install Dependencies**
   Install the required libraries by running:
   ```bash
   pip install -r requirements.txt
   ```
   Alternatively, install manually:
   ```bash
   pip install requests dnspython google-api-python-client
   ```

4. **Google Custom Search API Key & CSE ID**
   - Get your **API key** from the [Google Cloud Console](https://console.cloud.google.com/).
   - Create a **Custom Search Engine (CSE)** at [Google Custom Search](https://cse.google.com/cse/) and get your **CSE ID**.

5. **Optional Files for Enhanced Functionality**:
   - `user_agents.txt`: A list of user-agent strings for rotating requests (optional).
   - `scanned_urls.txt`: A file to keep track of URLs that have already been scanned (optional).

---

## ⚙️ Setup

1. **Clone or Download the Repository**

   Clone the repository using Git:
   ```bash
   git clone https://github.com/xfnx-17/DorkHunter.git
   cd Dorkhunter
   ```

   Alternatively, you can download the Python script (`Dorkhunter.py`) directly and place it in your desired directory.

2. **Configure Google API Key and CSE ID**

   On your first run, you will be prompted to enter your Google Custom Search API Key and CSE ID.

---

## 🎮 Usage

### Running the Tool

To start the tool, run the following command:

```bash
python DorkHunter.py
```

### Workflow:
1. **Enter Google API Key & CSE ID**: When prompted, provide your Google API key and Custom Search Engine ID.
   
2. **Enter Dork**: Input a Google search dork to find potential vulnerable URLs (e.g., `inurl:login.php?id=`).

3. **Set Maximum Vulnerable URLs**: Specify the maximum number of vulnerable URLs you want to find.

4. **Save the Report (Optional)**: Choose if you would like to save the results to a CSV file for later use.

5. **View Results**: Vulnerable URLs will be displayed in the terminal. If you chose to save the results, they will be saved in `report.csv`.

6. **Re-run or Exit**: After the scan completes, you can choose to run another search or exit the tool.

### Example Output:

```bash
xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

      DorkHunter
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
```

---

## 📂 Files

- **DorkHunter.py**: Main script for SQLi Search.
- **requirements.txt**: List of required Python libraries.
- **user_agents.txt**: (Optional) A list of user-agent strings for rotating requests.
- **scanned_urls.txt**: (Optional) Tracks URLs that have already been scanned.
- **report.csv**: (Optional) Saved CSV report of vulnerable URLs.

---

## 🔐 Security Considerations

- **API Key Protection**: Always keep your Google API key secret. It's recommended to store sensitive credentials in environment variables instead of hardcoding them into the script.
- **Google API Limits**: Be mindful of rate limits for the Google Custom Search API. Check your usage and limits in the [Google Cloud Console](https://console.cloud.google.com/).
- **Responsible Use**: Always ensure you have permission to scan the websites you're testing. Use this tool ethically and in accordance with the law.

---

## 🌱 Contributing

We welcome contributions! If you find bugs or have suggestions for improvements, feel free to open an issue or create a pull request.

---

## 📜 License

This tool is provided "as-is" for educational and testing purposes only. The author assumes no responsibility for any misuse or legal consequences from using this tool. Always ensure you have permission before scanning any website.

**No warranty**: This tool is provided with no warranty, express or implied.

**Responsible Use**: Follow ethical guidelines and laws while using this tool.

---

## 💡 Tips for Customizing or Extending the Program

- **Custom Dorks**: Modify the search queries to target different types of vulnerabilities (e.g., `inurl:admin.php?id=` or `inurl:product=ID`).
- **Extend Payloads**: Add more SQL injection payloads in the `test_sqli()` function to test for additional injection techniques.
- **Enhanced Reporting**: Include more details in reports, such as payloads used, server responses, or headers.

---

## 🛠️ Troubleshooting

- **API Limits**: If the Google API fails, make sure you're within the usage limits by checking the Google Cloud Console.
- **No Vulnerable URLs Found**: Ensure that your dork query is valid and properly formatted. If necessary, adjust the search term to ensure it is applicable to the target website.

---

This **SQLi Search Tool** is provided to help identify common SQL injection vulnerabilities. Always use it responsibly and within the boundaries of the law.

---
