# 🧠 GenAI CVE Analyzer for SLES15 SP3

An AI-powered tool to automate the analysis and remediation of Common Vulnerabilities and Exposures (CVEs) by mapping affected packages and providing fixed versions for SUSE Linux Enterprise Server (SLES) 15 SP3.

## 🔍 What It Does

- Accepts CVE input via CSV upload or manual text entry.
- Crawls and analyzes CVE data intelligently using `crawl4ai`.
- Maps each CVE to impacted packages and their fixed versions.
- Outputs:
  - A **human-readable** grouped platform based view.
  - A **build-ready** `update_packages.json` file with fixed package versions (only for packages present in your product).

## ✅ Key Features

- ⚡ **Fast**: Analyze hundreds of CVEs in seconds.
- 🧠 **AI-Powered**: Uses intelligent parsing to crawl and summarize CVE details.
- 🔒 **Accurate**: Only updates packages that already exist in your product.
- 🛠️ **Actionable**: Outputs a ready-to-use package version list for product rebuilds.

## 📦 Requirements

## Install the dependencies with:
pip install -r requirements.txt

## 🚀 How to Run
Run the Streamlit app:

streamlit run app.py
Then upload a CSV file containing CVEs (with columns like CVE_ID, Package_Affected, and Fixed_Version) or enter CVEs manually.

## 📂 File Structure

.
├── app.py                   # Main Streamlit UI
├── updated_packages.py      # Logic to update existing product packages
├── product/packages.json    # Original product package list
├── update_packages.json     # Auto-generated updated package list
├── cve_summary.csv          # Flattened CVE summary
├── requirements.txt         # Python dependencies
└── README.md

## 📤 Output
After analyzing, you get:

YAML-style CVE breakdowns grouped by platform and ID.

update_packages.json – only includes existing packages from your product with updated fixed versions.

## 📌 Example

[
  {
    "pkg_name": "curl",
    "version": "7.66.0-150200.4.84.1"
  },
  {
    "pkg_name": "libcurl4",
    "version": "7.66.0-150200.4.84.1"
  }
]
