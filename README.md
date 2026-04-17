# XSS Scanner

An automated Cross-Site Scripting (XSS) vulnerability scanner built with Python and Selenium. Detects **reflected**, **stored**, and **DOM-based** XSS across all input fields on a target web page.

> ⚠️ **For authorized security testing only.** Do not use against systems you do not own or have explicit written permission to test.

---

## Features

- ✅Detects **Reflected**, **Stored**, and **DOM-based** XSS
- ✅ Automatically groups fields by parent `<form>` and tests them together
- ✅ Deep browser instrumentation (MutationObserver, XHR/fetch interception, `eval` hooking)
- ✅ Session-scoped unique markers to avoid false positives from previous runs
- ✅ JSON reports + screenshots saved for every finding
- ✅ Optional login support for authenticated scanning
- ✅ 80+ payloads (silent flag-based + alert-based)

---

## Requirements

- Python 3.8+
- Google Chrome
- ChromeDriver (matching your Chrome version) → [chromedriver.chromium.org](https://chromedriver.chromium.org/)

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/xss-scanner.git
cd xss-scanner
pip install -r requirements.txt
```

---

## Configuration

Copy the example config and fill in your target details:

```bash
cp config.example.json config.json
```

Edit `config.json`:

```json
{
  "target_url": "https://your-target.com",
  "stored_check_url": null,
  "login": {
    "url": "",
    "email_field_id": "",
    "password_field_id": "",
    "submit_btn_id": "",
    "email": "",
    "password": ""
  }
}
```

> Credentials are read from `config.json` and never hardcoded. Keep this file out of version control (it's in `.gitignore`).

---

## Usage

```bash
# Basic scan
python scanner.py --url https://your-target.com

# With config file (supports login + stored XSS URL)
python scanner.py --config config.json

# Headless mode (no browser window)
python scanner.py --url https://your-target.com --headless

# Save output to custom folder
python scanner.py --url https://your-target.com --output my_results
```

---

## Output

Results are saved in the output folder (default: `xss_scan_results/`):

```
xss_scan_results/
├── report_form_0_<payload>_<timestamp>.json
├── screenshot_form_0_<payload>_<timestamp>.png
└── ...
```

Each JSON report contains:
- Payload used
- Detection vector (reflected / stored / DOM)
- Session marker
- Monitor data (injected scripts, eval calls, alerts)
- Screenshot path

---

## Detection Vectors

| Vector | How it works |
|---|---|
| **Reflected** | Checks DOM and JS state immediately after form submission |
| **Stored** | Re-visits the page after submission and checks if payload persists |
| **DOM** | MutationObserver + `eval`/`Function()` hooks detect silent JS execution |

---

## Tested On

- [DVWA](https://github.com/digininja/DVWA) (Damn Vulnerable Web Application)
- [HackTheBox](https://www.hackthebox.com/) web challenges
- [TryHackMe](https://tryhackme.com/) rooms

---

## License

MIT — see [LICENSE](LICENSE)
# XSS
