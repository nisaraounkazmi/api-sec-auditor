# API-SecLens: Automated Security Audit & Header Scanner

A lightweight command-line security auditing utility written in Python designed to inspect web endpoints and APIs for common application security misconfigurations, missing headers, and information disclosure vulnerabilities.

## Features

- **Security Header Inspection:** Audits targets for critical missing headers:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options` (Clickjacking protection)
  - `X-Content-Type-Options` (MIME-sniffing defense)
- **Technology & Information Disclosure:** Flags verbose headers like `Server`, `X-Powered-By`, or `X-AspNet-Version` that leak backend stack data.
- **CORS Configuration Analysis:** Evaluates `Access-Control-Allow-Origin` policies to detect insecure wildcards or overly permissive setups.
- **Color-Coded CLI Output:** Provides clear status indicators (`[✔]` for secure, `[✘]` for missing, `[!]` for warnings) for rapid security analysis.

## Tech Stack
- **Language:** Python
- **Libraries:** `requests`, `colorama`, `urllib3`

## Installation & Usage

1. Clone the repository:
   ```bash
   git clone [https://github.com/nisaraoun514/api-sec-auditor.git](https://github.com/nisaraoun514/api-sec-auditor.git)
   cd api-sec-auditor
