# VulnHawk - Web Security Scanner

VulnHawk is a comprehensive web security scanning tool designed to detect and report vulnerabilities in web applications. It combines automated scanning capabilities with AI-enhanced analysis to provide actionable insights for improving web application security.

---

## Table of Contents

- [Project Overview](#project-overview)
- [Features](#features)
- [Application Architecture](#application-architecture)
  - [Backend Components](#backend-components)
  - [Frontend Components](#frontend-components)
- [Key Security Checks](#key-security-checks)
  - [Security Header Analysis](#security-header-analysis)
  - [SSL/TLS Assessment](#ssltls-assessment)
  - [Vulnerability Testing](#vulnerability-testing)
- [Usage Instructions](#usage-instructions)
  - [Running VulnHawk](#running-vulnhawk)
  - [PDF Analysis & AI-Enhanced Assessment](#pdf-analysis--ai-enhanced-assessment)
- [Technical Requirements](#technical-requirements)
- [License](#license)
- [Contributing](#contributing)

---

## Project Overview

VulnHawk is a full-stack web application that allows users to scan websites for common vulnerabilities, generate detailed security reports, and visualize security scores. The platform features:

- Automated vulnerability scanning for SQL Injection, XSS, and insecure forms
- Security header and SSL/TLS analysis
- Technology stack detection
- AI-powered PDF analysis of security reports
- User-friendly interface for scanning and report visualization

---

## Features

- **Comprehensive Security Scanning:** Detects common web vulnerabilities and misconfigurations.
- **SSL/TLS Assessment:** Checks certificate validity, supported protocols, and cipher suites.
- **Security Header Analysis:** Ensures essential security headers are configured correctly.
- **Technology Detection:** Identifies frameworks, servers, and libraries used by the target.
- **Report Generation:** Generates detailed PDF reports with security scores and findings.
- **AI-Enhanced Analysis:** Uses OpenAI GPT models to analyze vulnerabilities from uploaded PDF reports.

---

## Application Architecture

VulnHawk follows a client-server architecture with the following components:

### Backend Components

#### Main Security Scanner

Handles core scanning and vulnerability detection:

- **Security Header Analysis:** Detects missing headers like Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, and more.
- **SSL/TLS Assessment:** Validates certificates, checks for insecure protocols (TLS 1.0/1.1), and evaluates cipher suites.
- **Configuration Analysis:** Identifies misconfigurations in HTTP settings.
- **Vulnerability Detection:**
  - SQL Injection testing (basic syntax, authentication bypass, union-based, and destructive payloads)
  - Cross-Site Scripting (XSS) detection (DOM-based, event handler injections, JavaScript URI payloads)
  - Form vulnerability analysis
- **Technology Detection:** Identifies the web stack, server, and frameworks in use.

**API Endpoints:**

- `GET /` - Serves the frontend application
- `GET /<path:filename>` - Serves static files
- `POST /scan` - Initiates a security scan and returns a comprehensive assessment

#### PDF Analysis Service

Performs AI-enhanced analysis of uploaded PDF reports:

- **PDF Text Extraction:** Extracts content from security reports.
- **AI Analysis:** Leverages OpenAI GPT to evaluate vulnerabilities and provide actionable insights.
- **Memory-Efficient Processing:** Handles large PDF files efficiently.

**API Endpoint:**

- `POST /api/upload-pdf` - Uploads PDF and returns AI-generated vulnerability analysis.

---

### Frontend Components

- **Report Generation:** Uses `jsPDF` to generate downloadable PDF reports.
- **Security Score Calculation:** Computes scores based on detected issues.
- **UI Features:**
  - Summary of scan results
  - Color-coded security indicators
  - Circular progress visualization for security scores
  - Downloadable PDF reports

---

## Key Security Checks

### Security Header Analysis

VulnHawk checks for critical headers:

- `Strict-Transport-Security` – Enforces HTTPS
- `Content-Security-Policy` – Mitigates XSS and injection attacks
- `X-Frame-Options` – Prevents clickjacking
- `X-Content-Type-Options` – Prevents MIME sniffing
- `Referrer-Policy` – Controls referrer information

### SSL/TLS Assessment

- Certificate validation and expiration check
- Protocol support analysis (TLS 1.0/1.1 detection)
- Cipher suite evaluation
- Security best practice verification

### Vulnerability Testing

#### SQL Injection

Tests URL parameters and form inputs with payloads like:

- Basic SQL syntax: `'` or `"`
- Authentication bypass: `' OR '1'='1`
- Union-based attacks: `' UNION SELECT 1,2,3 --`
- Database manipulation: `1'; DROP TABLE users; --`

#### Cross-Site Scripting (XSS)

- Script injection: `<script>alert(1)</script>`
- Event handler injection: `<img src=x onerror=alert(1)>`
- JavaScript URI payloads: `javascript:alert(1)`
- DOM-based injection vectors

#### Form Vulnerability Analysis

- Tests form fields with malicious payloads
- Detects reflected and unsanitized input

---

## Usage Instructions

### Running VulnHawk

1. Enter the target URL in the input field.
2. Click **Scan** to initiate the security assessment.
3. Review results:
   - Security score
   - Missing headers
   - Detected vulnerabilities
   - SSL/TLS issues
   - Technology stack

### PDF Analysis & AI-Enhanced Assessment

1. Upload a PDF report (max 2MB) via the AI analysis endpoint.
2. VulnHawk extracts text and evaluates vulnerabilities.
3. Review AI-generated recommendations and insights.

---

## Technical Requirements

**Backend:**

- Python 3.6+
- Flask framework
- Required Python packages:
  - `requests`
  - `beautifulsoup4`
  - `PyPDF2`
  - `openai`
  - `python-dotenv`
  - `flask-cors`
  - `OpenSSL`

**Frontend:**

- HTML5, CSS3, JavaScript
- `jsPDF` library for PDF generation

---


> VulnHawk combines automated scanning with AI-powered insights to provide a holistic view of web application security, helping developers and security professionals strengthen their security posture.
