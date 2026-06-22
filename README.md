# C2SAST — Sentinel Static Analysis Security Tool

> **Live :** [https://c2sast.onrender.com/](https://c2sast.onrender.com/)

A static application security testing (SAST) tool for C/C++ codebases. Scans source files using the Clang AST and reports 30+ vulnerability types mapped to MITRE CWE categories. Built with a Flask API backend and a glassmorphism-styled single-page frontend.

---

### Situation
Security vulnerabilities in C/C++ codebases — buffer overflows, use-after-free, command injection, and 30+ other CWE-classified flaws — are notoriously hard to catch manually. Developers lacked a fast, self-hosted SAST scanner that could integrate into both CI/CD pipelines and interactive web workflows without requiring a commercial license.

### Task
Build a production-ready SAST tool that:
- Analyzes C/C++ source code via the Clang AST (libclang)
- Detects 30+ vulnerability types with CWE mapping, severity rating, and mitigation guidance
- Provides a web UI for drag-and-drop uploads and visual report rendering
- Exposes a CLI for CI/CD integration (GitHub Actions)
- Supports PDF report export
- Deploys on Render with zero configuration

### Action
- Implemented a Python-based AST walker using `libclang` (`clang.cindex`) that scans for 33 distinct vulnerability patterns including CWE-120 (buffer overflow), CWE-78 (command injection), CWE-416 (use-after-free), CWE-415 (double free), CWE-798 (hardcoded credentials), CWE-190 (integer overflow), and 27 more
- Built a Flask REST API (`/api/analyze`, `/api/register`, `/api/export-pdf`) with JWT authentication and PostgreSQL-backed persistence
- Designed a vanilla HTML/CSS/JS single-page frontend with glassmorphism UI, drag-and-drop upload, expandable vulnerability cards, severity stats, and PDF download
- Created `cli/sast-cli.py` for command-line scans with `--format table|gcc` and `--fail-on` policy enforcement
- Wrote a GitHub Actions workflow (`.github/workflows/sast-scan.yml`) that auto-scans on every push
- Containerized with Docker (Python 3.11-slim + libclang) and deployed on Render

### Result
- **33 vulnerability checks** covering 25+ CWE categories with High/Medium severity ratings, code snippets, and secure-code examples
- Fully functional web app at [c2sast.onrender.com](https://c2sast.onrender.com/) supporting login, file upload, visual report, and PDF export
- CI/CD pipeline that runs the SAST scanner on every commit via GitHub Actions
- CLI tool for local/ad-hoc scanning with configurable exit policies

---

## Features

### Static Analysis Engine
- **Clang AST-based scanning** — parses C/C++ translation units via `libclang`
- **33 vulnerability rules** across 25+ CWE categories:

| CWE | Vulnerability | Severity |
|-----|---------------|----------|
| CWE-120 | Buffer Overflow | High |
| CWE-120 | Potential Buffer Overflow in scanf | Medium |
| CWE-78 | Command Injection | High |
| CWE-134 | Format String Vulnerability | High |
| CWE-22 | Path Traversal | High |
| CWE-798 | Hardcoded Credentials | High |
| CWE-416 | Use-After-Free | High |
| CWE-415 | Double Free | High |
| CWE-480 | Assignment in Condition | High |
| CWE-457 | Use of Uninitialized Variable | High |
| CWE-562 | Return of Stack Address | High |
| CWE-367 | TOCTOU Race Condition | High |
| CWE-190 | Integer Overflow in Allocation | Medium |
| CWE-252 | Unchecked Return Value | Medium |
| CWE-401 | Memory Leak | Medium |
| CWE-772 | Missing fclose | Medium |
| CWE-242 | Inherently Dangerous Function | Medium |
| CWE-783 | Operator Precedence Logic Error | Medium |
| CWE-835 | Infinite Loop | Medium |
| CWE-704 | Suspicious Pointer Cast | Medium |
| CWE-789 | Uncontrolled Memory Allocation | Medium |
| CWE-330 | Insufficiently Random Values | Medium |
| CWE-338 | Weak Random Number Generator | Medium |
| CWE-377 | Insecure Temporary File | Medium |
| CWE-676 | Potentially Dangerous Function | Medium |
| CWE-558 | Use of getlogin() | Medium |
| CWE-467 | sizeof on Pointer Type | Medium |
| CWE-665 | Uninitialized Struct | Medium |
| CWE-193 | Array Index Out of Bounds | Medium |
| CWE-478 | Missing Default Case in Switch | Medium |
| CWE-484 | Omitted Break in Switch Case | Medium |
| CWE-587 | Fixed Address Assignment | Medium |

- Each finding includes: **CWE ID**, **severity**, **line number**, **code snippet**, **explanation**, **mitigation**, and **secure-code example**

### Web Frontend
- **Glassmorphism UI** — dark theme with backdrop blur, gradient accents, and smooth animations
- **Drag-and-drop upload** — supports `.c`, `.cpp`, `.h`, `.hpp`, `.cc` files
- **Interactive report** — severity stats (High/Medium/Low), expandable vulnerability cards, syntax-highlighted code snippets
- **PDF export** — one-click download of scan report
- **Responsive** — works on desktop and tablet

### API Endpoints
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/register` | POST | Create account (returns JWT token) |
| `/api/analyze` | POST | Upload & scan C/C++ file |
| `/api/export-pdf` | POST | Export scan report as PDF |

### CLI Tool
```bash
python cli/sast-cli.py target.c --format table --fail-on high
```
- `--format table` — tabular output
- `--format gcc` — GCC-style error format (CI-friendly)
- `--fail-on high|medium` — exit code policy for pipeline enforcement

### CI/CD Integration
- GitHub Actions workflow (`.github/workflows/sast-scan.yml`)
- Runs automatically on `push` and `pull_request` to `main`
- Scans all `.c`/`.cpp` files in the repository

---

## Quick Start

### Local
```bash
pip install -r requirements.txt
python start.py
# -> http://localhost:5000
```

### Docker
```bash
docker build -t c2sast .
docker run -p 5000:5000 c2sast
```

### Deploy on Render
1. Fork/push this repo to GitHub
2. On [render.com](https://render.com), create a **Web Service**
3. Connect repo, set **Start Command** to `python start.py`
4. Deploy

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, Flask, libclang, ReportLab |
| Frontend | Vanilla HTML/CSS/JS, Google Fonts |
| Database | PostgreSQL (optional, SQLite fallback) |
| Auth | JWT (Flask-JWT-Extended) |
| CI/CD | GitHub Actions |
| Container | Docker |
| Deployment | Render |
