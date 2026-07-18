<div align="center">

<img src="assets/cyber-neo-hero.png" alt="Cyber Neo — Claw'd, the open-source cybersecurity mascot, holding a green padlock shield" width="820">

# CYBER NEO

### The Open-Source Cybersecurity Agent for Claude Code

**Protect your apps. Protect your users. Protect your community.**

[![License: MIT](https://img.shields.io/badge/License-MIT-00ff41.svg)](https://opensource.org/licenses/MIT)
[![OWASP 2025](https://img.shields.io/badge/OWASP-2025%20Top%2010-00ff41.svg)](https://owasp.org/www-project-top-ten/)
[![CWE Top 25](https://img.shields.io/badge/CWE-Top%2025%20(2025)-00ff41.svg)](https://cwe.mitre.org/top25/)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Skill-00ff41.svg)](https://claude.ai/code)
[![Community](https://img.shields.io/badge/Community-tododeia.com-00ff41.svg)](https://tododeia.com)
[![Instagram](https://img.shields.io/badge/Shipped%20by-@soyenriquerocha-E4405F.svg?logo=instagram&logoColor=white)](https://instagram.com/soyenriquerocha)

---

*Shipped by [@soyenriquerocha](https://instagram.com/soyenriquerocha) | Built by the [Tododeia](https://tododeia.com) community — empowering developers to ship secure software.*

</div>

---

## What is Cyber Neo?

**Cyber Neo** is a comprehensive cybersecurity analysis agent that runs inside [Claude Code](https://claude.ai/code). Point it at any project on your computer, and it performs a deep security audit — scanning your code, dependencies, secrets, infrastructure, and supply chain for vulnerabilities. It generates a professional, prioritized report with actionable remediation guidance so you can fix issues before they become incidents.

**No security expertise required.** Just run `/cyber-neo` and let the agent do the work.

Cyber Neo was built with a mission: our community at [tododeia.com](https://tododeia.com) is building apps, tools, and products. We want to help every developer in the community protect what they're building. This agent is our contribution — open source, free, and designed to be the most thorough security scanner available as a Claude Code skill.

---

## Why Cyber Neo?

Most security tools require installation, configuration, and expertise to interpret results. Cyber Neo is different:

| Traditional Security Tools | Cyber Neo |
|---|---|
| Require installation and setup | Works instantly as a Claude Code skill |
| Need security expertise to interpret | Plain-language findings with code-level remediation |
| Scan one category (SAST *or* SCA *or* secrets) | Scans **11 categories** in one run |
| Output raw findings without context | CWE/OWASP-classified findings with fix examples |
| Run sequentially | **5 parallel subagents** for speed |
| Require paid licenses for full coverage | **100% free and open source** |

---

## What It Scans

<div align="center"><img src="assets/claw-d-scanner.png" alt="Claw'd inspecting code with a magnifying glass and spotting a bug" width="280"></div>

Cyber Neo covers **11 security domains** across every major vulnerability class:

| # | Category | What It Finds | How |
|---|----------|--------------|-----|
| 1 | **Code Security (SAST)** | SQL injection, XSS, command injection, code injection, path traversal, SSRF, deserialization, prototype pollution | Semgrep (optional) + Claude-native pattern analysis |
| 2 | **Authentication & Authorization** | Missing auth middleware, JWT misconfigurations, broken access control, IDOR, session management flaws, missing RBAC | Claude-native analysis using `auth-authz-patterns.md` |
| 3 | **Cryptographic Security** | Weak algorithms (MD5, SHA1, DES, RC4), hardcoded keys/IVs, TLS bypass, insecure random, weak key lengths | Claude-native analysis using `crypto-patterns.md` |
| 4 | **Secret Detection** | 60+ regex patterns: AWS, GCP, Azure, GitHub, Slack, Stripe, database credentials, private keys, API keys, JWT tokens, .env files | Python batch scanner + Gitleaks (optional) |
| 5 | **Dependency Vulnerabilities (SCA)** | Known CVEs in npm, pip, cargo, bundler, composer, and Go dependencies | Trivy / npm audit / pip-audit / cargo-audit (optional) |
| 6 | **Web Security** | Missing security headers (CSP, CORS, HSTS), CSRF, cookie flags, file upload flaws, open redirects | Claude-native analysis using `web-security-patterns.md` |
| 7 | **Supply Chain Security** | Lock file integrity, dependency confusion, typosquatting, unpinned versions, malicious packages | Python lockfile checker + Claude-native analysis |
| 8 | **CI/CD Security** | GitHub Actions script injection, overly permissive permissions, unpinned actions, secret exposure in workflows | Claude-native analysis using `cicd-security.md` |
| 9 | **Docker & Container Security** | Root user, unpinned base images, secrets in layers, privileged containers, Docker socket exposure | Claude-native analysis using `iac-docker.md` |
| 10 | **Error Handling** | Debug mode in production, stack trace exposure, empty catch blocks, missing error boundaries | Claude-native analysis using `error-handling-patterns.md` |
| 11 | **Logging Security** | Sensitive data in logs, log injection, missing security event logging | Claude-native analysis using `logging-patterns.md` |

### Standards Coverage

Cyber Neo maps every finding to industry standards:

- **All 10 OWASP 2025 Top 10 categories** — including the two new entries: *A03 Software Supply Chain Failures* and *A10 Mishandling of Exceptional Conditions*
- **15+ CWE Top 25 (2025) items** — XSS, SQLi, CSRF, command injection, SSRF, deserialization, path traversal, missing auth, broken crypto, hardcoded credentials, and more
- **CVSS-aligned severity scoring** — Critical (9.0-10.0), High (7.0-8.9), Medium (4.0-6.9), Low (1.0-3.9), Info (0.0-0.9)

---

## Supported Languages & Frameworks

| Language | Frameworks | Reference File |
|----------|-----------|---------------|
| **JavaScript / TypeScript** | Express, Next.js, React, Vue, Angular, Fastify, NestJS, Koa, Electron | `lang-javascript.md` (924 lines) |
| **Python** | Django, Flask, FastAPI, Tornado, Starlette | `lang-python.md` (935 lines) |
| **Any language** | Generic SAST patterns (eval, exec, hardcoded creds, command injection) | Built into SKILL.md |

> **Coming in v0.2:** Go, Ruby/Rails, Java/Spring, Rust, PHP/Laravel

---

## Installation

### Option 1: Clone to Skills Directory (Recommended)

```bash
cd ~/.claude/skills
git clone https://github.com/Hainrixz/cyber-neo.git
```

That's it. Claude Code automatically discovers the skill.

### Option 2: Symlink from Any Location

```bash
git clone https://github.com/Hainrixz/cyber-neo.git ~/projects/cyber-neo
ln -s ~/projects/cyber-neo ~/.claude/skills/cyber-neo
```

### Option 3: Claude Code Plugin Marketplace

```
/plugin install cyber-neo
```

> *Marketplace availability coming soon.*

### Verify Installation

Open Claude Code and type:

```
/cyber-neo
```

If installed correctly, Cyber Neo will ask you for a project path to scan.

---

## Usage

### Basic Scan

```bash
# Scan a specific project
/cyber-neo /path/to/your/project

# Scan the current working directory
/cyber-neo .
```

### What Happens When You Run It

```
 Phase 1: Reconnaissance
   Detects your tech stack, frameworks, and infrastructure
   Estimates project scope and applies scanning tier

 Phase 2-6: Parallel Analysis (5 subagents)
   Dependency vulnerabilities (SCA)
   Code security patterns (SAST)
   Secret detection (60+ regex patterns)
   Configuration & infrastructure checks
   Supply chain & CI/CD security

 Phase 7: Report Generation
   Deduplicates, scores, and classifies findings
   Generates professional security report
```

### Output

The report is saved to your Desktop:

```
~/Desktop/cyber-neo-report-{project-name}-{YYYY-MM-DD}.md
```

---

## Report Format

Every Cyber Neo report includes:

### Executive Summary

```markdown
Risk Score: 67/100 (High Risk)

| Severity | Count |
|----------|-------|
| Critical | 2     |
| High     | 5     |
| Medium   | 8     |
| Low      | 3     |
| Info     | 4     |

Top 3 Priority Actions:
1. Fix SQL injection in src/api/users.js:42 — use parameterized queries
2. Rotate leaked AWS key in .env — key is active and exposed
3. Add authentication to /api/admin routes — currently public
```

### Detailed Findings

Each finding includes:

```markdown
[CN-001] SQL Injection in User Query
 Severity: Critical (CVSS ~9.8)
 CWE: CWE-89 (SQL Injection)
 OWASP: A05:2025 (Injection)
 Location: src/api/users.js:42

 Description: User input is directly concatenated into SQL query
 without parameterization, enabling SQL injection attacks.

 Evidence:
   const query = `SELECT * FROM users WHERE id = ${req.params.id}`;

 Remediation:
   const query = 'SELECT * FROM users WHERE id = $1';
   const result = await db.query(query, [req.params.id]);
```

### Additional Sections

- **Dependency Vulnerabilities** — Table of CVEs with package names, versions, and fix versions
- **Supply Chain Assessment** — Lock file status, dependency pinning, CI/CD pipeline security
- **Scan Metadata** — Files scanned, coverage percentage, tools used, scan duration

---

## How It Works — Architecture Deep Dive

<div align="center"><img src="assets/claw-d-architecture.png" alt="Claw'd analyzing code on a terminal showing a passing check" width="280"></div>

Cyber Neo is built as a Claude Code **skill** — a markdown-based prompt that orchestrates Claude's analysis capabilities. The architecture has three layers:

### Layer 1: SKILL.md — The Orchestration Engine

The `SKILL.md` file (563 lines) is the brain of Cyber Neo. It contains:

- **7-phase analysis pipeline** with explicit instructions for each phase
- **Subagent dispatch templates** for parallel analysis
- **Severity scoring rubric** aligned with CVSS
- **Report generation instructions** with deduplication and classification rules
- **Safety constraints** (read-only iron law) reinforced in every subagent prompt
- **Edge case handling** for empty projects, unsupported languages, and large codebases

### Layer 2: Reference Files — The Security Knowledge Base

14 reference files totaling **10,000+ lines** of security patterns:

```
references/
├── owasp-top-10.md            # OWASP 2025 classification + scoring guide
├── cwe-top-25.md              # CWE mappings with detection patterns
├── secrets-patterns.md        # 60+ regex patterns for secret detection
├── auth-authz-patterns.md     # JWT, sessions, RBAC, IDOR patterns
├── crypto-patterns.md         # Weak crypto, hardcoded keys, TLS bypass
├── web-security-patterns.md   # Headers, CORS, CSRF, SSRF, uploads, redirects
├── error-handling-patterns.md # Debug mode, stack traces, empty catches
├── logging-patterns.md        # Sensitive data in logs, log injection
├── cicd-security.md           # GitHub Actions injection, permissions
├── supply-chain.md            # Dependency confusion, typosquatting, lock files
├── lang-javascript.md         # Node/Express/Next.js/React patterns (924 lines)
├── lang-python.md             # Django/Flask/FastAPI patterns (935 lines)
├── iac-docker.md              # Dockerfile/Compose security (1,005 lines)
└── report-template.md         # Report format specification
```

Each reference file contains:
- **Grep-ready regex patterns** Claude can use for analysis
- **Vulnerable code examples** showing the actual problem
- **Secure code examples** showing the fix
- **CWE and OWASP 2025 mappings** for classification
- **Severity ratings** for consistent scoring

### Layer 3: Python Scripts — Batch Processing

Two Python scripts handle tasks where batch processing is faster than sequential Claude analysis:

| Script | Purpose | Lines |
|--------|---------|-------|
| `scan_secrets.py` | Regex-based secret scanning across all files. 60+ patterns covering AWS, GCP, GitHub, Slack, Stripe, database credentials, private keys, API keys, and more. Includes smart allowlisting to reduce false positives. | 510 |
| `check_lockfiles.py` | Lock file integrity verification for 10 package managers (npm, yarn, pnpm, bun, pip, pipenv, poetry, cargo, bundler, composer, Go). Detects missing lock files, unpinned dependencies, and risky lifecycle scripts. | 340 |

Both scripts:
- Use **only Python standard library** (zero dependencies)
- Output **structured JSON** for easy parsing
- Handle edge cases gracefully (empty dirs, missing files, binary files)
- Are strictly **read-only** — never modify the target project

---

## Optional: External Tool Integration

Cyber Neo works **out of the box** using Claude-native analysis. For deeper scanning, install these optional tools:

| Tool | Category | Install | What It Adds |
|------|----------|---------|-------------|
| [Semgrep](https://semgrep.dev) | SAST | `brew install semgrep` | 3,000+ community rules for 30+ languages |
| [Trivy](https://trivy.dev) | SCA | `brew install trivy` | Comprehensive dependency vulnerability database |
| [Gitleaks](https://gitleaks.io) | Secrets | `brew install gitleaks` | Git history scanning for committed secrets |
| [pip-audit](https://pypi.org/project/pip-audit/) | Python SCA | `pip install pip-audit` | Python package vulnerability checking |
| [cargo-audit](https://crates.io/crates/cargo-audit) | Rust SCA | `cargo install cargo-audit` | Rust crate vulnerability checking |

When these tools are installed, Cyber Neo automatically detects and uses them alongside its built-in analysis for deeper coverage.

---

## Scope Tiering — How It Handles Large Projects

Cyber Neo adapts its scanning strategy based on project size:

| Tier | File Count | Strategy |
|------|-----------|----------|
| **Small** | < 1,000 | Full scan — every source file analyzed |
| **Medium** | 1,000 - 10,000 | Targeted scan — prioritizes `src/`, `app/`, API routes, auth middleware, config files |
| **Large** | 10,000+ | Critical-path scan — focuses on entry points, auth, config, deps. Reports coverage percentage |

The final report always shows how many files were scanned vs. skipped, so you know exactly what was covered.

---

## Safety Guarantees

<div align="center"><img src="assets/claw-d-shield.png" alt="Claw'd standing guard behind a shield with a green padlock — the read-only iron law" width="280"></div>

Cyber Neo follows a strict **read-only iron law**:

| Rule | Description |
|------|-------------|
| **Never modifies files** | Your project files are never changed, deleted, or created |
| **Never executes code** | No `npm start`, `python app.py`, or any project execution |
| **Never installs packages** | No `npm install`, `pip install`, or dependency modifications |
| **Never runs fix commands** | No `npm audit --fix` or auto-remediation |
| **Single write operation** | Only writes the report file to `~/Desktop/` |
| **Secrets are redacted** | Detected secrets are never included in the report |

These constraints are enforced at the top level AND in every subagent prompt.

---

## OWASP 2025 Top 10 Coverage Map

| ID | Category | Where Addressed |
|----|----------|----------------|
| A01:2025 | Broken Access Control | `auth-authz-patterns.md` — missing middleware, IDOR, privilege escalation |
| A02:2025 | Security Misconfiguration | `web-security-patterns.md` + `error-handling-patterns.md` — headers, debug mode, env config |
| A03:2025 | Software Supply Chain Failures | `supply-chain.md` + `cicd-security.md` — dep confusion, typosquatting, CI injection |
| A04:2025 | Cryptographic Failures | `crypto-patterns.md` + `secrets-patterns.md` — weak algorithms, hardcoded keys |
| A05:2025 | Injection | `lang-javascript.md` + `lang-python.md` + `web-security-patterns.md` — SQLi, XSS, SSRF |
| A06:2025 | Insecure Design | `auth-authz-patterns.md` + `web-security-patterns.md` — structural design flaws |
| A07:2025 | Authentication Failures | `auth-authz-patterns.md` — JWT, sessions, password hashing, OAuth |
| A08:2025 | Software/Data Integrity Failures | `lang-*.md` + `supply-chain.md` — deserialization, dependency integrity |
| A09:2025 | Logging/Monitoring Failures | `logging-patterns.md` — sensitive data in logs, missing security logging |
| A10:2025 | Mishandling of Exceptional Conditions | `error-handling-patterns.md` — empty catches, stack traces, debug mode |

---

## Remediation Workflow

After running Cyber Neo, we recommend a **test-driven security fix** approach:

```
1. Read the report — start with Critical findings
2. Pick the highest-severity finding
3. Write a test that proves the vulnerability exists
4. Apply the fix from the remediation guidance
5. Run the test — verify it passes
6. Re-run /cyber-neo to confirm the finding is resolved
7. Repeat for the next finding
```

If you have the [Superpowers](https://github.com/obra/superpowers) plugin installed, use its TDD workflow for structured remediation.

---

## Skill Integration

Cyber Neo works with other Claude Code skills for enhanced analysis:

| Skill | Integration |
|-------|------------|
| [/last30days](https://github.com/mvanhorn/last30days-skill) | Researches emerging threats and community discussions about your detected stack |
| /deep-research | Looks up context on unfamiliar CVEs or emerging threats found during scan |
| [Superpowers](https://github.com/obra/superpowers) | TDD-driven remediation workflow for fixing findings systematically |

---

## Project Structure

```
cyber-neo/
├── .claude-plugin/
│   └── plugin.json                        # Plugin metadata
├── skills/
│   └── cyber-neo/
│       ├── SKILL.md                       # Orchestration engine (563 lines)
│       ├── scripts/
│       │   ├── scan_secrets.py            # Batch secret scanner (510 lines)
│       │   └── check_lockfiles.py         # Lock file checker (340 lines)
│       └── references/                    # Security knowledge base (14 files, 10K+ lines)
│           ├── owasp-top-10.md
│           ├── cwe-top-25.md
│           ├── secrets-patterns.md
│           ├── auth-authz-patterns.md
│           ├── crypto-patterns.md
│           ├── web-security-patterns.md
│           ├── error-handling-patterns.md
│           ├── logging-patterns.md
│           ├── cicd-security.md
│           ├── supply-chain.md
│           ├── lang-javascript.md
│           ├── lang-python.md
│           ├── iac-docker.md
│           └── report-template.md
├── CLAUDE.md                              # Contributor guidelines
├── LICENSE                                # MIT
└── README.md                              # This file
```

---

## Roadmap

### v0.1.0 (Current)
- 7-phase analysis pipeline with parallel subagents
- JavaScript/TypeScript + Python language support
- 14 security reference files (10,000+ lines)
- 60+ secret detection patterns
- 10 package manager support for lock file checks
- Full OWASP 2025 Top 10 and CWE Top 25 coverage
- Professional report generation with CWE/OWASP mapping

### v0.2.0 (Planned)
- Go, Ruby/Rails, Java/Spring, Rust language patterns
- Kubernetes and Terraform/IaC security scanning
- OWASP Top 10 for LLMs (prompt injection, sensitive data in AI apps)
- Mobile security patterns (React Native, Flutter)
- Serverless/Lambda security patterns
- GraphQL security analysis
- SARIF output format for CI/CD integration
- Configuration sub-skill (`/cyber-neo:config`)

### v0.3.0 (Future)
- Session-start hook for automatic security context
- ASVS (Application Security Verification Standard) mapping
- Trend tracking (re-scan and diff findings over time)
- Cross-platform support (Cursor, Copilot CLI, Windsurf)
- CI/CD integration mode (GitHub Action wrapper)
- Race condition detection patterns

---

## Contributing

We welcome contributions from the community. See [CLAUDE.md](CLAUDE.md) for detailed contributor guidelines.

### Key Principles

1. **SKILL.md is the product** — its quality determines how good the agent is
2. **Reference files are pure knowledge** — grep-ready patterns with CWE/OWASP mappings
3. **Scripts use only standard library** — zero pip dependencies
4. **Every finding needs classification** — CWE ID, OWASP category, severity, and remediation
5. **Read-only on target projects** — never modify what we're scanning

### How to Add a New Language

1. Create `references/lang-{language}.md` following the existing pattern
2. Add framework detection patterns, vulnerability patterns with grep regex, and secure/vulnerable code examples
3. Map every pattern to CWE and OWASP 2025 categories
4. Update SKILL.md Phase 1.1 to detect the new language
5. Update SKILL.md Phase 1.3 to load the new reference file
6. Test against a deliberately vulnerable project in that language

---

## Community

<div align="center"><img src="assets/claw-d-community.png" alt="Claw'd waving and holding up an A+ security report" width="280"></div>

Cyber Neo is shipped by **[@soyenriquerocha](https://instagram.com/soyenriquerocha)** and built by the **[Tododeia](https://tododeia.com)** community — a growing network of developers building apps, tools, and products together. We believe every developer deserves access to enterprise-grade security tooling, for free.

- **Creator:** [@soyenriquerocha](https://instagram.com/soyenriquerocha) on Instagram
- **Community:** [tododeia.com](https://tododeia.com)
- **GitHub:** [github.com/Hainrixz/cyber-neo](https://github.com/Hainrixz/cyber-neo)
- **License:** MIT — use it, modify it, share it

---

## Acknowledgments

Cyber Neo builds on the shoulders of the security community:

- [OWASP Foundation](https://owasp.org) — Top 10 and ASVS standards
- [MITRE](https://cwe.mitre.org) — CWE vulnerability classification
- [Semgrep](https://semgrep.dev) — Static analysis patterns and rules
- [Trivy](https://trivy.dev) — Vulnerability database
- [Superpowers](https://github.com/obra/superpowers) — Skill architecture patterns
- [last30days](https://github.com/mvanhorn/last30days-skill) — Research integration patterns

---

<div align="center">

**Shipped by [@soyenriquerocha](https://instagram.com/soyenriquerocha) | Built with purpose. Open source forever.**

*Protecting the apps our community builds — one scan at a time.*

[Get Started](#installation) | [Report an Issue](https://github.com/Hainrixz/cyber-neo/issues) | [Join the Community](https://tododeia.com) | [Follow @soyenriquerocha](https://instagram.com/soyenriquerocha)

</div>
