# API Sentry

![Python](https://img.shields.io/badge/Python-3.12-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-Latest-009688)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-blue)
![License](https://img.shields.io/badge/License-MIT-green)

## Overview

API Sentry is an enterprise-grade API Security Analysis platform built using FastAPI.

The platform analyzes source code and APIs for security vulnerabilities and provides detailed findings, severity ratings, remediation guidance, and security reports.

---

# Features

- API Security Scanner
- Source Code Security Analysis
- Authentication Analysis
- Authorization Analysis
- JWT Security Checks
- SQL Injection Detection
- XSS Detection
- SSRF Detection
- Command Injection Detection
- Path Traversal Detection
- File Upload Security
- Secrets Detection
- Security Score
- Vulnerability Reports
- Dashboard
- Multi-user Support
- Email Verification
- Role Based Authentication
- Project Uploads
- Scan History

---

# Technology Stack

- Python 3.12
- FastAPI
- SQLAlchemy
- PostgreSQL
- Alembic
- Jinja2
- Bootstrap 5
- Uvicorn
- Apache
- Pytest

---

# Project Structure

```
app/
    api/
    core/
    db/
    models/
    repositories/
    routers/
    schemas/
    services/
    static/
    templates/

tests/
alembic/
```

---

# Local Installation

## Clone Repository

```bash
git clone https://github.com/jey-kathirvel/apisentry.git
cd apisentry
```

## Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

## Configure Environment

```bash
cp .env.example .env
```

Update your environment variables.

---

## Database Migration

```bash
alembic upgrade head
```

---

## Run Development Server

```bash
uvicorn app.main:app --reload
```

---

# Running Tests

```bash
pytest -q
```

---

# Production

Production URL

```
https://apisentry.ads-ai.in
```

---

# Security

Never commit the following files:

- .env
- Private Keys
- API Keys
- SMTP Credentials
- Database Passwords
- Uploaded Customer Projects
- Scan Artifacts

---

# Development Workflow

```
Feature Branch

↓

Development

↓

Testing

↓

Pull Request

↓

Code Review

↓

Production
```

---

# Author

**Jey Kathirvel**

Enterprise AI & Security Platform

---

# License

MIT License

Copyright (c) 2026 Jey Kathirvel
