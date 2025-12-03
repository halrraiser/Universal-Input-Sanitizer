# Universal Input Sanitizer

Universal Input Sanitizer is a compact and extensible toolkit designed to help developers 
clean, normalize, sanitize, and safely embed user-supplied values across different languages 
and environments. The project focuses on being lightweight, dependency-free, and easy to integrate 
into existing workflows.

It provides a simple Python API, a command-line tool, and a set of extensible helpers for masking 
sensitive data, escaping unsafe characters, and producing safe string literals for multiple 
programming languages.

---

## 🔍 What does it do?

The Universal Input Sanitizer solves a common problem:  
**You receive input from users, logs, forms, APIs, configuration files, or third-party services, and you need to make sure the values are safe to store, print, embed, or reuse.**

This toolkit provides:

- **Sanitization**  
  Trims whitespace, normalizes strings, strips dangerous characters, and applies optional 
  SQL/HTML-style escaping to reduce common injection vectors.

- **Sensitive data masking**  
  Emails, phone numbers, access tokens, and URLs can be partially masked to avoid exposing 
  private information in logs or debugging output.

- **Language-safe literals**  
  Sometimes you need to safely embed values into different languages (Python, JS, Go, C#, Java, Bash...).  
  The sanitizer converts strings into escaped, safe literals for each target language.

- **Auto-detection of simple file types**  
  The CLI can process JSON files, `.env` files (KEY=VALUE format), or plain text, sanitizing each field 
  with reasonable defaults.

This makes the tool useful for:

- log sanitization  
- debugging and safe error reporting  
- template generation  
- config validation  
- pipeline preprocessing  
- data ingestion  
- CLI tools and dev utilities  

---

## 🧠 How it works (technical overview)

The sanitizer works in three simple stages:

1. **Input Identification**  
   The CLI (or API) inspects the input.  
   - JSON → parsed and sanitized key-by-key  
   - `.env` files → split into key=value pairs  
   - Plain text → treated as a single raw value  

2. **Sanitization Pipeline**  
   A small chain of transformations is applied:
   - Strip/normalize whitespace  
   - Remove control characters  
   - Optional SQL/HTML-style escaping  
   - Pattern-based masking (email, phone, URL, tokens)  
   - Generic text cleaning for unsafe sequences  

   These transformations live in `sanitizer.py` and are intentionally simple to modify.

3. **Language-Safe Literal Generation (optional)**  
   If a target language is requested (`--languages python javascript bash ...`),  
   the value is encoded into a safe literal:
   - Quotes escaped  
   - Backslashes normalized  
   - Shell-unsafe characters escaped  
   - Language-specific wrapper formats applied  

The entire pipeline is dependency-free (pure Python) and easy to extend.

---

## ✨ Features

- Detects simple file types: **JSON**, **.env**, **plain text**
- Sanitizes and masks:
  - emails  
  - phone numbers  
  - URLs  
  - generic text  
  - basic HTML/SQL unsafe characters
- Produces escaped literals for:
  **Python, JavaScript, Java, Go, Rust, PHP, Ruby, C#, Swift, Bash**
- Includes:
  - CLI
  - Python API
  - Examples
  - Unit tests
  - Zero external dependencies

The codebase is intentionally minimal and built for extension.

---

## 🚀 Quick start

```bash
# Optional: create a virtual environment
python -m venv .venv
source .venv/bin/activate

# Install (no deps required unless you add your own)
pip install -r requirements.txt
