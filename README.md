<p align="center">
  <img src="https://raw.githubusercontent.com/Arc-Cyber-Arsenal/XSS-Tesseract/master/xss.png" alt="403-Killchain Banner" width="600">
</p>


# 🔮 XSS‑Tesseract

### The 4‑Dimensional XSS Engine

**XSS‑Tesseract** fuses three independent XSS detection and exploitation
strategies into a single, self‑contained binary – a context‑aware payload
generator, a DOM‑AST verification engine, and a curated payload
intelligence database. They run **in parallel** against the same target,
producing one combined report that shows not only *where* XSS exists
but *why* it works.

---

## 💡 How XSS‑Tesseract Works

The tool orchestrates three complementary engines. Each attacks the same
URL with a completely different philosophy.

### Engine 1 – Context‑Aware Payload Generator

This engine doesn’t spray payloads blindly. It first **parses the
response at the markup level** using four hand‑written parsers to
determine exactly where user input lands:

- Inside an HTML tag (`<div>HERE</div>`)
- Inside an attribute value (`<input value="HERE">`)
- Between `<script>` tags
- Inside a JavaScript string literal

Once the injection context is known, the engine **crafts payloads that
are guaranteed to work in that context**, then mutates them with a
fuzzing engine to evade WAFs. While doing so it also:

- Performs multi‑threaded crawling to discover all hidden parameters
- Detects Web Application Firewalls (WAFs) and adapts payloads
  accordingly
- Executes blind XSS tests with out‑of‑band callbacks
- Reports every parameter that returned anything other than a 403 or
  empty response

The result is **near‑zero false positives** – you only see confirmed
vulnerable endpoints.

### Engine 2 – DOM‑AST Verification Engine

This engine takes automation seriously. It goes beyond simple reflected
parameter checks and performs:

- **Static Analysis** – parses JavaScript files and HTML pages for
  potential sinks
- **Parameter Mining** – extracts hidden parameters from forms,
  scripts, and meta tags
- **Blind / Stored / DOM‑based XSS Detection** – injects payloads and
  tracks whether they reach a sink in the DOM or JavaScript AST
- **WAF Fingerprinting** – identifies the specific WAF (Cloudflare,
  AWS, ModSecurity, etc.) with a confidence score
- **Bypass Tracking** – records which payloads succeeded against which
  WAF configurations

Output is available in multiple formats (JSON, SARIF, Markdown, TOML)
so it integrates directly into CI/CD pipelines. The DOM‑AST verification
step ensures you’re not just guessing – the engine **proves** a sink was
reached.

### Engine 3 – Payload Intelligence Database

This is a structured, categorised knowledge base of hundreds of XSS
payloads, organised by:

- **Injection Context** – HTML, Attribute, JavaScript, CSS, URL
- **Defence Type** – WAF bypass, encoding evasion, CSP violation,
  polyglot vectors

The database is loaded at runtime and **merged into a single payload
list** that is fed into the other two engines, ensuring that no
high‑value payload is ever missed. The wrapper also prints a summary of
the payload distribution so you know exactly which contexts are being
covered before the scan even starts.

**All three engines run concurrently.** You get the combined output in
less time than it takes to run two of them separately.

---

## 🧰 Features

| Feature | Description |
|---------|-------------|
| 🔬 **Context‑Aware Payload Generation** | Parses HTML/DOM structure before crafting payloads |
| ✅ **DOM/AST Verification** | Confirms whether a payload actually reaches a sink |
| 🗂️ **Curated Payload Database** | 900+ payloads organised by context and defence type |
| ⚡ **Parallel Multi‑Engine Execution** | All engines attack simultaneously |
| 🧠 **Engine Selection** | Use `--only` or `--skip` to pick specific engines |
| 📋 **Unified Reporting** | Clean, sectioned output for rapid analysis |
| 🔒 **Self‑Contained Binary** | No external dependencies at runtime – all engines are embedded |
| 🪶 **Static Binary** | Runs on Linux, macOS, and Windows without installers |
| 🧹 **Offline Operation** | Zero external API calls; payloads and engines are compiled‑in |

---

## 🚀 Installation

### From Pre‑compiled Binary
Download from [Releases](https://github.com/Arc-Cyber-Arsenal/XSS-Tesseract/releases)

### Build from Source (Go 1.20+ required; Python 3.4+ needed for the
context‑aware engine)
```bash
git clone https://github.com/Arc-Cyber-Arsenal/XSS-Tesseract
cd XSS-Tesseract
go build -o XSS-Tesseract
```

---

## 🎯 Usage

```bash
./XSS-Tesseract -u https://target.com/search?q=test
```

### Flags

| Flag       | Description |
|------------|-------------|
| `-u`       | Target URL (required) |
| `-p`       | Custom payload file (one per line) |
| `--only`   | Run only specified engines (`xsstrike`, `dalfox`, `payloaddb`) |
| `--skip`   | Skip engines (comma‑separated) |
| `-h`       | Show banner and help |

### Examples

**Full Tesseract scan:**
```bash
./XSS-Tesseract -u "https://example.com/search?q=test"
```

**Only the payload database summary:**
```bash
./XSS-Tesseract -u "https://example.com/search?q=test" --only payloaddb
```

**Supply custom payloads and skip the database engine:**
```bash
./XSS-Tesseract -u "https://example.com/search?q=test" -p my_payloads.txt --skip payloaddb
```

---

## 📊 Comparison with Traditional Scanners

| Capability               | Traditional scanners | XSS‑Tesseract |
|--------------------------|:--------------------:|:-------------:|
| Context‑aware payloads   | ❌                   | ✅            |
| DOM/AST sink verification | ❌                   | ✅            |
| Curated payload database | ❌                   | ✅            |
| Parallel engine execution | ❌                   | ✅            |
| Unified output           | ❌                   | ✅            |
| Offline / self‑contained | ❌                   | ✅            |

---

## 👤 Author & Organisation

- **Archsec-Emman** – [@Archsec-Emman](https://github.com/Archsec-Emman)
- **Arc‑Cyber‑Arsenal** – [https://github.com/Arc-Cyber-Arsenal](https://github.com/Arc-Cyber-Arsenal)

---

## 📄 License

MIT License © 2026 Archsec-Emman  
The embedded engines contain code from multiple open‑source projects –
see `THIRD_PARTY_LICENSES.md` for full attributions.
