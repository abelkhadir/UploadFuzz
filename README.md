# File Upload Fuzzer

A powerful, intelligent Node.js fuzzer for discovering and exploiting file upload vulnerabilities in web applications. It combines intelligent extension testing, bypass technique detection, and response analysis to systematically identify upload vulnerabilities and achieve remote code execution (RCE).

## Overview

File upload vulnerabilities remain one of the most critical attack vectors in web applications. This fuzzer automates the discovery and exploitation process by:

1. **Parsing target requests** - Extracts URLs, headers, and form parameters from curl commands
2. **Baseline analysis** - Establishes a baseline response to compare against
3. **Intelligent fuzzing** - Tests extension variations and bypass techniques
4. **Smart detection** - Uses a 5-signal detection system to identify successful uploads even with obfuscated responses
5. **Path extraction** - Locates uploaded files in complex HTML responses using advanced pattern matching
6. **RCE verification** - Executes payloads to confirm code execution capabilities
7. **Brute force discovery** - Searches common upload directories for file upload paths

## Core Capabilities

### 1. Extension Fuzzing
Tests PHP extensions and variants including:
- Standard PHP extensions: `.php`, `.php3`, `.php4`, `.php5`, `.php7`, `.phtml`, `.phar`, `.phps`
- Alternative scripts: `.py`, `.pyc`, `.pl`, `.cgi`
- Windows executables: `.asp`, `.aspx`, `.jspx`, `.cer`, `.asa`, `.ashx`, `.asmx`

### 2. Bypass Technique Detection
Automatically tests common upload filters:
- **Double extensions**: `.php.jpg`, `.jpg.php`, `.php.png`
- **Case variation**: `.PhP`, `.pHp`, `.PHP`
- **Null byte injection**: `.php%00.jpg`
- **Semicolon bypass**: `.php;.jpg`
- **Whitespace tricks**: `.php .jpg`

### 3. Configuration Exploitation
Advanced attack vector:
- Uploads `.htaccess` to modify Apache behavior
- Forces `Allowed Extensions` files to execute as PHP automatically
- Enables polyglot file execution

### 4. Platform Detection
- Automatic Windows server detection via whatweb
- OS-specific extension testing
- Targeted exploit strategies

### 5. Intelligent Response Analysis
**5-Signal Detection System**:
- **Content Length Delta** (>50 bytes change) - Indicates file was processed
- **Success Keywords** - Matches patterns like "uploaded", "success", "saved", "stored"
- **Filename Echo** - Detects if filename appears in response
- **File Path Recognition** - Identifies path patterns (`images/filename.ext`, etc.)
- **Confidence Score** - 0-10 based on signals triggered
- **Success Threshold** - 3+ signals = successful upload

### 6. Upload Path Extraction
Advanced path discovery using multiple strategies:
- Exact filename matching in quotes/href attributes
- Common directory pattern recognition (upload, image, file, asset)
- URL/path extraction from HTML attributes

### 7. Payload Execution Verification
- Appends `?cmd=id` to verify PHP execution
- Detects both direct output and command results
- Confirms RCE capability before reporting success

## Installation

```bash
# Optional: Install whatweb for OS detection
sudo apt-get install whatweb  # Linux
```

## Usage

### Basic Usage
```bash
# Run fuzzer with curl request file
node fuzzer.mjs request.txt
```

### Verbose Output
```bash
# Shows detection signals, confidence scores, and extracted paths
node fuzzer.mjs request.txt -v
```

### Brute force common directories (if not found in html)
```bash
node fuzzer.mjs request.txt -b
```