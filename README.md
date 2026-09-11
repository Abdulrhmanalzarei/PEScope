# PEScope

**Pure Python Windows PE Analyzer**

PEScope is a command-line tool for statically inspecting Windows Portable Executable (PE) files such as `.exe`, `.dll`, and `.sys` files. It reads the file structure without executing the target file and reports useful structural and security-oriented indicators.

> **Important:** PEScope is an educational static-analysis tool. Its security indicators are heuristics and are **not proof that a file is malicious**.

---

## 1. Problem

Windows executable files contain structured information that can be useful during malware analysis, incident response, reverse engineering, and security research. However, manually inspecting PE headers, sections, imports, strings, and entropy can be time-consuming for beginners.

PEScope addresses this problem by providing a simple command-line interface that extracts and presents important PE information in a readable form.

---

## 2. Project Idea

The project is a **Pure Python PE parser and analyzer** that performs static inspection of a Windows PE file.

The tool can:

- Validate the `MZ` DOS signature.
- Locate and validate the `PE\0\0` signature.
- Read the COFF header.
- Identify common CPU architectures such as x86, x64, ARM, and ARM64.
- Read the PE Optional Header.
- Display the entry point and image base.
- Display section alignment and file alignment.
- Parse PE sections.
- Calculate Shannon entropy for sections.
- Extract ASCII strings.
- Parse imported DLLs and imported APIs.
- Report basic security indicators based on configured suspicious APIs and high-entropy sections.

The tool does **not execute** the analyzed PE file.

---

## 3. Objectives

The main objectives of PEScope are:

1. Build a practical cybersecurity tool using **Python Pure**.
2. Work with Windows PE file structures at the binary level.
3. Practice binary parsing with Python's standard library.
4. Understand the relationship between PE headers, sections, imports, strings, and entropy.
5. Provide a clear CLI that can be demonstrated easily.
6. Implement useful error handling for invalid files and configuration errors.
7. Keep the project cross-platform at the Python application level, while analyzing Windows PE files.
8. Provide a foundation that can be extended for future static-analysis features.

---

## 4. How the Tool Works

The internal processing flow is:

```text
PE File
   |
   v
MZ Signature
   |
   v
e_lfanew -> PE Signature
   |
   v
COFF Header
   |
   v
Optional Header
   |
   v
Section Table
   |
   +------------------+------------------+
   |                  |                  |
   v                  v                  v
Imports            Strings           Entropy
   |                  |                  |
   +------------------+------------------+
                      |
                      v
             Security Indicators
                      |
                      v
                  CLI Output
```

### 4.1 PE Signature Validation

PEScope first checks that the file begins with the DOS `MZ` signature. It then reads the `e_lfanew` value to locate the PE header and verifies the `PE\0\0` signature.

### 4.2 COFF Header

The COFF header provides information such as:

- Machine type.
- Number of sections.
- Size of the Optional Header.

### 4.3 Optional Header

PEScope supports the common PE32 and PE32+ formats and extracts values including:

- Entry Point.
- Image Base.
- Section Alignment.
- File Alignment.
- Import Directory location.

### 4.4 Section Analysis

For every section, the tool reports information such as:

- Section name.
- Relative Virtual Address (RVA).
- Virtual size.
- Raw file size.
- Raw file offset.
- Shannon entropy.

### 4.5 Import Analysis

PEScope resolves imported DLL names and imported API names when the import table can be mapped successfully.

The analyzer also checks imported APIs against a built-in set of security-related indicators. Examples include APIs associated with memory manipulation, process creation, remote thread creation, registry access, and network activity.

### 4.6 String Extraction

The `strings` command scans the PE file for printable ASCII sequences and reports their file offsets.

### 4.7 Entropy Analysis

PEScope calculates Shannon entropy for section data. A high entropy value can be associated with compressed, encrypted, packed, or otherwise high-variation data. Entropy alone is not evidence of malware.

---

## 5. Project Structure

```text
PEScope_Final/
|
+-- README.md
+-- config.json
+-- pescope/
|   +-- __init__.py
|   +-- __main__.py
|   +-- cli.py
|   +-- config.py
|   +-- errors.py
|   +-- logging_utils.py
|   +-- pe.py
|
+-- tests/
    +-- test_pe.py
```

### File Responsibilities

| File | Responsibility |
|---|---|
| `README.md` | Project documentation, usage, demonstration, and requirements. |
| `config.json` | Default configurable analysis values. |
| `pescope/__init__.py` | Stores the project version. |
| `pescope/__main__.py` | Allows the package to run with `python -m pescope`. |
| `pescope/cli.py` | Defines the CLI and displays analysis results. |
| `pescope/config.py` | Loads and validates JSON configuration. |
| `pescope/errors.py` | Defines project-specific exceptions. |
| `pescope/logging_utils.py` | Configures standard-library logging. |
| `pescope/pe.py` | Contains PE parsing, section, string, import, entropy, and security-analysis logic. |
| `tests/test_pe.py` | Automated unit tests for the main functionality. |

---

## 6. Requirements

### Software Requirements

- Python 3.9 or newer is recommended.
- No third-party Python packages are required.
- The implementation uses the Python standard library only.

### Libraries Used

PEScope relies only on standard-library modules, including:

- `argparse`
- `collections`
- `dataclasses`
- `json`
- `logging`
- `math`
- `struct`
- `sys`
- `unittest` for testing

No external PE-parsing package is required.

---

## 7. How to Run the Tool

Open a terminal in the project directory.

### Show Help

```bash
python -m pescope --help
```

### Show Version

```bash
python -m pescope --version
```

Expected version format:

```text
PEScope 1.1.0
```

### Show PE Information

```bash
python -m pescope info sample.exe
```

### Show PE Sections

```bash
python -m pescope sections sample.exe
```

### Show Imports

```bash
python -m pescope imports sample.exe
```

### Extract Strings

```bash
python -m pescope strings sample.exe
```

Specify a different minimum string length:

```bash
python -m pescope strings sample.exe --min-length 8
```

### Run Security Analysis

```bash
python -m pescope analyze sample.exe
```

---

## 8. Configuration

PEScope supports a JSON configuration file through the `--config` option.

Example:

```bash
python -m pescope --config config.json analyze sample.exe
```

The configuration file contains values such as:

```json
{
    "min_string_length": 5,
    "entropy_threshold": 7.2
}
```

### Configuration Values

| Setting | Meaning | Default |
|---|---|---:|
| `min_string_length` | Minimum length for extracted ASCII strings. | `5` |
| `entropy_threshold` | Entropy value used by the security analysis. | `7.2` |

Invalid configuration values produce a clear configuration error instead of exposing a raw Python exception.

---

## 9. Logging

The CLI supports four logging levels:

```bash
python -m pescope --log-level DEBUG info sample.exe
python -m pescope --log-level INFO info sample.exe
python -m pescope --log-level WARNING info sample.exe
python -m pescope --log-level ERROR info sample.exe
```

The default level is `WARNING`.

---

## 10. Error Handling

PEScope handles common input and configuration problems and reports a readable message to the user.

Examples include:

- Missing PE file.
- File that does not contain an `MZ` signature.
- Invalid PE header offset.
- Missing `PE\0\0` signature.
- Truncated Optional Header.
- Truncated section table.
- Unsupported Optional Header format.
- Missing or unresolved import information.
- Invalid string-length argument.
- Missing configuration file.
- Invalid JSON configuration.
- Configuration values with invalid types or ranges.
- Operating-system file-read errors such as permission problems.

Example:

```text
Error: Not a valid PE file: missing MZ signature.
```

The program does not intentionally expose a raw traceback for these handled project errors.

---

## 11. Results and Outputs

The tool provides several categories of output.

### `info`

Displays general PE information, including:

- File path.
- File size.
- Architecture.
- PE32/PE32+ format.
- Entry point.
- Image base.
- Number of sections.
- Section and file alignment.

Example format:

```text
PEScope
========================================
File       : sample.exe
Size       : 123456 bytes
Machine    : x64
Format     : PE32+
Entry Point: 0x00001234
Image Base : 0x140000000
Sections   : 5
Alignment  : section=4096, file=512
```

### `sections`

Displays the PE section table together with calculated entropy.

Example format:

```text
NAME       RVA          V.SIZE       RAW SIZE     RAW OFF      ENTROPY
------------------------------------------------------------------------------
.text      0x00001000   4096         4096         0x00000400   6.21
.rdata     0x00002000   2048         2048         0x00001400   5.34
```

### `imports`

Displays imported DLLs and their imported APIs.

Example format:

```text
KERNEL32.dll
  CreateProcessW
  VirtualAlloc
  VirtualProtect
```

### `strings`

Displays printable ASCII strings and their file offsets.

Example format:

```text
Found 120 ASCII strings (minimum length=5):
0x00000120  This is a sample string
0x00000480  KERNEL32.dll
```

### `analyze`

Displays basic security indicators.

Example format:

```text
Security Analysis
========================================

Indicators:
  [!] API indicator: VirtualAlloc
  [!] API indicator: CreateProcessW
  [!] High entropy section: .text

Important: indicators are NOT proof of malware.
```

---

## 12. Testing

The project includes automated tests using Python's built-in `unittest` framework.

Run the tests from the project directory:

```bash
python -m unittest discover -s tests -v
```

The tests cover important functionality such as:

- PE parsing.
- ASCII string extraction.
- Entropy calculation.
- RVA-to-file-offset mapping.
- Invalid PE handling.
- Configuration loading.
- Invalid configuration handling.

---

## 13. Practical Demonstration Plan

The project can be presented as a short practical demonstration.

### Step 1 — Introduce the Problem

Explain that PE files contain many useful structures but manually inspecting them is inconvenient, especially for beginners.

### Step 2 — Introduce PEScope

Explain that PEScope performs static analysis using Python's standard library without executing the target PE file.

### Step 3 — Demonstrate the CLI

Run:

```bash
python -m pescope --help
```

Then show the available commands.

### Step 4 — Analyze a PE File

Use an authorized Windows PE sample and run:

```bash
python -m pescope info sample.exe
```

Explain the `MZ` signature, PE signature, architecture, entry point, image base, and sections.

### Step 5 — Explain Sections and Entropy

Run:

```bash
python -m pescope sections sample.exe
```

Explain how each section has its own size, address, and entropy value.

### Step 6 — Explain Imports

Run:

```bash
python -m pescope imports sample.exe
```

Explain that imported APIs can provide useful behavioral clues during static analysis.

### Step 7 — Explain Strings

Run:

```bash
python -m pescope strings sample.exe
```

Explain how strings can reveal readable information embedded in a binary.

### Step 8 — Run the Security Analysis

Run:

```bash
python -m pescope analyze sample.exe
```

Explain that the result contains heuristic indicators rather than a malware verdict.

### Step 9 — Demonstrate Error Handling

Run the tool against an invalid or non-PE file and show that it returns a clear error message.

### Step 10 — Demonstrate Testing

Run:

```bash
python -m unittest discover -s tests -v
```

Explain that automated tests help verify the parser and supporting functions.

---

## 14. Bonus / Future Development Readiness

The current architecture provides a reasonable foundation for future extensions without changing the basic CLI concept.

Possible future improvements include:

- Additional PE data-directory parsing.
- More security indicators.
- Export-table analysis.
- Resource-directory inspection.
- Richer reporting formats.
- Additional automated tests.
- Packaging the application for easier distribution.
- Publishing the project as an open-source GitHub repository.

These are extension ideas and are not required for the current implementation.

---

## 15. Responsible Use

PEScope should be used only with files that you are authorized to inspect.

For cybersecurity education and demonstrations, use your own binaries, intentionally created samples, or files provided for authorized analysis. Do not execute unknown or suspicious binaries merely to test this project.

---

## 16. Academic Requirements Checklist

| Requirement | Status |
|---|---|
| Practical application/tool | Yes |
| Main language: Python | Yes |
| Pure Python implementation | Yes |
| Third-party implementation libraries | None required |
| CLI interface | Yes |
| `--help` | Yes |
| `--version` | Yes |
| `--config` | Yes |
| `--log-level` | Yes |
| Subcommands | Yes |
| Input/file error handling | Yes |
| Configuration error handling | Yes |
| Documentation | Yes |
| Practical demonstration plan | Yes |
| Automated tests | Yes |

---

## 17. Important Note About the Code

The Python source code in this version has **not been functionally changed**. The source files were only reorganized and formatted visually to improve readability, consistency, indentation, spacing, and overall presentation.

The project functionality, command structure, parsing logic, configuration behavior, analysis logic, and test scope remain unchanged.

---

## License

This project is intended for educational and authorized cybersecurity analysis purposes.
