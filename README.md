# Cryptoolsec: Secure CLI & GUI Encryption Tool

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.html)
[![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
![Status](https://img.shields.io/badge/status-pre--release-orange.svg)
![Platforms](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey.svg)
![Framework](https://img.shields.io/badge/Framework-PySide6%2FQt6-success.svg)


## 1. Description

**Cryptoolsec** is a versatile tool providing both a Command-Line Interface (CLI) and a Graphical User Interface (GUI) for strong file and data stream encryption/decryption on Windows, macOS, and Linux.

It leverages the robust **AES-256-GCM** authenticated encryption standard, ensuring confidentiality, integrity, and authenticity. For password-based operations, keys are securely derived using **Argon2id** with unique salts per encryption. Alternatively, raw 32-byte AES keys can be used directly via key files.

The application is built with Python and PySide6 (for the GUI), featuring streaming I/O for handling large files efficiently and a threaded GUI for a responsive user experience.


## 2. Key Features

* **Dual Interface:** Functional CLI (`cryptoolsec`) and modern GUI (`cryptoolsec-gui`).
* **Strong Encryption:** AES-256-GCM standard.
* **Secure Key Derivation:** Argon2id with unique salts for passwords.
* **Flexible Secret Handling:** Supports interactive passwords, password files, password via stdin, and raw key files.
* **Large File Support:** Uses streaming I/O (chunked processing) for low memory usage.
* **Responsive GUI:** Background threading prevents UI freezing during operations.
* **GUI Enhancements:** Progress bar, status messages, platform icon, intelligent output filename suggestion, automatic field clearing.
* **Cross-Platform:** Python codebase designed for Windows, macOS, and Linux. Packaged builds available (starting with Windows).


## 3. Index

* [1. Description](#1-description)
* [2. Key Features](#2-key-features)
* [3. Index](#3-index)
* [4. Installation](#4-installation)
* [5. Usage](#5-usage)
    * [5.1. Launching](#51-launching)
    * [5.2. CLI Usage](#52-cli-usage)
        * [5.2.1. General Syntax](#521-general-syntax)
        * [5.2.2. Commands](#522-commands)
        * [5.2.3. Common Options](#523-common-options)
        * [5.2.4. Secret Options](#524-secret-options)
        * [5.2.5. CLI Examples](#525-cli-examples)
    * [5.3. GUI Usage](#53-gui-usage)
* [6. File Format](#6-file-format)
* [7. Technologies Used](#7-technologies-used)
* [8. License](#8-license)
* [9. Project Status](#9-project-status)
* [10. Contribution](#10-contribution)
* [11. Contact](#11-contact)


## 4. Installation

1.  **Prerequisites:**
    * Python (>= 3.10 recommended, as specified in `pyproject.toml`).
    * `pip` (Python package installer).

2.  **Clone or Download:**
    * Obtain the project source code.
    ```bash
    # Example using Git
    git clone https://github.com/victorvernier/Cryptoolsec.git
    # cd Cryptoolsec
    ```

3.  **Create & Activate Virtual Environment (Recommended):**
    * Navigate to the project root directory in your terminal.
    ```bash
    # Create venv
    python -m venv .venv
    # Activate venv
    # Windows: .\.venv\Scripts\activate
    # Linux/macOS: source .venv/bin/activate
    ```

4.  **Install Project and Dependencies:**
    * With the virtual environment activated, install `Cryptoolsec` and its dependencies using `pip` and the `pyproject.toml` file. Using the editable (`-e`) flag is recommended for development.
    ```bash
    # Installs dependencies and creates the 'cryptoolsec' and 'cryptoolsec-gui' commands
    pip install -e .
    ```
    * This command reads `pyproject.toml`, installs the packages listed under `dependencies` (`PySide6`, `pycryptodome`, `argon2-cffi`), and makes the entry points available.


## 5. Usage

### 5.1. Launching

After installation (`pip install -e .`), the following commands become available in your terminal (while the virtual environment is active):

* **Launch GUI:**
    ```bash
    cryptoolsec-gui
    ```
* **Use CLI:**
    ```bash
    cryptoolsec <command> [options...]
    ```

### 5.2. CLI Usage


#### 5.2.1. General Syntax

```bash
cryptoolsec <command> [options...]
```


#### 5.2.2. Commands

* `encrypt`: Encrypt input file/stream to output file/stream.
* `decrypt`: Decrypt input file/stream to output file/stream.


#### 5.2.3. Common Options

* `-i FILE`, `--input FILE`: Input file path. Reads from stdin if omitted.
* `-o FILE`, `--output FILE`: Output file path. Writes to stdout if omitted.
* `--verbose`: Show detailed debug messages.
* `-q`, `--quiet`: Show only error messages.
* `-V`, `--version`: Show program version.
* `-h`, `--help`: Show help message (use after command for specific help, e.g., `cryptoolsec encrypt -h`).


#### 5.2.4. Secret Options

One of these mutually exclusive options is required for both `encrypt` and `decrypt`:

* `--password-interactive`: Securely prompts for password entry.
* `--password-file FILE`: Reads password from the first line of `FILE`.
* `--password-stdin`: Reads password from the first line of stdin (for piping).
* `--keyfile FILE`: Uses the raw 32-byte AES key from `FILE`.


#### 5.2.5. CLI Examples

* Encrypt `doc.txt` to `doc.enc` using interactive password:
```bash
cryptoolsec encrypt -i doc.txt -o doc.enc --password-interactive
```

* Decrypt `pic.jpg.enc` to `pic.jpg` using password from `key.txt`:
```bash
cryptoolsec decrypt -i pic.jpg.enc -o pic.jpg --password-file key.txt
```

* Encrypt large `archive.zip` using `secret.key` file, show verbose logs:
```bash
cryptoolsec --verbose encrypt --keyfile secret.key -i archive.zip -o archive.zip.enc
```

* Compress, encrypt, and upload a folder using pipes:
```bash
tar czf - /my/folder | cryptoolsec encrypt --keyfile secret.key > backup.tar.gz.enc
# (Upload backup.tar.gz.enc)
```

* Download, decrypt, and extract using pipes:
```bash
# (Download backup.tar.gz.enc first)
cat backup.tar.gz.enc | cryptoolsec decrypt --keyfile secret.key | tar xzf - -C /restore/here
```


## 5.3. GUI Usage

1. **Launch:** Run `cryptoolsec-gui` in your terminal (after installation and with venv active).

2. **Select Files:** Use the "Select..." buttons to choose your Input File and define your Output File path. The output filename will be suggested automatically based on the input file (adding/removing `.enc`).

3. ** Secret Method:** Select either "Use Password" or "Use Key File".

4. **Enter Secret:**
    * If "Use Password", type the password in both fields (input is masked).
    * If "Use Key File", click "Select Key File..." and choose your raw 32-byte key file.

5. **Click Action:** Click "Encrypt" or "Decrypt".

6. **Monitor:** The UI will disable, and the progress bar will show activity (it might be indeterminate if reading from stdin, not yet implemented in GUI). A success or error message will appear upon completion.

7. **Repeat:** Input fields will clear automatically after the operation finishes.




## 6. File Format

The encrypted output (`.enc` file) format depends on the secret method used:

* Password Mode: `[16-byte Salt][12-byte IV][Ciphertext][16-byte GCM Tag]`

* Key File Mode: `[12-byte IV][Ciphertext][16-byte GCM Tag]` (No Salt is stored as none was needed for key derivation)


## 7. Technologies Used

* Python (>= 3.10)
* PySide6 (for the GUI)
* pycryptodome (for AES-GCM implementation)
* argon2-cffi (for Argon2id key derivation)
* PyInstaller (for packaging)


## 8. License

Distributed under the GPL-3.0 license. See LICENSE file or [LICENSE](https://github.com/victorvernier/Cryptoolsec/blob/main/LICENSE) for more information.


## 9. Project Status

**v0.2.0 - Beta / Pre-release:** Core functionality for both CLI and GUI is implemented and has undergone successful manual testing. However, automated test coverage is still pending. **Not recommended for production use with critical data until further testing.**


## 10. Contribution
Contributions, bug reports, and feature requests are welcome! Please open an [issues](https://github.com/victorvernier/Cryptoolsec/issues) to discuss changes or report problems.


## 11. Contact
[Jean V O Melo](https://orcid.org/0009-0006-5691-6159) | [E-mail](victorvernier@proton.me) | [Cryptoolsec](https://github.com/victorvernier/Cryptoolsec)
