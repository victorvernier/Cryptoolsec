# Cryptoolsec: Secure Encryption CLI


[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT) 


## 1. Description

`cryptoolsec` is a command-line interface (CLI) tool written in Python 3 for performing strong encryption and decryption of files or data streams. It utilizes the robust **AES-256-GCM** authenticated encryption algorithm.

When using passwords, `cryptoolsec` derives the encryption key using the secure **Argon2id** key derivation function. Alternatively, you can provide a raw AES-256 key directly via a key file.

This tool is designed with security, efficiency, and usability in mind, suitable for both command-line automation and manual file protection.

**Security Features:**

* **Encryption Algorithm:** AES-256-GCM (Advanced Encryption Standard - Galois/Counter Mode) provides confidentiality, data integrity, and authenticity.
* **Key Derivation (Password Mode):** Argon2id (current secure standard) derives a strong 256-bit encryption key from the user's password, protecting against brute-force/dictionary attacks.
* **Salting (Password Mode):** A unique, cryptographically secure 16-byte salt is generated for each password-based encryption and stored with the ciphertext, ensuring the same password results in different ciphertext each time.
* **Nonce (IV):** A unique 12-byte nonce (Initialization Vector) is generated for each encryption operation (both password and keyfile modes) as required by AES-GCM.
* **Key File Mode:** Allows using a pre-generated, raw 32-byte (256-bit) AES key for operations, bypassing password derivation.
* **Secure Password Prompt:** Uses `getpass` to avoid echoing passwords to the terminal during interactive input.

**Efficiency:**

* Reads input and writes output using buffered I/O (streaming).
* Cryptographic operations using `pycryptodome` are performed on data chunks, making the tool suitable for encrypting/decrypting files larger than available RAM without loading the entire content into memory at once.


## 2. Index

* [1. Description](#1-description)
* [2. Index](#2-index)
* [3. Installation](#3-installation)
* [4. Usage](#4-usage)
    * [4.1. General Syntax](#41-general-syntax)
    * [4.2. Common Options](#42-common-options)
    * [4.3. Providing the Secret (Password/Key)](#43-providing-the-secret-passwordkey)
    * [4.4. Encryption Examples](#44-encryption-examples)
    * [4.5. Decryption Examples](#45-decryption-examples)
    * [4.6. Using Pipes (Streams)](#46-using-pipes-streams)
* [5. Technologies Used](#5-technologies-used)
* [6. License](#6-license)
* [7. Project Status](#7-project-status)
* [8. Contribution](#8-contribution)
* [9. Contact](#9-contact)


## 3. Installation

1.  **Prerequisites:**
    * Python 3.x (developed/tested with 3.10+, but likely compatible with >= 3.8)
    * `pip` (Python package installer, usually included with Python)

2.  **Clone or Download the Source:**
    Obtain the project files (e.g., using `git clone` if it's in a repository, or by downloading and extracting a source archive).
    ```bash
    # Example if using Git
    # git clone https://github.com/victorvernier/Cryptoolsec.git
    # cd cryptoolsec
    ```

3.  **(Optional but Recommended) Create a Virtual Environment:**
    ```bash
    python -m venv .venv
    # Activate the environment

    # Windows (Command Prompt/PowerShell):
    # .\venv\Scripts\activate
    
    # Linux/macOS (Bash/Zsh):
    # source .venv/bin/activate
    ```

4.  **Install Dependencies:**
    Navigate to the project's root directory (the one containing `requirements.txt`) in your terminal and install the required libraries:
    ```bash
    pip install -r requirements.txt
    ```
    This will install `pycryptodome` and `argon2-cffi`.


## 4. Usage

### 4.1. General Syntax

`cryptoolsec` is run as a Python module from the project's root directory (the directory containing the `cryptoolsec` package folder).

```bash
python -m cryptoolsec.main <command> [options...]
# Or using 'py' launcher on Windows
# py -m cryptoolsec.main <command> [options...]
```


## Commands:

* `encrypt`: Encrypt data.
* `decrypt`: Decrypt data.


## Getting Help:

```bash
# General help
python -m cryptoolsec.main -h

# Help for the encrypt command
python -m cryptoolsec.main encrypt -h

# Help for the decrypt command
python -m cryptoolsec.main decrypt -h
```

## 4.2. Common Options

* `-i FILE`, `--input FILE`: Path to the input file. If omitted, reads from standard input (stdin).
* `-o FILE`, --output FILE: Path to the output file. If omitted, writes to standard output (stdout).
* `-v`, `--verbose`: Enable detailed debug logging output to stderr.
* `-q`, `--`: Suppress informational logs; only show errors on stderr.
* `-V`, `--version`: Display the program's version


## 4.3. Providing the Secret (Password/Key)

For both `encrypt` and `decrypt` commands, you must provide the secret using one of the following mutually exclusive options:

* `--password-interactive`: Prompts securely for the password (and confirmation during encryption) on the terminal. Recommended for manual use.

* `--password-file FILE`: Reads the password from the first line of the specified `FILE`. Useful for automation, but ensure the file has appropriate permissions.

* `--password-stdin`: Reads the password from the first line of standard input (stdin). Intended for piping passwords (e.g., from password managers or `echo`), do not use interactively.

* `--keyfile FILE`: Uses the raw 32-byte (256-bit) AES key contained in the specified `FILE`. This bypasses password derivation (Argon2id) and salt generation/storage. Requires secure key generation and management.


## 4.4. Encryption Examples

* Encrypt file with interactive password:
```bash
py -m cryptoolsec.main encrypt -i document.txt -o document.enc --password-interactive
# Enter password when prompted
```

* Encrypt file using a password stored in `pass.txt`:
```bash
py -m cryptoolsec.main encrypt -i photo.jpg -o photo.jpg.enc --password-file pass.txt
```

* Encrypt file using a raw key from `my.key` (verbose output):
```bash
# First, ensure my.key contains exactly 32 raw bytes
# Example generation (replace with a secure method if needed):
# py -c "import sys, os; sys.stdout.buffer.write(os.urandom(32))" > my.key

py -m cryptoolsec.main encrypt -v --keyfile my.key -i archive.zip -o archive.zip.enc
```


## 4.5. Decryption Examples

* Decrypt file with interactive password:
```bash
py -m cryptoolsec.main decrypt -i document.enc -o document_dec.txt --password-interactive
# Enter the original password when prompted
```

* Decrypt file using a password stored in `pass.txt`:
```bash
py -m cryptoolsec.main decrypt -i photo.jpg.enc -o photo_dec.jpg --password-file pass.txt
```

* Decrypt file using a raw key from `my.key` (quiet mode):
```bash
py -m cryptoolsec.main decrypt -q --keyfile my.key -i archive.zip.enc -o archive_dec.zip
```

## 4.6. Using Pipes (Streams)

`cryptoolsec` handles standard input and output, allowing integration with other command-line tools via pipes (`|`).

* Encrypt data piped from another command:
```bash
# Example: Compressing and encrypting a directory
tar czf - /path/to/my_data | py -m cryptoolsec.main encrypt --password-file pass.txt > my_data.tar.gz.enc
```

* Decrypt data and pipe it to another command:
```bash
# Example: Decrypting and extracting an archive
py -m cryptoolsec.main decrypt --password-file pass.txt < my_data.tar.gz.enc | tar xzf - -C /path/to/restore/location
```

* Encrypt text directly using `echo` and password from stdin:
```bash
# Note: Requires password on first line of stdin, data on subsequent lines (if using echo like this)
# A better way for stdin password is often via a heredoc or password manager CLI
printf '%s\n%s' "MySecretPassword" "This is secret text" | py -m cryptoolsec.main encrypt --password-stdin > secret.enc
```

*Decryption Example:*
```bash
printf '%s\n' "MySecretPassword" | py -m cryptoolsec.main decrypt --password-stdin < secret.enc
# Should output: This is secret text
```

Important: When writing encrypted data to standard output without redirecting (`>`) or piping (`|`), your terminal might display garbled characters, as it's binary data.


## 5. Technologies Used

* Python 3: Core language.
* pycryptodome: Library for AES-256-GCM encryption/decryption operations.
* argon2-cffi: Library for Argon2id key derivation function.
* argparse: Standard library for parsing command-line arguments.
* getpass: Standard library for securely prompting for passwords.
* logging, os, sys: Standard libraries for logging and system interactions.


## 6. License
[MIT License](https://github.com/victorvernier/Cryptoolsec/blob/main/LICENSE)


## 7. Project Status

**Beta** - Core functionality implemented and tested. Ongoing development may occur.

Note on Efficiency: While I/O and cryptographic operations are streamed/chunked, extremely high throughput may depend on system resources (CPU for Argon2/AES, disk speed).


## 8. Contribution

Contributions, bug reports, and feature requests are welcome! Please refer to the project repository for contribution guidelines or open an [issue](https://github.com/victorvernier/Cryptoolsec/issues).


## 9. Contact

For questions or suggestions, contact: **victorvernier@protonmail.com**
