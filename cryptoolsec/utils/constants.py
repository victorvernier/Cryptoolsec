# constants.py
# -*- coding: utf-8 -*-
"""Defines constants used throughout the Cryptoolsec application."""

# --- AES-GCM Parameters ---
AES_KEY_BYTES: int = 32  # AES-256 key size in bytes
GCM_IV_BYTES: int = 12   # Recommended IV size for GCM (96 bits)
GCM_TAG_BYTES: int = 16  # Standard GCM authentication tag size (128 bits)

# --- Key Derivation Parameters ---
SALT_BYTES: int = 16     # Size of the salt for key derivation (common size)

# Argon2 Parameters (Example values - can be tuned based on security requirements and performance)
ARGON2_TIME_COST: int = 3       # Number of iterations (increases computation time)
ARGON2_MEMORY_COST_KIB: int = 65536 # Memory cost in KiB (64 MiB) (increases memory usage)
ARGON2_PARALLELISM: int = 4       # Degree of parallelism (adjust based on available cores)

# --- File I/O ---
CHUNK_SIZE: int = 64 * 1024  # 64 KB buffer size for efficient streaming file I/O

# --- Exit Codes ---
# Standard exit codes for shell script compatibility and error identification
EXIT_SUCCESS: int = 0        # Operation completed successfully
EXIT_GENERIC_ERROR: int = 1  # Generic or unexpected runtime error
EXIT_FILE_ERROR: int = 2     # File access/IO error (e.g., not found, permission denied)
EXIT_AUTH_ERROR: int = 3     # Authentication/crypto error (e.g., bad password/key, MAC check fail)
EXIT_ARG_ERROR: int = 4      # Invalid command-line arguments or configuration error
EXIT_INTERRUPT: int = 130    # Process interrupted by user (commonly Ctrl+C -> SIGINT)