# password_utils.py
# -*- coding: utf-8 -*-
"""Utilities for handling passwords and keys from various sources."""

import getpass
import sys
import logging
import os

# Import constants and exceptions
from ..utils.constants import AES_KEY_BYTES, EXIT_INTERRUPT
from ..utils.exceptions import FileAccessError, AuthenticationError, ArgumentError, CryptoCLIError

logger = logging.getLogger(__name__)

def get_interactive_password() -> bytes:
    """
    Prompts the user interactively for a password and confirmation.

    Returns:
        The confirmed password as bytes (utf-8 encoded).

    Raises:
        AuthenticationError: If passwords do not match.
        CryptoCLIError: On other unexpected errors during input.
        SystemExit: If the user cancels with Ctrl+C (exits with EXIT_INTERRUPT).
    """
    try:
        password_prompt = "Enter password: "
        password = getpass.getpass(prompt=password_prompt)
        password_confirm_prompt = "Confirm password: "
        password_confirm = getpass.getpass(prompt=password_confirm_prompt)

        if password == password_confirm:
            logger.info("Password confirmed interactively.")
            # Ensure password returned is bytes
            return password.encode('utf-8')
        else:
            msg = "Error: Passwords do not match."
            # Avoid logging the password itself, even on mismatch
            logger.error("Interactive password entry failed: passwords mismatch.")
            print(msg, file=sys.stderr)
            raise AuthenticationError("Passwords do not match.")

    except KeyboardInterrupt:
        print("\nOperation cancelled by user.", file=sys.stderr)
        logger.warning("Password entry cancelled by user (KeyboardInterrupt).")
        sys.exit(EXIT_INTERRUPT) # Exit directly on Ctrl+C during password input
    except EOFError:
        # Handle case where getpass stdin is closed unexpectedly (e.g., redirected from /dev/null)
        msg = "Error: Could not read password from standard input (EOF)."
        logger.error(msg)
        print(msg, file=sys.stderr)
        raise CryptoCLIError(msg) from None # No underlying exception to chain
    except Exception as e:
        # Catch other potential issues with getpass or encoding
        msg = f"Error getting password interactively: {e}"
        logger.error(msg, exc_info=True)
        print(f"Error: An unexpected issue occurred during password entry.", file=sys.stderr)
        raise CryptoCLIError(msg) from e

def read_password_file(filepath: str) -> bytes:
    """
    Reads the password from the first line of the specified file.

    Args:
        filepath: Path to the password file.

    Returns:
        The password bytes (read as binary, stripped).

    Raises:
        FileAccessError: If the file cannot be found or read due to permissions/OS issues.
        ArgumentError: If the file is empty.
        CryptoCLIError: On other unexpected errors.
    """
    logger.debug(f"Attempting to read password from file: {filepath}")
    if not os.path.exists(filepath):
        msg = f"Password file not found: {filepath}"
        logger.error(msg)
        raise FileAccessError(msg)
    try:
        with open(filepath, 'rb') as f:
            # Read the first line only and strip leading/trailing whitespace/newlines
            password_bytes = f.readline().strip()

        if not password_bytes:
            msg = f"Password file is empty: {filepath}"
            logger.error(msg)
            # Treat empty file as bad argument/config
            raise ArgumentError(msg)

        logger.info(f"Password successfully read from file: {filepath}")
        return password_bytes
    except PermissionError as e:
        msg = f"Permission denied reading password file: {filepath}"
        logger.error(msg)
        raise FileAccessError(msg) from e
    except OSError as e:
        msg = f"OS error reading password file {filepath}: {e}"
        logger.error(msg, exc_info=True)
        raise FileAccessError(msg) from e
    except Exception as e:
        msg = f"Unexpected error reading password file {filepath}: {e}"
        logger.error(msg, exc_info=True)
        raise CryptoCLIError(msg) from e

def read_key_file(filepath: str) -> bytes:
    """
    Reads the raw key from the specified file and validates its length.

    Args:
        filepath: Path to the key file.

    Returns:
        The key bytes if the length is correct (AES_KEY_BYTES).

    Raises:
        FileAccessError: If the file cannot be found or read due to permissions/OS issues.
        ArgumentError: If the key length is incorrect.
        CryptoCLIError: On other unexpected errors.
    """
    logger.debug(f"Attempting to read key from file: {filepath}")
    if not os.path.exists(filepath):
        msg = f"Key file not found: {filepath}"
        logger.error(msg)
        raise FileAccessError(msg)
    try:
        with open(filepath, 'rb') as f:
            # Read the entire file content as the raw key
            key_bytes = f.read()

        if len(key_bytes) != AES_KEY_BYTES:
            msg = f"Invalid key length in file {filepath}. Expected {AES_KEY_BYTES} bytes, got {len(key_bytes)}."
            logger.error(msg)
            # Invalid key is an argument/config error
            raise ArgumentError(msg)

        logger.info(f"Key successfully read and validated from file: {filepath}")
        return key_bytes
    except PermissionError as e:
        msg = f"Permission denied reading key file: {filepath}"
        logger.error(msg)
        raise FileAccessError(msg) from e
    except OSError as e:
        msg = f"OS error reading key file {filepath}: {e}"
        logger.error(msg, exc_info=True)
        raise FileAccessError(msg) from e
    except Exception as e:
        msg = f"Unexpected error reading key file {filepath}: {e}"
        logger.error(msg, exc_info=True)
        raise CryptoCLIError(msg) from e

def read_password_stdin() -> bytes:
    """
    Reads the password from the first line of standard input.
    Intended for piped input, not interactive use.

    Returns:
        The password bytes (read as binary, stripped).

    Raises:
        ArgumentError: If stdin is a TTY or if no data is received.
        CryptoCLIError: On other unexpected errors.
    """
    logger.debug("Attempting to read password from stdin.")
    try:
        # Check if stdin is interactive (TTY); fail if so, as this mode expects piped input.
        if sys.stdin.isatty():
             msg = "Cannot read password from TTY stdin using --password-stdin. Pipe input (e.g., echo 'pass' | ...) or use --password-interactive."
             logger.error(msg)
             raise ArgumentError(msg)

        # Read the first line from stdin buffer and strip whitespace/newlines
        password_bytes = sys.stdin.buffer.readline().strip()

        if not password_bytes:
            msg = "No password received from stdin."
            logger.error(msg)
            # Treat empty stdin as bad argument/usage
            raise ArgumentError(msg)

        logger.info("Password successfully read from stdin.")
        return password_bytes
    except Exception as e:
        # Catch potential errors reading from stdin buffer
        msg = f"Error reading password from stdin: {e}"
        logger.error(msg, exc_info=True)
        raise CryptoCLIError(msg) from e