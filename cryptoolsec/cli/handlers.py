# cryptoolsec/cli/handlers.py
# -*- coding: utf-8 -*-
"""Command handlers for the Cryptoolsec CLI."""

import logging
import sys
import os # Keep for OSError check

# Absolute imports from the project package root
try:
    from cryptoolsec.cli.password_utils import (
        get_interactive_password,
        read_password_file,
        read_key_file,
        read_password_stdin
    )
    from cryptoolsec.core.file_handler import process_encryption_io, process_decryption_io
    from cryptoolsec.utils.exceptions import FileAccessError, AuthenticationError, ArgumentError, CryptoCLIError
    from cryptoolsec.utils.constants import EXIT_SUCCESS, EXIT_GENERIC_ERROR, EXIT_FILE_ERROR, EXIT_AUTH_ERROR, EXIT_ARG_ERROR
except ImportError as e:
     logging.critical(f"Handlers: Failed to import required modules: {e}", exc_info=True)
     raise

logger = logging.getLogger(__name__)

def handle_encrypt(args) -> int:
    """
    Handles the 'encrypt' command. Maps exceptions to exit codes.
    (Full docstring from previous version)
    """
    logger.info("Processing 'encrypt' command...")
    password_bytes: bytes | None = None
    key_bytes: bytes | None = None

    try:
        # --- Get password/key ---
        if args.password_interactive: password_bytes = get_interactive_password()
        elif args.password_file: password_bytes = read_password_file(args.password_file)
        elif args.password_stdin: password_bytes = read_password_stdin()
        elif args.keyfile: key_bytes = read_key_file(args.keyfile)

        if key_bytes: logger.info("Key obtained.")
        elif password_bytes: logger.info("Password obtained.")

        # --- Delegate I/O and Encryption ---
        if key_bytes:
            process_encryption_io(args.input, args.output, key_bytes, is_key=True)
        elif password_bytes:
            process_encryption_io(args.input, args.output, password_bytes, is_key=False)
        else:
            raise ArgumentError("Internal logic error: No key or password available for encryption.")

        logger.info("Encryption process finished successfully.")
        return EXIT_SUCCESS

    # --- Exception Handling and Exit Code Mapping (CORRECT ORDER) ---
    except AuthenticationError as e: # Specific auth errors (e.g., password mismatch in interactive) first
        logger.error(f"Authentication error during encryption handler: {e}")
        return EXIT_AUTH_ERROR # Exit Code 3
    except FileAccessError as e: # Specific file access errors (incl OSError from write/open)
        logger.error(f"File access error during encryption handler: {e}")
        return EXIT_FILE_ERROR # Exit Code 2
    except (ArgumentError, ValueError) as e: # Specific argument/value/format errors
        logger.error(f"Argument or value error during encryption handler: {e}")
        return EXIT_ARG_ERROR # Exit Code 4
    except CryptoCLIError as e: # Other specific application errors (like key derivation)
        logger.error(f"Application error during encryption processing: {e}")
        return EXIT_GENERIC_ERROR # Exit Code 1
    except Exception as e: # Catch any other unexpected errors
        logger.critical(f"Unexpected error during encryption handling: {e}", exc_info=True)
        print(f"Error: An unexpected error occurred during encryption. Check logs.", file=sys.stderr)
        return EXIT_GENERIC_ERROR # Exit Code 1

def handle_decrypt(args) -> int:
    """
    Handles the 'decrypt' command. Maps exceptions to exit codes.
    (Full docstring from previous version)
    """
    logger.info("Processing 'decrypt' command...")
    password_bytes: bytes | None = None
    key_bytes: bytes | None = None

    try:
        # --- Get password/key (Identical logic to encrypt) ---
        if args.password_interactive: password_bytes = get_interactive_password()
        elif args.password_file: password_bytes = read_password_file(args.password_file)
        elif args.password_stdin: password_bytes = read_password_stdin()
        elif args.keyfile: key_bytes = read_key_file(args.keyfile)

        if key_bytes: logger.info("Key obtained.")
        elif password_bytes: logger.info("Password obtained.")

        # --- Delegate I/O and Decryption ---
        if key_bytes:
            process_decryption_io(args.input, args.output, key_bytes, is_key=True)
        elif password_bytes:
            process_decryption_io(args.input, args.output, password_bytes, is_key=False)
        else:
            raise ArgumentError("Internal logic error: No key or password available for decryption.")

        logger.info("Decryption process finished successfully.")
        return EXIT_SUCCESS

    # --- Exception Handling and Exit Code Mapping (CORRECT ORDER) ---
    # Catch MOST specific first!
    except AuthenticationError as e: # MAC check fail, potentially bad header mapped from ValueError, derive key error mapped from CryptoCLIError? Check file_handler raises.
        logger.error(f"Authentication error during decryption handler: {e}")
        return EXIT_AUTH_ERROR # <-- EXIT CODE 3!
    except FileAccessError as e: # File not found, permissions, write errors
        logger.error(f"File access error during decryption handler: {e}")
        return EXIT_FILE_ERROR # <-- EXIT CODE 2
    except (ArgumentError, ValueError) as e: # Bad key length, empty password file, other format errors from file_handler not mapped to AuthError
        logger.error(f"Argument or value error during decryption handler: {e}")
        return EXIT_ARG_ERROR # <-- EXIT CODE 4
    except CryptoCLIError as e: # Other internal errors from core/utils not fitting above categories
        logger.error(f"Application error during decryption processing: {e}")
        return EXIT_GENERIC_ERROR # <-- EXIT CODE 1
    except Exception as e: # Catch-all unexpected
        logger.critical(f"Unexpected error during decryption handling: {e}", exc_info=True)
        print(f"Error: An unexpected error occurred during decryption. Check logs.", file=sys.stderr)
        return EXIT_GENERIC_ERROR # <-- EXIT CODE 1
