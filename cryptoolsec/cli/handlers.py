# handlers.py
# -*- coding: utf-8 -*-
"""Command handlers for the Cryptoolsec CLI."""

import logging
import sys
import os # For OSError potentially

# Import local modules using relative paths
from .password_utils import (
    get_interactive_password,
    read_password_file,
    read_key_file,
    read_password_stdin
)
# Assuming core and utils are siblings or accessible in PYTHONPATH
from ..core.file_handler import process_encryption_io, process_decryption_io
from ..utils.exceptions import FileAccessError, AuthenticationError, ArgumentError, CryptoCLIError
from ..utils.constants import EXIT_SUCCESS, EXIT_GENERIC_ERROR, EXIT_FILE_ERROR, EXIT_AUTH_ERROR, EXIT_ARG_ERROR

logger = logging.getLogger(__name__)

def handle_encrypt(args) -> int:
    """
    Handles the 'encrypt' command.

    Retrieves the password or key based on command-line arguments,
    then delegates the encryption process to the file handler.
    Maps exceptions to appropriate exit codes.

    Args:
        args: The argparse namespace containing parsed command-line arguments.

    Returns:
        An integer exit code (0 for success, non-zero for errors).
    """
    logger.info("Processing 'encrypt' command...")
    password_bytes: bytes | None = None
    key_bytes: bytes | None = None

    try:
        # --- Get password/key ---
        # Determine the source of the secret based on provided arguments
        if args.password_interactive:
            password_bytes = get_interactive_password()
            logger.info("Password obtained interactively.")
        elif args.password_file:
            password_bytes = read_password_file(args.password_file)
            logger.info("Password obtained from file.")
        elif args.password_stdin:
            password_bytes = read_password_stdin()
            logger.info("Password obtained from stdin.")
        elif args.keyfile:
            key_bytes = read_key_file(args.keyfile)
            logger.info("Key obtained from file.")
        # else: argparse mutually exclusive group ensures one of these options is present.

        # --- Delegate I/O and Encryption ---
        # Call the core encryption logic with the obtained secret
        if key_bytes:
            process_encryption_io(args.input, args.output, key_bytes, is_key=True)
        elif password_bytes:
            process_encryption_io(args.input, args.output, password_bytes, is_key=False)
        else:
            # Safety check in case argparse validation somehow fails.
            raise ArgumentError("Internal logic error: No key or password available for encryption.")

        logger.info("Encryption process finished successfully.")
        return EXIT_SUCCESS

    # --- Exception Handling and Exit Code Mapping ---
    # Catch specific exceptions and map to exit codes.
    # Error messages are assumed to be printed/logged by the function that originally raised the exception.
    except (FileAccessError, OSError) as e: # Catch file system and general OS I/O errors
        logger.error(f"File access or OS error during encryption handler: {e}") # Log context
        # Error message assumed to be printed/logged by the function that raised the exception.
        return EXIT_FILE_ERROR
    except AuthenticationError as e: # Password mismatch, key derivation failure
        logger.error(f"Authentication error during encryption handler: {e}")
        return EXIT_AUTH_ERROR
    except (ArgumentError, ValueError) as e: # Invalid args (empty file, bad key len), config issues
        logger.error(f"Argument or value error during encryption handler: {e}")
        return EXIT_ARG_ERROR
    except CryptoCLIError as e: # Generic application error during crypto process
        # Additional log at the handler level for context.
        logger.error(f"Application error during encryption processing: {e}")
        return EXIT_GENERIC_ERROR
    except Exception as e: # Catch any other unexpected errors
        logger.critical(f"Unexpected error during encryption handling: {e}", exc_info=True)
        # Provide a generic error message to the user for unexpected issues.
        print(f"Error: An unexpected error occurred during encryption.", file=sys.stderr)
        return EXIT_GENERIC_ERROR

def handle_decrypt(args) -> int:
    """
    Handles the 'decrypt' command.

    Retrieves the password or key based on command-line arguments,
    then delegates the decryption process to the file handler.
    Maps exceptions to appropriate exit codes.

    Args:
        args: The argparse namespace containing parsed command-line arguments.

    Returns:
        An integer exit code (0 for success, non-zero for errors).
    """
    logger.info("Processing 'decrypt' command...")
    password_bytes: bytes | None = None
    key_bytes: bytes | None = None

    try:
        # --- Get password/key ---
        # Determine the source of the secret based on provided arguments
        if args.password_interactive:
            password_bytes = get_interactive_password()
            logger.info("Password obtained interactively.")
        elif args.password_file:
            password_bytes = read_password_file(args.password_file)
            logger.info("Password obtained from file.")
        elif args.password_stdin:
            password_bytes = read_password_stdin()
            logger.info("Password obtained from stdin.")
        elif args.keyfile:
            key_bytes = read_key_file(args.keyfile)
            logger.info("Key obtained from file.")
        # else: argparse mutually exclusive group ensures one of these options is present.

        # --- Delegate I/O and Decryption ---
        # Call the core decryption logic with the obtained secret
        if key_bytes:
            process_decryption_io(args.input, args.output, key_bytes, is_key=True)
        elif password_bytes:
            process_decryption_io(args.input, args.output, password_bytes, is_key=False)
        else:
            # Safety check in case argparse validation somehow fails.
            raise ArgumentError("Internal logic error: No key or password available for decryption.")

        logger.info("Decryption process finished successfully.")
        return EXIT_SUCCESS

    # --- Exception Handling and Exit Code Mapping ---
    # Catch specific exceptions and map to exit codes.
    # Error messages are assumed to be printed/logged by the function that originally raised the exception.
    except (FileAccessError, OSError) as e: # Catch file system and general OS I/O errors
        logger.error(f"File access or OS error during decryption handler: {e}")
        return EXIT_FILE_ERROR
    except AuthenticationError as e: # Primarily for MAC check failures or key derivation/header errors.
        logger.error(f"Authentication error during decryption handler: {e}")
        return EXIT_AUTH_ERROR
    except (ArgumentError, ValueError) as e: # Invalid args, config issues, potentially truncated input leading to ValueError
        logger.error(f"Argument or value error during decryption handler: {e}")
        return EXIT_ARG_ERROR
    except CryptoCLIError as e: # Generic application error during crypto process
        # Additional log at the handler level for context.
        logger.error(f"Application error during decryption processing: {e}")
        return EXIT_GENERIC_ERROR
    except Exception as e: # Catch any other unexpected errors
        logger.critical(f"Unexpected error during decryption handling: {e}", exc_info=True)
        # Provide a generic error message to the user for unexpected issues.
        print(f"Error: An unexpected error occurred during decryption.", file=sys.stderr)
        return EXIT_GENERIC_ERROR