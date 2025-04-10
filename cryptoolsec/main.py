# main.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Main entry point for the Cryptoolsec CLI application."""

import argparse
import sys
import logging

# Import local modules relative to the 'cryptoolsec' package
# Use relative import if the package is installed or run as a module (`python -m cryptoolsec`)
from .cli.handlers import handle_encrypt, handle_decrypt
# OR use absolute import if the structure allows direct script execution from the root
# from cli.handlers import handle_encrypt, handle_decrypt
from .utils.constants import EXIT_SUCCESS, EXIT_GENERIC_ERROR, EXIT_INTERRUPT # Import exit codes

# Note: Adjust imports based on how you structure/run the final package

def create_parser():
    """Creates and configures the argument parser."""
    parser = argparse.ArgumentParser(
        prog="cryptoolsec",
        description="CLI Tool for AES-256-GCM Encryption/Decryption.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  cryptoolsec encrypt -i file.txt -o file.enc --password-interactive
  echo 'mypassword' | cryptoolsec decrypt --password-stdin -i file.enc -o file.dec
  cryptoolsec encrypt --verbose --keyfile my.key -i large.zip -o large.zip.enc
  cryptoolsec decrypt -q --keyfile my.key -i large.zip.enc
"""
    )
    parser.add_argument('-V', '--version', action='version', version='%(prog)s 0.1.0')

    # --- Logging Control Group ---
    log_level_group = parser.add_mutually_exclusive_group()
    log_level_group.add_argument(
        '-q', '--quiet',
        action='store_const',
        const=logging.ERROR,
        dest='log_level',
        help='Show only error messages.'
    )
    log_level_group.add_argument(
        '-v', '--verbose',
        action='store_const',
        const=logging.DEBUG,
        dest='log_level',
        help='Show detailed debug messages.'
    )
    parser.set_defaults(log_level=logging.INFO) # Default log level

    # --- Subparsers ---
    subparsers = parser.add_subparsers(dest='command', help='Available commands (encrypt/decrypt)', required=True)

    # --- Encrypt Command ---
    parser_encrypt = subparsers.add_parser('encrypt', help='Encrypt a file or stdin.')
    parser_encrypt.add_argument('-i', '--input', type=str, default=None, metavar='FILE', help='Input file path (default: stdin).')
    parser_encrypt.add_argument('-o', '--output', type=str, default=None, metavar='FILE', help='Output file path (default: stdout).')
    pw_group_enc = parser_encrypt.add_mutually_exclusive_group(required=True)
    pw_group_enc.add_argument('--password-interactive', action='store_true', help='Prompt for password interactively.')
    pw_group_enc.add_argument('--password-file', type=str, metavar='FILE', help='File containing the password.')
    pw_group_enc.add_argument('--password-stdin', action='store_true', help='Read password from stdin.')
    pw_group_enc.add_argument('--keyfile', type=str, metavar='FILE', help='File containing the raw AES key.')
    parser_encrypt.set_defaults(func=handle_encrypt)

    # --- Decrypt Command ---
    parser_decrypt = subparsers.add_parser('decrypt', help='Decrypt a file or stdin.')
    parser_decrypt.add_argument('-i', '--input', type=str, default=None, metavar='FILE', help='Input encrypted file path (default: stdin).')
    parser_decrypt.add_argument('-o', '--output', type=str, default=None, metavar='FILE', help='Output decrypted file path (default: stdout).')
    pw_group_dec = parser_decrypt.add_mutually_exclusive_group(required=True)
    pw_group_dec.add_argument('--password-interactive', action='store_true', help='Prompt for password interactively.')
    pw_group_dec.add_argument('--password-file', type=str, metavar='FILE', help='File containing the password.')
    pw_group_dec.add_argument('--password-stdin', action='store_true', help='Read password from stdin.')
    pw_group_dec.add_argument('--keyfile', type=str, metavar='FILE', help='File containing the raw AES key.')
    parser_decrypt.set_defaults(func=handle_decrypt)

    return parser

def main():
    """Main execution function: parses arguments, sets up logging, and calls the appropriate handler."""
    parser = create_parser()
    exit_code = EXIT_SUCCESS # Default to success

    try:
        args = parser.parse_args()

        # --- Configure Logging ---
        log_level = args.log_level
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        # Use a more detailed format for debug level
        if log_level <= logging.DEBUG:
            log_format = '%(asctime)s - %(levelname)s - [%(name)s:%(lineno)d] - %(message)s'

        # Configure the root logger to output to stderr.
        # `force=True` removes and replaces any existing handlers for the root logger,
        # ensuring clean configuration even if this function were somehow called multiple times.
        logging.basicConfig(level=log_level, format=log_format, stream=sys.stderr, force=True)

        logging.debug(f"Log level set to: {logging.getLevelName(log_level)}")
        logging.debug(f"Command: {args.command}")
        # Security: Avoid logging the full args object directly, especially if it might contain sensitive info.
        # Log specific, safe attributes individually if needed for debugging (e.g., input/output paths).
        # logging.debug(f"Input: {args.input or 'stdin'}") # Example if needed, handlers likely log this
        # logging.debug(f"Output: {args.output or 'stdout'}") # Example if needed

        # --- Dispatch to Handler ---
        # The handler function (handle_encrypt or handle_decrypt) is responsible
        # for executing the command logic and returning the appropriate exit code.
        exit_code = args.func(args)

    except SystemExit as e:
        # Catch SystemExit to allow normal exits (e.g., from argparse help/version,
        # or Ctrl+C captured cleanly in password_utils resulting in sys.exit).
        exit_code = e.code or EXIT_SUCCESS # Use explicit code if provided, otherwise assume success
    except Exception as e:
        # Catch any unhandled exceptions that propagate up to the main function.
        # Log the full exception details for debugging.
        logging.critical(f"An unhandled exception reached main: {e}", exc_info=True)
        # Provide a user-friendly error message, avoiding a raw traceback by default.
        print(f"\nCritical Error: An unexpected error occurred. Use --verbose for more details or check logs.", file=sys.stderr)
        exit_code = EXIT_GENERIC_ERROR
    finally:
        logging.debug(f"Exiting with code: {exit_code}")
        sys.exit(exit_code)

if __name__ == "__main__":
    # This construct allows the script to be run directly using:
    # 1. `python -m cryptoolsec.main` (if cryptoolsec is importable/installed)
    # 2. `python path/to/cryptoolsec/main.py` (if PYTHONPATH is set correctly or run from parent dir)
    main()