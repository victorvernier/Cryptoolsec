# cryptoolsec/core/file_handler.py
# -*- coding: utf-8 -*-
"""
Handles streaming file/standard I/O operations for encryption and decryption,
including progress reporting and error handling. Uses context managers for streams.
"""

import sys
import logging
import os
from typing import Callable
from contextlib import contextmanager

# Crypto imports needed for cipher object creation
from Crypto.Cipher import AES

# Local imports (ensure relative paths are correct based on project structure)
try:
    from .crypto_logic import derive_key, generate_salt
    from ..utils.constants import (
        AES_KEY_BYTES, SALT_BYTES, GCM_IV_BYTES, GCM_TAG_BYTES, CHUNK_SIZE
    )
    from ..utils.exceptions import (
        FileAccessError, AuthenticationError, CryptoCLIError, ArgumentError
    )
except ImportError as e:
     # Critical if core components are missing during runtime
     logging.critical(f"FileHandler: Failed to import core/utils modules: {e}", exc_info=True)
     raise

# Module-specific logger is preferred over root logger
logger = logging.getLogger(__name__)

# --- Context Manager for Stream Handling ---
@contextmanager
def stream_handler(filepath: str | None, mode: str):
    """
    Context manager to safely handle file paths or standard streams (stdin/stdout).
    Yields the appropriate stream and handles file opening/closing.
    Raises FileAccessError on issues with files.
    """
    is_std_stream = filepath is None
    stream = None
    # Log stream usage at DEBUG level
    log_stream_type = ('stdin' if 'r' in mode else 'stdout') if is_std_stream else filepath
    logger.debug(f"Attempting to access stream: {log_stream_type} in mode '{mode}'.")
    try:
        if is_std_stream:
            # Get standard stream buffer
            stream = sys.stdin.buffer if 'r' in mode else sys.stdout.buffer
            # Ensure it's not None (though unlikely for std streams in normal execution)
            if stream is None:
                 raise OSError(f"Could not access standard {'input' if 'r' in mode else 'output'} buffer.")
            logger.debug(f"Using {'stdin' if 'r' in mode else 'stdout'}.")
            yield stream # Yield the standard stream (do not close it in finally)
        else:
            # Check existence for reading modes first to provide clearer error
            if 'r' in mode and not os.path.exists(filepath):
                 # Raise standard FileNotFoundError which inherits from OSError
                 raise FileNotFoundError(f"Input file not found: {filepath}")

            # Use 'with open' for automatic and safe file closing
            with open(filepath, mode) as file_stream:
                logger.debug(f"Opened file: {filepath} successfully.")
                yield file_stream # Yield the opened file stream
            # File is automatically closed here upon exiting 'with' block
            logger.debug(f"Closed file: {filepath}")

    except (FileNotFoundError, PermissionError, OSError) as e:
        # Wrap underlying OS/builtin errors in our custom FileAccessError
        msg = f"File access error for '{log_stream_type}': {e}"
        logger.error(msg, exc_info=True) # Log full traceback for file errors
        raise FileAccessError(msg) from e
    except Exception as e: # Catch any other unexpected error during stream setup
        msg = f"Unexpected error setting up stream for '{log_stream_type}': {e}"
        logger.critical(msg, exc_info=True)
        raise CryptoCLIError(msg) from e
    # No 'finally' block needed for closing files opened with 'with'


# --- Main I/O Processing Functions ---

def process_encryption_io(
    input_path: str | None,
    output_path: str | None,
    key_or_password: bytes,
    is_key: bool,
    *, # Keyword-only marker for subsequent arguments
    progress_callback: Callable[[int], None] | None = None
) -> None:
    """
    Handles streaming encryption using context managers for I/O. Raises exceptions on failure.

    Args:
        input_path: Path to the input file, or None for stdin.
        output_path: Path to the output file, or None for stdout.
        key_or_password: The AES key or the user's password as bytes.
        is_key: Flag indicating if key_or_password is the key or password.
        progress_callback: Optional function to report progress (0-100, or -1).

    Raises:
        FileAccessError: If input/output files cannot be accessed or written.
        AuthenticationError: If key derivation fails (via derive_key).
        ArgumentError: If provided key has incorrect length.
        CryptoCLIError: For other crypto setup or unexpected errors.
        OSError: If writing to stream fails.
    """
    key: bytes | None = None
    salt: bytes | None = None
    iv: bytes | None = None
    total_size: int | None = None
    bytes_processed: int = 0
    last_percentage = -1

    try:
        # --- Get Key (Handles potential CryptoCLIError from derive_key) ---
        if is_key:
            key = key_or_password
            if len(key) != AES_KEY_BYTES: raise ArgumentError(f"Invalid key length. Expected {AES_KEY_BYTES}.")
            logger.debug("Using provided key for encryption.")
        else:
            password = key_or_password
            salt = generate_salt()
            key = derive_key(password, salt) # Can raise CryptoCLIError
            logger.debug("Derived key from password.")

        # --- Get Input Size ---
        if input_path:
            try:
                total_size = os.path.getsize(input_path)
                logger.debug(f"Input file size: {total_size} bytes.")
            except OSError as e:
                total_size = None
                logger.warning(f"Could not get size of input file '{input_path}': {e}")
        else:
            total_size = None
            logger.info("Using stdin for input (size unknown). Progress unavailable.")
            if progress_callback: progress_callback(-1) # Signal indeterminate

        # --- Process Streams ---
        # stream_handler manages opening/closing and related FileAccessErrors
        with stream_handler(input_path, 'rb') as input_stream, \
             stream_handler(output_path, 'wb') as output_stream:

            # --- Write Header ---
            if salt:
                logging.debug(f"Attempting to write {len(salt)} salt bytes...")
                bytes_written = output_stream.write(salt)
                if bytes_written != len(salt): raise OSError(f"Failed to write all salt bytes to output.")
                logging.debug(f"Finished writing salt.")
            iv = os.urandom(GCM_IV_BYTES)
            logging.debug(f"Attempting to write {len(iv)} IV bytes...")
            bytes_written = output_stream.write(iv)
            if bytes_written != len(iv): raise OSError(f"Failed to write all IV bytes to output.")
            logging.debug(f"Finished writing IV.")

            # --- Encrypt in Chunks ---
            if not isinstance(key, bytes): raise CryptoCLIError("Internal: Key is not bytes.")
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            logger.info("Starting chunk encryption...")

            while chunk := input_stream.read(CHUNK_SIZE):
                encrypted_chunk = cipher.encrypt(chunk)
                logging.debug(f"Attempting to write {len(encrypted_chunk)} encrypted bytes...")
                bytes_written = output_stream.write(encrypted_chunk)
                if bytes_written != len(encrypted_chunk): raise OSError("Failed to write all encrypted chunk bytes.")
                logging.debug(f"Finished writing encrypted chunk.")
                bytes_processed += len(chunk)

                # Report Progress
                if progress_callback:
                    if total_size is not None and total_size > 0:
                        percentage = int((bytes_processed / total_size) * 100)
                        if percentage > last_percentage:
                             progress_callback(percentage)
                             last_percentage = percentage
                    # No else needed, indeterminate already signaled if applicable

            if bytes_processed == 0: logger.warning("Input data was empty.")
            logger.info(f"Finished encrypting {bytes_processed} plaintext bytes.")
            if progress_callback and total_size is not None and last_percentage < 100:
                 progress_callback(100) # Ensure 100%

            # --- Finalize and Write Tag ---
            tag = cipher.digest()
            logging.debug(f"Attempting to write {len(tag)} tag bytes...")
            bytes_written = output_stream.write(tag)
            if bytes_written != len(tag): raise OSError("Failed to write all GCM tag bytes.")
            logging.debug(f"Finished writing tag.")
            logging.debug("Attempting to flush output stream...")
            output_stream.flush() # Ensure buffers are written to underlying file descriptor
            logging.debug("Output stream flushed.")

        # If 'with' blocks exit without error, log overall success of stream handling
        logger.info("Successfully exited stream context managers for encryption.")

    # Exception Handling Strategy:
    # - Let specific exceptions (FileAccessError, ArgumentError, CryptoCLIError, ValueError)
    #   raised internally or by called functions propagate up.
    # - Catch broad OSError for write errors inside the 'with' block.
    # - Catch generic Exception for truly unexpected issues.
    # - Logging occurs near the error source. User message printed before raise or included in exception.
    except (FileAccessError, ArgumentError, CryptoCLIError, ValueError) as e:
        # These should have been logged already, just re-raise for handler
        # Add context log message if helpful
        logger.error(f"Encryption failed due to expected error type: {type(e).__name__}")
        raise
    except OSError as e: # Catch write/flush errors within the 'with' block
         msg = f"File write/flush error during encryption: {e}"
         logger.error(msg, exc_info=True)
         # Wrap in FileAccessError for consistent handling by upstream caller
         raise FileAccessError(msg) from e
    except Exception as e: # Catch any other unexpected errors
        msg = "An unexpected error occurred during encryption process."
        logger.critical(msg + f" Details: {e}", exc_info=True)
        # Wrap in generic app error
        raise CryptoCLIError(msg) from e


def process_decryption_io(
    input_path: str | None,
    output_path: str | None,
    key_or_password: bytes,
    is_key: bool,
    *, # Keyword-only marker
    progress_callback: Callable[[int], None] | None = None
) -> None:
    """
    Handles streaming decryption using context managers for I/O. Raises exceptions on failure.
    (Docstring args/raises como antes)
    """
    key: bytes | None = None
    salt: bytes | None = None
    iv: bytes | None = None
    total_size: int | None = None
    bytes_processed: int = 0 # Processed ciphertext bytes (after header)
    header_size = 0
    last_percentage = -1
    ciphertext_total_size: int | None = None

    try:
        # --- Get Input Size ---
        if input_path:
             try:
                 total_size = os.path.getsize(input_path)
                 logger.debug(f"Input file size: {total_size} bytes.")
             except OSError as e:
                 total_size = None
                 logger.warning(f"Could not get size of input file '{input_path}': {e}")
        else:
            total_size = None
            logger.info("Using stdin for input (size unknown). Progress unavailable.")
            if progress_callback: progress_callback(-1)

        # --- Process Streams using Context Managers ---
        with stream_handler(input_path, 'rb') as input_stream, \
             stream_handler(output_path, 'wb') as output_stream:

            # --- Read Header and Get Key ---
            if is_key:
                key = key_or_password
                if len(key) != AES_KEY_BYTES: raise ArgumentError("Invalid key length.")
                logger.debug("Using provided key (Salt not read).")
                iv = input_stream.read(GCM_IV_BYTES)
                if len(iv) != GCM_IV_BYTES: raise ValueError(f"Input too short: Could not read {GCM_IV_BYTES}-byte IV.")
                header_size = GCM_IV_BYTES
                logging.debug(f"Read {len(iv)} IV bytes.")
            else:
                password = key_or_password
                salt = input_stream.read(SALT_BYTES)
                if len(salt) != SALT_BYTES: raise ValueError(f"Input too short: Could not read {SALT_BYTES}-byte Salt.")
                logging.debug(f"Read {len(salt)} salt bytes.")
                key = derive_key(password, salt) # Can raise CryptoCLIError
                iv = input_stream.read(GCM_IV_BYTES)
                if len(iv) != GCM_IV_BYTES: raise ValueError(f"Input too short: Could not read {GCM_IV_BYTES}-byte IV after Salt.")
                header_size = SALT_BYTES + GCM_IV_BYTES
                logging.debug(f"Read {len(iv)} IV bytes after salt. Key derived.")

            # Validate total size vs header/tag
            min_expected_size = header_size + GCM_TAG_BYTES
            if total_size is not None:
                if total_size < min_expected_size:
                     # Use ValueError for format issues
                     raise ValueError(f"Input file size ({total_size}b) is too small for header ({header_size}b) and tag ({GCM_TAG_BYTES}b).")
                ciphertext_total_size = total_size - min_expected_size
                logging.debug(f"Calculated ciphertext size: {ciphertext_total_size} bytes.")
                if ciphertext_total_size == 0: logger.warning("Input contains only header and tag.")

            # --- Decrypt in Chunks (Buffering for Tag) ---
            if not isinstance(key, bytes) or not isinstance(iv, bytes):
                 raise CryptoCLIError("Internal: Decryption key or IV is not bytes.")

            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            logger.info("Starting chunk decryption...")

            buffer = b''
            tag: bytes | None = None # Initialize tag as None

            while True:
                chunk = input_stream.read(CHUNK_SIZE)
                if not chunk: # End of input stream
                    if len(buffer) < GCM_TAG_BYTES:
                        raise ValueError(f"Input ended unexpectedly. Missing or incomplete tag? Final buffer size {len(buffer)}, need {GCM_TAG_BYTES}.")
                    # Process final part (all buffer except tag)
                    tag = buffer[-GCM_TAG_BYTES:] # Extract tag first
                    to_process = buffer[:-GCM_TAG_BYTES]
                    buffer = b'' # Buffer is now empty or only contained tag
                    if to_process: # Only decrypt if there's ciphertext before the tag
                         try:
                             decrypted_chunk = cipher.decrypt(to_process)
                         except ValueError as e:
                             logger.error("Decryption error processing final chunk.", exc_info=True)
                             raise AuthenticationError("Decryption error on final chunk.") from e
                         output_stream.write(decrypted_chunk) # Could raise OSError
                         bytes_processed += len(to_process)
                         logger.debug(f"Decrypted final chunk: {len(to_process)} -> {len(decrypted_chunk)} bytes.")
                    break # Exit loop after processing final buffer

                else: # Still reading chunks
                    buffer += chunk
                    # Process buffer if it holds significantly more than the tag size
                    # Keep at least TAG_BYTES + a small margin (or 0) in buffer? Let's just keep TAG_BYTES.
                    if len(buffer) > GCM_TAG_BYTES:
                         process_len = len(buffer) - GCM_TAG_BYTES
                         to_process = buffer[:process_len]
                         buffer = buffer[process_len:]
                         try:
                             decrypted_chunk = cipher.decrypt(to_process)
                         except ValueError as e:
                             logger.error("Decryption error during streaming chunk.", exc_info=True)
                             raise AuthenticationError("Decryption error during streaming.") from e
                         output_stream.write(decrypted_chunk) # Could raise OSError
                         bytes_processed += len(to_process)
                         # logger.debug(f"Decrypted chunk: {len(to_process)} -> {len(decrypted_chunk)} bytes.") # Too verbose

                         # Report Progress
                         if progress_callback:
                             if ciphertext_total_size is not None and ciphertext_total_size > 0:
                                 percentage = int((bytes_processed / ciphertext_total_size) * 100)
                                 # Throttle progress updates
                                 if percentage > last_percentage and (percentage % 5 == 0 or percentage == 100):
                                     progress_callback(percentage)
                                     last_percentage = percentage
                             # else: indeterminate already signaled

            # --- Final Tag Verification ---
            if tag is None:
                 # This should only happen if input stream was completely empty after header
                 # And total_size didn't catch it earlier
                 if bytes_processed == 0 and ciphertext_total_size == 0:
                      logger.warning("Input contained only header and tag. Attempting verification.")
                      # Need to read the tag if buffer logic didn't catch it (e.g. exact TAG_SIZE read last)
                      # Rereading the last read chunk logic might be safer.
                      # Let's assume the buffer logic is correct and tag is set if input had >= TAG_SIZE after header.
                      # If ciphertext_total_size == 0, the loop didn't run, buffer might hold only tag.
                      if len(buffer) == GCM_TAG_BYTES: # Check if buffer holds exactly the tag now
                           tag = buffer
                      else: # If buffer size is wrong, previous checks should have failed
                           raise CryptoCLIError("Internal logic error: Tag could not be extracted for verification.")
                 else:
                    raise CryptoCLIError("Internal logic error: Tag is None after processing.")


            try:
                cipher.verify(tag)
                logging.info(f"Tag verification successful. Total ciphertext bytes processed: {bytes_processed}.")
                if progress_callback and last_percentage < 100:
                     progress_callback(100)
            except ValueError as e:
                # The specific error for MAC check failure
                msg = "MAC check failed: Incorrect password/key or data corrupted."
                logger.error(msg)
                # Print user message directly for this critical failure
                print(f"Error: {msg}", file=sys.stderr)
                raise AuthenticationError(msg) # Raise specific error type

        logger.info("Successfully exited stream context managers for decryption.")

    # Exception Handling (similar structure to encryption)
    except AuthenticationError as e:
        logger.error(f"Decryption failed due to authentication/corruption: {e}")
        # Message likely printed already (MAC fail) or included in exception
        raise
    except (FileAccessError, ArgumentError, ValueError) as e: # File, setup, or format errors
        logger.error(f"Decryption failed due to file/setup/format error: {e}", exc_info=True)
        print(f"Error: {e}", file=sys.stderr) # Ensure user sees format/file errors
        # Map ValueError (likely format/header error) to AuthenticationError for user simplicity?
        if isinstance(e, ValueError):
             raise AuthenticationError(f"Invalid input data format: {e}") from e
        else:
             raise # Re-raise FileAccessError, ArgumentError
    except CryptoCLIError as e: # Other known app errors (like derive_key failure)
         logger.error(f"Decryption failed: {e}", exc_info=True)
         print(f"Error: {e}", file=sys.stderr)
         raise
    except OSError as e: # Catch potential write errors inside the 'with' block
         msg = f"File write error during decryption: {e}"
         logger.error(msg, exc_info=True)
         print(f"Error: {msg}", file=sys.stderr)
         raise FileAccessError(msg) from e
    except Exception as e:
        msg = "An unexpected error occurred during decryption."
        logger.critical(msg + f" Details: {e}", exc_info=True)
        print(f"Error: {msg}", file=sys.stderr)
        raise CryptoCLIError(msg) from e
    # No 'finally' block for closing needed due to 'with'