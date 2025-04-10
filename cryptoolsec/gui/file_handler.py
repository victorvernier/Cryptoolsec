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
     logging.critical(f"FileHandler: Failed to import core/utils modules: {e}", exc_info=True)
     raise

logger = logging.getLogger(__name__) # Module-specific logger

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
    log_stream_type = ('stdin' if 'r' in mode else 'stdout') if is_std_stream else filepath
    logger.debug(f"Attempting to access stream: {log_stream_type} in mode '{mode}'.")
    try:
        if is_std_stream:
            stream = sys.stdin.buffer if 'r' in mode else sys.stdout.buffer
            if stream is None:
                 raise OSError(f"Could not access standard {'input' if 'r' in mode else 'output'} buffer.")
            logger.debug(f"Using {'stdin' if 'r' in mode else 'stdout'}.")
            yield stream
        else:
            if 'r' in mode and not os.path.exists(filepath):
                 raise FileNotFoundError(f"Input file not found: {filepath}")
            with open(filepath, mode) as file_stream:
                logger.debug(f"Opened file: {filepath} successfully.")
                yield file_stream
            logger.debug(f"Closed file: {filepath}")

    except (FileNotFoundError, PermissionError, OSError) as e:
        msg = f"File access error for '{log_stream_type}': {e}"
        logger.error(msg, exc_info=True)
        raise FileAccessError(msg) from e
    except Exception as e:
        msg = f"Unexpected error setting up stream for '{log_stream_type}': {e}"
        logger.critical(msg, exc_info=True)
        raise CryptoCLIError(msg) from e


# --- Main I/O Processing Functions ---

def process_encryption_io(
    input_path: str | None,
    output_path: str | None,
    key_or_password: bytes,
    is_key: bool,
    *, # Keyword-only marker
    progress_callback: Callable[[int], None] | None = None
) -> None:
    """
    Handles streaming encryption using context managers for I/O. Raises exceptions on failure.
    """
    key: bytes | None = None
    salt: bytes | None = None
    iv: bytes | None = None
    total_size: int | None = None
    bytes_processed: int = 0
    last_percentage = -1

    try:
        # Get Key
        if is_key:
            key = key_or_password
            if len(key) != AES_KEY_BYTES: raise ArgumentError(f"Invalid key length. Expected {AES_KEY_BYTES}.")
            logger.debug("Using provided key for encryption.")
        else:
            password = key_or_password
            salt = generate_salt()
            key = derive_key(password, salt) # Can raise CryptoCLIError
            logger.debug("Derived key from password.")

        # Get Input Size
        if input_path:
            try: total_size = os.path.getsize(input_path); logger.debug(f"Input file size: {total_size} bytes.")
            except OSError as e: total_size = None; logger.warning(f"Could not get size of input file '{input_path}': {e}")
        else:
            total_size = None
            logger.info("Using stdin for input (size unknown). Progress unavailable.")
            if progress_callback: progress_callback(-1)

        # Process Streams
        with stream_handler(input_path, 'rb') as input_stream, \
             stream_handler(output_path, 'wb') as output_stream:

            # Write Header
            if salt:
                logger.debug(f"Attempting to write {len(salt)} salt bytes...")
                bytes_written = output_stream.write(salt)
                if bytes_written != len(salt): raise OSError("Failed to write all salt bytes.")
                logger.debug(f"Finished writing salt.")
            iv = os.urandom(GCM_IV_BYTES)
            logger.debug(f"Attempting to write {len(iv)} IV bytes...")
            bytes_written = output_stream.write(iv)
            if bytes_written != len(iv): raise OSError("Failed to write all IV bytes.")
            logger.debug(f"Finished writing IV.")

            # Encrypt in Chunks
            if not isinstance(key, bytes): raise CryptoCLIError("Internal: Key is not bytes.")
            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            logger.info("Starting chunk encryption...")

            while chunk := input_stream.read(CHUNK_SIZE):
                encrypted_chunk = cipher.encrypt(chunk)
                logger.debug(f"Attempting to write {len(encrypted_chunk)} encrypted bytes...")
                bytes_written = output_stream.write(encrypted_chunk)
                if bytes_written != len(encrypted_chunk): raise OSError("Failed to write all encrypted chunk bytes.")
                logger.debug(f"Finished writing encrypted chunk.")
                bytes_processed += len(chunk)

                # Report Progress
                if progress_callback:
                    if total_size is not None and total_size > 0:
                        percentage = int((bytes_processed / total_size) * 100)
                        if percentage > last_percentage:
                             progress_callback(percentage)
                             last_percentage = percentage

            if bytes_processed == 0: logger.warning("Input data was empty.")
            logger.info(f"Finished encrypting {bytes_processed} plaintext bytes.")
            if progress_callback and total_size is not None and last_percentage < 100:
                 progress_callback(100)

            # Finalize and Write Tag
            tag = cipher.digest()
            logger.debug(f"Attempting to write {len(tag)} tag bytes...")
            bytes_written = output_stream.write(tag)
            if bytes_written != len(tag): raise OSError("Failed to write all GCM tag bytes.")
            logger.debug(f"Finished writing tag.")
            logger.debug("Attempting to flush output stream...")
            output_stream.flush()
            logger.debug("Output stream flushed.")

        logger.info("Successfully exited stream context managers for encryption.")
        # Verification log added previously
        if output_path:
            try:
                final_size = os.path.getsize(output_path)
                logger.info(f"VERIFICATION: Final size of '{output_path}' immediately after close is {final_size} bytes.")
                min_expected = (SALT_BYTES if salt else 0) + GCM_IV_BYTES + GCM_TAG_BYTES
                if final_size < min_expected:
                     logger.error(f"VERIFICATION ERROR: File size {final_size} is less than minimum expected {min_expected} bytes!")
            except Exception as post_e:
                 logger.error(f"VERIFICATION ERROR: Could not get size/stat of output file after write: {post_e}", exc_info=True)

    # Exception Handling
    except (FileAccessError, ArgumentError, CryptoCLIError, ValueError) as e:
        logger.error(f"Encryption failed: {e}", exc_info=True)
        print(f"Error during encryption: {e}", file=sys.stderr)
        raise
    except OSError as e:
         msg = f"File write/flush error during encryption: {e}"
         logger.error(msg, exc_info=True)
         raise FileAccessError(msg) from e
    except Exception as e:
        msg = "An unexpected error occurred during encryption process."
        logger.critical(msg + f" Details: {e}", exc_info=True)
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
    """
    key: bytes | None = None
    salt: bytes | None = None
    iv: bytes | None = None
    total_size: int | None = None
    bytes_processed: int = 0 # Processed ciphertext bytes (after header)
    header_size = 0
    last_percentage = -1
    ciphertext_total_size: int | None = None
    tag: bytes | None = None # Define tag here

    try:
        # Get Input Size
        if input_path:
             try: total_size = os.path.getsize(input_path); logger.debug(f"Input file size: {total_size} bytes.")
             except OSError as e: total_size = None; logger.warning(f"Could not get size of input file '{input_path}': {e}")
        else:
            total_size = None
            logger.info("Using stdin for input (size unknown). Progress unavailable.")
            if progress_callback: progress_callback(-1)

        # Process Streams
        with stream_handler(input_path, 'rb') as input_stream, \
             stream_handler(output_path, 'wb') as output_stream:

            # Read Header and Get Key
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
                     raise ValueError(f"Input size ({total_size}b) < min expected ({min_expected_size}b).")
                ciphertext_total_size = total_size - min_expected_size
                logging.debug(f"Calculated ciphertext size: {ciphertext_total_size} bytes.")
                if ciphertext_total_size == 0: logger.warning("Input contains only header and tag.")

            # Decrypt in Chunks (Buffering for Tag)
            if not isinstance(key, bytes) or not isinstance(iv, bytes):
                 raise CryptoCLIError("Internal: Decryption key or IV is not bytes.")

            cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
            logger.info("Starting chunk decryption...")

            buffer = b''
            min_len_for_tag = GCM_TAG_BYTES

            while True:
                chunk = input_stream.read(CHUNK_SIZE)
                if not chunk: # End of stream
                    if len(buffer) < min_len_for_tag:
                        raise ValueError(f"Input ended before reading full tag. Got {len(buffer)}, need {min_len_for_tag}.")
                    tag = buffer[-min_len_for_tag:]
                    to_process = buffer[:-min_len_for_tag]
                    buffer = b'' # Clear after processing
                    if to_process:
                        try: decrypted_chunk = cipher.decrypt(to_process)
                        except ValueError as e: raise AuthenticationError("Decryption error on final chunk.") from e
                        output_stream.write(decrypted_chunk)
                        bytes_processed += len(to_process)
                        logger.debug(f"Decrypted final chunk: {len(to_process)} -> {len(decrypted_chunk)} bytes.")
                    break # Exit loop

                else: # Still reading chunks
                    buffer += chunk
                    if len(buffer) > min_len_for_tag:
                         process_len = len(buffer) - min_len_for_tag
                         to_process = buffer[:process_len]
                         buffer = buffer[process_len:]
                         try: decrypted_chunk = cipher.decrypt(to_process)
                         except ValueError as e: raise AuthenticationError("Decryption error during streaming.") from e
                         output_stream.write(decrypted_chunk)
                         bytes_processed += len(to_process)
                         # Report Progress
                         if progress_callback:
                             if ciphertext_total_size is not None and ciphertext_total_size > 0:
                                 percentage = int((bytes_processed / ciphertext_total_size) * 100)
                                 if percentage > last_percentage and (percentage % 5 == 0 or percentage == 100):
                                     progress_callback(percentage)
                                     last_percentage = percentage

            # --- Final Tag Verification ---
            if tag is None: raise CryptoCLIError("Internal logic error: Tag not extracted.")

            # --- ADDED DEBUG LOGS ---
            logger.debug(f"Preparing for final tag verification.")
            logger.debug(f"Expected tag size (GCM_TAG_BYTES): {GCM_TAG_BYTES}")
            logger.debug(f"Extracted tag type: {type(tag)}")
            logger.debug(f"Extracted tag length: {len(tag)}")
            try:
                tag_hex = tag.hex()
                preview_len = min(len(tag_hex), 8) # Show up to 8 hex chars (4 bytes)
                logger.debug(f"Extracted tag (hex preview): {tag_hex[:preview_len]}...")
            except Exception:
                logger.debug("Could not get hex representation of extracted tag.")
            # --- END OF ADDED DEBUG LOGS ---

            try:
                cipher.verify(tag) # The verification point
                logger.info(f"Tag verification successful. Total ciphertext bytes processed: {bytes_processed}.")
                if progress_callback and last_percentage < 100: progress_callback(100)
            except ValueError as e:
                msg = "MAC check failed: Incorrect password/key or data corrupted."
                logger.error(msg)
                print(f"Error: {msg}", file=sys.stderr)
                raise AuthenticationError(msg) # Do not chain original generic ValueError

        logger.info("Successfully exited stream context managers for decryption.")

    # Exception Handling
    except AuthenticationError as e: raise
    except (FileAccessError, ArgumentError, ValueError) as e:
         msg = f"Decryption failed due to file/setup/format error: {e}"
         logger.error(msg, exc_info=True)
         print(f"Error: {e}", file=sys.stderr)
         # Map relevant ValueErrors (like format errors) to AuthenticationError for simpler user feedback
         if isinstance(e, ValueError): raise AuthenticationError(msg) from e
         else: raise # Re-raise FileAccessError, ArgumentError
    except CryptoCLIError as e:
         msg = f"Decryption failed: {e}"
         logger.error(msg, exc_info=True)
         print(f"Error: {e}", file=sys.stderr)
         raise
    except OSError as e:
         msg = f"File write error during decryption: {e}"
         logger.error(msg, exc_info=True)
         raise FileAccessError(msg) from e
    except Exception as e:
        msg = "An unexpected error occurred during decryption."
        logger.critical(msg + f" Details: {e}", exc_info=True)
        print(f"Error: {msg}", file=sys.stderr)
        raise CryptoCLIError(msg) from e