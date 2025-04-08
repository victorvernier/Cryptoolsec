# -*- coding: utf-8 -*-
"""Handles streaming file/standard I/O for encryption/decryption."""

import sys
import logging
import os
from typing import Any # Mantido para compatibilidade se usado em type hints complexos não mostrados

# Crypto imports
from Crypto.Cipher import AES
# No direct use of argon2 here, but its exceptions might bubble up via derive_key
# import argon2 # Keep if derive_key might raise argon2.exceptions directly

# Local imports assumed to be in correct PYTHONPATH or relative structure
from .crypto_logic import derive_key, generate_salt
from ..utils.constants import (
    AES_KEY_BYTES, SALT_BYTES, GCM_IV_BYTES, GCM_TAG_BYTES, CHUNK_SIZE
)
# Consolidated Exception Import
from ..utils.exceptions import (
    FileAccessError, AuthenticationError, CryptoCLIError, ArgumentError
)

logger = logging.getLogger(__name__) # Best practice: use module-specific logger

def process_encryption_io(
    input_path: str | None,
    output_path: str | None,
    key_or_password: bytes,
    is_key: bool
) -> None: # Returns nothing on success, raises exception on error
    """
    Handles streaming encryption from input (file/stdin) to output (file/stdout).
    Derives key from password if necessary, writes header (salt+IV), encrypts
    data in chunks, and writes the GCM tag.

    Raises:
        FileAccessError: If input/output files cannot be accessed.
        AuthenticationError: If key derivation fails (via derive_key).
        ArgumentError: If provided key has incorrect length.
        CryptoCLIError: For other crypto setup or unexpected errors.
    """
    input_stream = None
    output_stream = None
    key: bytes | None = None
    salt: bytes | None = None

    try:
        # --- Get Key ---
        if is_key:
            key = key_or_password
            # Extra validation redundancy (primary check should be in CLI handler)
            if len(key) != AES_KEY_BYTES:
                raise ArgumentError(f"Invalid key length provided to I/O handler. Expected {AES_KEY_BYTES}.")
            logger.info("Using provided key for encryption.")
        else:
            password = key_or_password
            salt = generate_salt() # Generate fresh salt for each encryption
            # derive_key handles logging of success/failure and can raise CryptoCLIError/AuthenticationError
            key = derive_key(password, salt)
            # Key derivation success/info is logged within derive_key

        # --- Open Streams ---
        if input_path:
            # Check existence before opening to provide clearer error
            if not os.path.exists(input_path):
                raise FileAccessError(f"Input file not found: {input_path}")
            try:
                input_stream = open(input_path, 'rb')
            except (PermissionError, OSError) as e:
                raise FileAccessError(f"Cannot open input file '{input_path}': {e}") from e
            logger.info(f"Opened input file: {input_path}")
        else:
            input_stream = sys.stdin.buffer
            logger.info("Using stdin for input.")

        if output_path:
            # TODO: Consider adding check/creation for output directory if it doesn't exist.
            try:
                output_stream = open(output_path, 'wb')
            except (PermissionError, OSError) as e:
                raise FileAccessError(f"Cannot open output file '{output_path}': {e}") from e
            logger.info(f"Opened output file: {output_path}")
        else:
            # Ensure stdout is treated as binary
            try:
                output_stream = sys.stdout.buffer
            except AttributeError: # Should not happen in modern Python, but belt-and-suspenders
                 raise CryptoCLIError("Cannot access sys.stdout.buffer for binary output.")
            logger.info("Using stdout for output.")

        # --- Write Header (Salt + IV) ---
        if salt:
            output_stream.write(salt)
            logger.debug(f"Wrote {len(salt)} salt bytes.")

        iv = os.urandom(GCM_IV_BYTES) # Generate fresh IV for each encryption
        output_stream.write(iv)
        logger.debug(f"Wrote {len(iv)} IV bytes.")

        # --- Encrypt in Chunks ---
        # Ensure key is bytes before passing to AES.new (should be via derive_key or input validation)
        if not isinstance(key, bytes):
             raise CryptoCLIError("Internal error: Encryption key is not bytes.")

        # DEBUG LINE - Keep temporarily while diagnosing the 97-byte key issue
        #logger.debug(f"DEBUG CHECK: Key type={type(key)}, Key length={len(key)}") # <-- Keep for now
        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        logger.info("AES-GCM cipher created. Starting chunk encryption...")

        bytes_processed = 0
        while chunk := input_stream.read(CHUNK_SIZE):
            encrypted_chunk = cipher.encrypt(chunk)
            output_stream.write(encrypted_chunk)
            bytes_processed += len(chunk)
            logger.debug(f"Processed {len(chunk)} bytes -> {len(encrypted_chunk)} encrypted bytes written.")

        if bytes_processed == 0 and input_path and os.path.getsize(input_path) == 0:
            logger.warning("Input file was empty. Output will contain only header and tag.")
        elif bytes_processed == 0:
             logger.warning("Input data stream was empty. Output might be just header/tag.")


        logger.info(f"Finished encrypting {bytes_processed} plaintext bytes.")

        # --- Finalize and Write Tag ---
        tag = cipher.digest() # Get the authentication tag
        output_stream.write(tag)
        logger.debug(f"Wrote {len(tag)} GCM tag bytes.")

        # Implicit success if no exceptions were raised

    except (FileNotFoundError, PermissionError, OSError) as e:
        # Catch broad I/O errors not already caught by specific open() try-excepts
        msg = f"File I/O error during encryption: {e}"
        logger.error(msg, exc_info=True)
        # Raise specific custom exception for consistent handling upstream
        raise FileAccessError(msg) from e
    except (ArgumentError, AuthenticationError, CryptoCLIError) as e:
        # Catch known application-specific errors (config, key derivation)
        msg = f"Setup or configuration error during encryption: {e}"
        # Logging is assumed to have occurred where the original exception was raised (e.g., in derive_key)
        logger.error(f"Caught expected error: {msg}", exc_info=False) # Log re-raise point if needed
        raise # Re-raise for the main handler to map to the correct exit code
    except Exception as e:
        # Catch any truly unexpected errors
        msg = f"An unexpected error occurred during encryption."
        logger.critical(msg + f" Details: {e}", exc_info=True)
        raise CryptoCLIError(msg) from e # Wrap in generic app error
    finally:
        # Ensure streams associated with files are closed
        if input_stream and input_path:
            try:
                input_stream.close()
            except OSError as e:
                logger.warning(f"Error closing input file '{input_path}': {e}")
        if output_stream and output_path:
            try:
                output_stream.close()
            except OSError as e:
                logger.warning(f"Error closing output file '{output_path}': {e}")


def process_decryption_io(
    input_path: str | None,
    output_path: str | None,
    key_or_password: bytes,
    is_key: bool
) -> None: # Returns nothing on success, raises exception on error
    """
    Handles streaming decryption from input (file/stdin) to output (file/stdout).
    Reads header (salt+IV), derives key if necessary, decrypts data in chunks,
    and crucially verifies the GCM tag at the end.

    Raises:
        FileAccessError: If input/output files cannot be accessed or input is truncated.
        AuthenticationError: If key derivation fails, MAC check fails (tag mismatch),
                             or input data appears corrupted/invalid.
        ArgumentError: If provided key has incorrect length.
        CryptoCLIError: For other crypto setup or unexpected errors.
        ValueError: If input data is malformed (e.g., too short).
    """
    input_stream = None
    output_stream = None
    key: bytes | None = None
    salt: bytes | None = None
    iv: bytes | None = None

    try:
        # --- Open Streams ---
        if input_path:
            if not os.path.exists(input_path):
                raise FileAccessError(f"Input file not found: {input_path}")
            try:
                input_stream = open(input_path, 'rb')
            except (PermissionError, OSError) as e:
                raise FileAccessError(f"Cannot open input file '{input_path}': {e}") from e
            logger.info(f"Opened input file: {input_path}")
        else:
            input_stream = sys.stdin.buffer
            logger.info("Using stdin for input.")

        if output_path:
            try:
                output_stream = open(output_path, 'wb')
            except (PermissionError, OSError) as e:
                raise FileAccessError(f"Cannot open output file '{output_path}': {e}") from e
            logger.info(f"Opened output file: {output_path}")
        else:
             try:
                output_stream = sys.stdout.buffer
             except AttributeError:
                 raise CryptoCLIError("Cannot access sys.stdout.buffer for binary output.")
             logger.info("Using stdout for output.")

        # --- Read Header and Get Key ---
        if is_key:
            key = key_or_password
            if len(key) != AES_KEY_BYTES: raise ArgumentError("Invalid key length provided.")
            logger.info("Using provided key for decryption (Salt not expected in input).")
            # Read IV directly
            iv = input_stream.read(GCM_IV_BYTES)
            if len(iv) != GCM_IV_BYTES: raise ValueError(f"Could not read {GCM_IV_BYTES}-byte IV: Input too short or truncated.")
            logger.debug(f"Read {len(iv)} IV bytes.")
        else:
            password = key_or_password
            # Read Salt first
            salt = input_stream.read(SALT_BYTES)
            if len(salt) != SALT_BYTES: raise ValueError(f"Could not read {SALT_BYTES}-byte Salt: Input too short or truncated.")
            logger.debug(f"Read {len(salt)} salt bytes.")
            # derive_key handles logging and can raise CryptoCLIError/AuthenticationError
            key = derive_key(password, salt)
            # Read IV after Salt
            iv = input_stream.read(GCM_IV_BYTES)
            if len(iv) != GCM_IV_BYTES: raise ValueError(f"Could not read {GCM_IV_BYTES}-byte IV after Salt: Input too short or truncated.")
            logger.debug(f"Read {len(iv)} IV bytes.")

        # --- Decrypt in Chunks (Buffering for Tag) ---
        if not isinstance(key, bytes) or not isinstance(iv, bytes):
             raise CryptoCLIError("Internal error: Decryption key or IV is not bytes.")

        cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
        logger.info("AES-GCM cipher created. Starting chunk decryption...")

        # Buffer to hold the end of the stream, ensuring we don't decrypt the tag
        buffer = b''
        bytes_processed = 0
        min_len_for_tag = GCM_TAG_BYTES # Minimum length the buffer must hold at the end

        while True:
            chunk = input_stream.read(CHUNK_SIZE)
            if not chunk: break # End of stream reached

            buffer += chunk
            # If buffer holds significantly more than needed for the tag,
            # process the beginning part to avoid excessive memory use.
            if len(buffer) > CHUNK_SIZE + min_len_for_tag: # Heuristic threshold
                process_len = len(buffer) - min_len_for_tag
                to_process = buffer[:process_len]
                buffer = buffer[process_len:] # Keep the potential tag + margin in buffer
                try:
                    # Decrypt and write the processed part
                    decrypted_chunk = cipher.decrypt(to_process)
                except ValueError as e:
                    # Decryption error during streaming potentially indicates corruption early on.
                    logger.error("Decryption error during streaming.", exc_info=True)
                    raise AuthenticationError("Decryption error during streaming (possible data corruption).") from e
                output_stream.write(decrypted_chunk)
                bytes_processed += len(to_process)
                logger.debug(f"Processed {len(to_process)} encrypted bytes -> {len(decrypted_chunk)} decrypted bytes written.")

        # --- Process Final Buffer and Verify Tag ---
        if len(buffer) < GCM_TAG_BYTES:
            raise ValueError(f"Input ended abruptly or file is too small. Missing tag (got {len(buffer)} bytes, need at least {GCM_TAG_BYTES}).")

        # Extract the tag from the very end of the buffer
        tag = buffer[-GCM_TAG_BYTES:]
        final_ciphertext_chunk = buffer[:-GCM_TAG_BYTES]
        logger.debug(f"Final buffer processing. Buffer length: {len(buffer)}. Extracted tag ({len(tag)} bytes). Final ciphertext chunk size: {len(final_ciphertext_chunk)} bytes.")

        # Decrypt the final chunk of actual ciphertext (if any exists)
        if final_ciphertext_chunk:
            try:
                decrypted_chunk = cipher.decrypt(final_ciphertext_chunk)
            except ValueError as e:
                logger.error("Decryption error on final chunk before verification.", exc_info=True)
                raise AuthenticationError("Decryption error on final chunk (possible data corruption).") from e
            output_stream.write(decrypted_chunk)
            bytes_processed += len(final_ciphertext_chunk)
            logger.debug(f"Processed final {len(final_ciphertext_chunk)} encrypted bytes -> {len(decrypted_chunk)} decrypted bytes written.")

        # The final, crucial tag verification step!
        # This checks the integrity and authenticity of *all* decrypted data.
        try:
            cipher.verify(tag)
            logger.info(f"Tag verification successful. Total encrypted bytes processed (excluding header): {bytes_processed + len(final_ciphertext_chunk)}.")
        except ValueError:
            # This specific ValueError from verify() means the tag does not match.
            msg = "MAC check failed: Incorrect password/key or data corrupted."
            logger.error(msg)
            # User-facing message should be clear but avoid excessive detail
            print("Error: Decryption failed. Incorrect password/key or data corrupted.", file=sys.stderr)
            raise AuthenticationError(msg) # Do not chain the original ValueError here, the msg is specific

        # Implicit success if no exceptions were raised

    except AuthenticationError as e:
         # Re-raise specifically caught AuthenticationErrors for the main handler
         logger.warning(f"Authentication error during decryption: {e}") # Log the specific point
         raise
    except (FileNotFoundError, PermissionError, OSError) as e:
        # Catch broad I/O errors
        msg = f"File I/O error during decryption: {e}"
        logger.error(msg, exc_info=True)
        raise FileAccessError(msg) from e
    except (ValueError, ArgumentError, CryptoCLIError) as e:
        # Catch errors related to header reading, key derivation setup, or unexpected crypto issues
        # ValueError here likely means malformed input (too short header)
        msg = f"Setup, data format, or configuration error during decryption: {e}"
        logger.error(msg, exc_info=True)
        # Raising as AuthenticationError as it often implies wrong key/corrupted header.
        # A very short file might manifest as ValueError->AuthenticationError here.
        raise AuthenticationError(msg) from e
    except Exception as e:
        # Catch any truly unexpected errors
        msg = f"An unexpected error occurred during decryption."
        logger.critical(msg + f" Details: {e}", exc_info=True)
        raise CryptoCLIError(msg) from e
    finally:
        # Ensure streams associated with files are closed
        if input_stream and input_path:
            try:
                input_stream.close()
            except OSError as e:
                logger.warning(f"Error closing input file '{input_path}': {e}")
        if output_stream and output_path:
            try:
                output_stream.close()
            except OSError as e:
                logger.warning(f"Error closing output file '{output_path}': {e}")