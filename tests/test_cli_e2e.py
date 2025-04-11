# tests/test_cli_e2e.py
# -*- coding: utf-8 -*-
"""
End-to-end tests for the Cryptoolsec CLI.
Uses subprocess to run the actual command installed via entry points.
"""

import subprocess
import sys
import os # Needed for os.urandom
from pathlib import Path
import pytest

# --- Import Constants from the main package ---
try:
    from cryptoolsec.utils.constants import (
        SALT_BYTES, GCM_IV_BYTES, GCM_TAG_BYTES, AES_KEY_BYTES, # Added AES_KEY_BYTES
        EXIT_SUCCESS, EXIT_AUTH_ERROR, EXIT_FILE_ERROR # Added EXIT_FILE_ERROR
    )
except ImportError as e:
    print(f"\nERROR: Could not import constants from 'cryptoolsec'. "
          f"Did you run 'pip install -e .' from the project root?\nDetails: {e}", file=sys.stderr)
    pytest.skip("Cannot import constants from cryptoolsec package.", allow_module_level=True)


# --- Test Data ---
PLAINTEXT_CONTENT = b"Test data with different chars: !@#$%^&*()_+`~-=[]{}|\\:;\"'<>,.?/"
TEST_PASSWORD_CORRECT = b"correct_password_123!@#"
TEST_PASSWORD_WRONG   = b"wrong_password_XYZ#@!"
# Generate a valid key for keyfile tests
TEST_KEY_CORRECT = os.urandom(AES_KEY_BYTES) # Generate 32 random bytes

COMMAND_NAME = "cryptoolsec"


def run_cryptoolsec_cli(args: list[str], input_data: bytes | None = None) -> subprocess.CompletedProcess:
    """Helper function to run the CLI command via subprocess."""
    # (Implementation as before - runs command, captures output, prints info)
    command = [COMMAND_NAME] + args
    print(f"\nAttempting to run command: {' '.join(command)}")
    try:
        result = subprocess.run(
            command, input=input_data, capture_output=True, text=False,
            timeout=60, check=False
        )
        print(f"Return Code: {result.returncode}")
        if result.stdout: print(f"stdout (first 500 bytes):\n{result.stdout[:500].decode(errors='ignore')}...")
        if result.stderr: print(f"stderr (first 1000 bytes):\n{result.stderr[:1000].decode(errors='ignore')}...")
        return result
    except FileNotFoundError:
        print(f"\nERROR: Command '{COMMAND_NAME}' not found.", file=sys.stderr)
        pytest.fail(f"Command '{COMMAND_NAME}' not found on PATH.", pytrace=False)
    except subprocess.TimeoutExpired:
        print(f"\nERROR: Command timed out.", file=sys.stderr)
        pytest.fail("Command execution timed out.", pytrace=False)
    except Exception as e:
        print(f"\nERROR: Unexpected error running subprocess: {e}", file=sys.stderr)
        pytest.fail(f"Unexpected subprocess error: {e}", pytrace=False)


# --- Test Cases ---

def test_encrypt_decrypt_password_file_e2e(tmp_path: Path):
    """Tests encrypt/decrypt cycle with correct password from file."""
    # (Implementation as before - Passed successfully)
    input_file = tmp_path / "input_correct.txt"; password_file = tmp_path / "pass_correct.key"
    encrypted_file = tmp_path / "output_correct.enc"; decrypted_file = tmp_path / "decrypted_correct.txt"
    print(f"\nTest files (correct password test) in: {tmp_path}"); input_file.write_bytes(PLAINTEXT_CONTENT); password_file.write_bytes(TEST_PASSWORD_CORRECT)
    encrypt_args = ["encrypt", "--input", str(input_file), "--output", str(encrypted_file), "--password-file", str(password_file)]
    result_enc = run_cryptoolsec_cli(encrypt_args)
    assert result_enc.returncode == EXIT_SUCCESS, "Encryption failed"; assert encrypted_file.exists()
    min_size = SALT_BYTES + GCM_IV_BYTES + GCM_TAG_BYTES + 1; assert encrypted_file.stat().st_size >= min_size
    decrypt_args = ["decrypt", "--input", str(encrypted_file), "--output", str(decrypted_file), "--password-file", str(password_file)]
    result_dec = run_cryptoolsec_cli(decrypt_args)
    assert result_dec.returncode == EXIT_SUCCESS, "Decryption failed"; assert decrypted_file.exists()
    decrypted_content = decrypted_file.read_bytes(); assert decrypted_content == PLAINTEXT_CONTENT
    print("Correct password Encrypt-Decrypt cycle successful!")

def test_decrypt_wrong_password_e2e(tmp_path: Path):
    """Tests decrypt attempt with wrong password, expects EXIT_AUTH_ERROR."""
    # (Implementation as before - Should pass now)
    input_file = tmp_path / "input_wrongpass.txt"; password_file_correct = tmp_path / "pass_correct.key"
    password_file_wrong = tmp_path / "pass_wrong.key"; encrypted_file = tmp_path / "output_wrongpass.enc"
    decrypted_file = tmp_path / "decrypted_wrongpass.txt"
    print(f"\nTest files (wrong password test) in: {tmp_path}"); input_file.write_bytes(PLAINTEXT_CONTENT)
    password_file_correct.write_bytes(TEST_PASSWORD_CORRECT); password_file_wrong.write_bytes(TEST_PASSWORD_WRONG)
    encrypt_args = ["encrypt", "--input", str(input_file), "--output", str(encrypted_file), "--password-file", str(password_file_correct)]
    result_enc = run_cryptoolsec_cli(encrypt_args); assert result_enc.returncode == EXIT_SUCCESS; assert encrypted_file.exists()
    decrypt_args = ["decrypt", "--input", str(encrypted_file), "--output", str(decrypted_file), "--password-file", str(password_file_wrong)]
    result_dec = run_cryptoolsec_cli(decrypt_args)
    assert result_dec.returncode != EXIT_SUCCESS, "Decryption succeeded with wrong password!"
    assert result_dec.returncode == EXIT_AUTH_ERROR, f"Wrong exit code ({result_dec.returncode}), expected Auth Error ({EXIT_AUTH_ERROR})"
    stderr_output = result_dec.stderr.decode(errors='ignore').lower(); assert "mac check failed" in stderr_output or "incorrect password/key" in stderr_output
    if decrypted_file.exists(): assert decrypted_file.read_bytes() != PLAINTEXT_CONTENT
    print("Wrong password decryption test failed correctly!")


# --- NEW TEST: Keyfile ---
def test_encrypt_decrypt_keyfile_e2e(tmp_path: Path):
    """
    Tests encrypt/decrypt cycle using a keyfile (--keyfile).
    Verifies functionality without password derivation.
    """
    # 1. Setup
    input_file = tmp_path / "input_keyfile.txt"
    key_file = tmp_path / "secret.key"
    encrypted_file = tmp_path / "output_keyfile.enc"
    decrypted_file = tmp_path / "decrypted_keyfile.txt"

    print(f"\nTest files (keyfile test) in: {tmp_path}")
    input_file.write_bytes(PLAINTEXT_CONTENT)
    key_file.write_bytes(TEST_KEY_CORRECT) # Write the generated raw key

    # 2. Encrypt
    encrypt_args = [
        "encrypt",
        "--input", str(input_file),
        "--output", str(encrypted_file),
        "--keyfile", str(key_file), # Use keyfile option
    ]
    result_enc = run_cryptoolsec_cli(encrypt_args)

    # 3. Assert Encryption Success
    assert result_enc.returncode == EXIT_SUCCESS, f"Keyfile encryption failed (Code: {result_enc.returncode})"
    assert encrypted_file.exists(), "Encrypted file (keyfile) was not created."
    # Keyfile mode output does not include salt
    min_size = GCM_IV_BYTES + GCM_TAG_BYTES + (1 if PLAINTEXT_CONTENT else 0)
    assert encrypted_file.stat().st_size >= min_size, f"Encrypted file size {encrypted_file.stat().st_size} is too small (keyfile mode)."

    # 4. Decrypt
    decrypt_args = [
        "decrypt",
        "--input", str(encrypted_file),
        "--output", str(decrypted_file),
        "--keyfile", str(key_file), # Use the same keyfile
    ]
    result_dec = run_cryptoolsec_cli(decrypt_args)

    # 5. Assert Decryption Success
    assert result_dec.returncode == EXIT_SUCCESS, f"Keyfile decryption failed (Code: {result_dec.returncode})"
    assert decrypted_file.exists(), "Decrypted file (keyfile) was not created."

    # 6. Assert Content Match
    try:
        decrypted_content = decrypted_file.read_bytes()
        assert decrypted_content == PLAINTEXT_CONTENT, "Decrypted content does not match original (keyfile)."
    except Exception as e:
        pytest.fail(f"Failed reading/comparing decrypted file (keyfile): {e}", pytrace=False)

    print("Keyfile Encrypt-Decrypt cycle successful!")


# --- NEW TEST: File Not Found ---
def test_file_not_found_error_e2e(tmp_path: Path):
    """
    Tests running commands with a non-existent input file.
    Expects failure with the specific File Error exit code.
    """
    # 1. Setup
    non_existent_input = tmp_path / "non_existent_input.txt"
    dummy_output = tmp_path / "dummy_output.enc"
    password_file = tmp_path / "pass_dummy.key" # Need a valid secret provider
    password_file.write_bytes(TEST_PASSWORD_CORRECT)

    print(f"\nTest files (file not found test) in: {tmp_path}")
    # Ensure input file does NOT exist
    assert not non_existent_input.exists()

    # 2. Run Encryption with non-existent input
    encrypt_args = [
        "encrypt",
        "--input", str(non_existent_input), # Non-existent file
        "--output", str(dummy_output),
        "--password-file", str(password_file),
    ]
    result_enc = run_cryptoolsec_cli(encrypt_args)

    # 3. Assert Encryption Failure (File Not Found)
    assert result_enc.returncode != EXIT_SUCCESS, "Encryption succeeded with non-existent input file (ERROR!)"
    assert result_enc.returncode == EXIT_FILE_ERROR, \
        f"Encryption failed with wrong code ({result_enc.returncode}) instead of File Error ({EXIT_FILE_ERROR})"
    # Check for expected message in stderr
    stderr_output_enc = result_enc.stderr.decode(errors='ignore').lower()
    assert "file not found" in stderr_output_enc or "cannot open input file" in stderr_output_enc, \
           "Expected 'file not found' message missing in stderr for encrypt."

    # 4. Run Decryption with non-existent input
    decrypt_args = [
        "decrypt",
        "--input", str(non_existent_input), # Non-existent file
        "--output", str(dummy_output),
        "--password-file", str(password_file),
    ]
    result_dec = run_cryptoolsec_cli(decrypt_args)

    # 5. Assert Decryption Failure (File Not Found)
    assert result_dec.returncode != EXIT_SUCCESS, "Decryption succeeded with non-existent input file (ERROR!)"
    assert result_dec.returncode == EXIT_FILE_ERROR, \
        f"Decryption failed with wrong code ({result_dec.returncode}) instead of File Error ({EXIT_FILE_ERROR})"
    stderr_output_dec = result_dec.stderr.decode(errors='ignore').lower()
    assert "file not found" in stderr_output_dec or "cannot open input file" in stderr_output_dec, \
           "Expected 'file not found' message missing in stderr for decrypt."

    print("File not found errors handled correctly!")


# --- TODO: Add more tests here ---