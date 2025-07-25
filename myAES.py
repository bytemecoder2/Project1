"""
Encrypts a file using AES-GCM with a key derived from the user's password.
- Adds a structured header containing versioning, IV, salt, file type, and HMAC.
- Uses buffered I/O for efficiency and displays a progress bar.
- Deletes the original file securely after encryption.
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import tqdm
import secrets
from crypto_utils import *
from log import *

from myHeader import *


# Constants

SALT_SIZE = 16  # 16 bytes for salt
IV_SIZE = 12  # IV size for GCM
HMAC_SIZE = 32 # 32 bytes for size of Hmac
AUTH_TAG_SIZE = 16  # 16 bytes authentication tag

BUFFER_SIZE = 64 * 1024  # Size of the data the program will handle in pieces.

def encrypt_file(input_filename: str, password: str, encrypt_logger)->None:
    """
        This function will encrypt a file using the AES-GCM algorithm.

        Args:
            input_filename (str): The name of the file to be encrypted.
            password (str): Password we will use to make session key
            encrypt_logger: Logging information

        Returns:
            Nothing
    """

    # Checking to see if the input filename is a real file or not.
    if not os.path.exists(input_filename):
        encrypt_logger.error(f"File not found: {input_filename}\n")
        raise FileNotFoundError(f"The input file '{input_filename}' does not exist.")

    encrypt_logger.info(f"Input file '{input_filename}' exists, proceeding with encryption.")

    # Checking to see if user has inputted a password or not
    if not password:
        encrypt_logger.error(f"Must Enter password!\n")
        raise ValueError("Must enter a password!")

    success = False   # Flag to indicate if encrypion was a success or not

    try:
        encrypt_logger.info(f"Encrypting file: {input_filename}")

        # Create salt and IV for encryption
        salt = secrets.token_bytes(SALT_SIZE)
        iv = secrets.token_bytes(IV_SIZE)  # AES-GCM needs 12-byte IV
        encrypt_logger.info(f"Generated salt: {salt.hex()[:8]}")
        encrypt_logger.info("IV was successfully generated.")

        # Derive session key using the password and salt
        time_cost = 3
        memory_cost = 2 ** 18
        parallelism = 2
        crypto = CryptoUtils(salt=salt, password=password)
        derived_key_material = crypto.derive_session_key(time_cost, memory_cost, parallelism)
        session_key = derived_key_material[:32]
        hmac_key = derived_key_material[32:]

        encrypt_logger.info("KDF parameters — Time: 3, Memory: 262144 KiB, Parallelism: 2")
        encrypt_logger.info(f"Derived session key (first 8 bytes): {session_key.hex()[:16]}")
        crypto.secure_delete_variable(derived_key_material)


        # Create the cipher for AES-GCM encryption
        cipher = Cipher(algorithms.AES(session_key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypt_logger.info(f"We are using AES-GCM-{len(session_key) * 8}")
        crypto.secure_delete_variable(session_key)

        # Determine file size for progress tracking
        file_size = os.path.getsize(input_filename)
        encrypt_logger.info(f"File size: {file_size} bytes")

        # Separate the filename into name and extension to create the encrypted filename
        name, extension = os.path.splitext(input_filename)
        encrypted_filename = name + '.enc'
        file_type_bytes = (extension[1:].encode("utf-8")[:4] if extension else b"").ljust(4, b"\x00")

        encrypt_logger.info(f"Generated encrypted filename: {encrypted_filename}")

        # header = HeaderV1(MAGIC, 1, file_type_bytes, file_size, salt, iv, memory_cost, time_cost, parallelism)
        header = HeaderV1(file_type_bytes, file_size, salt, iv, memory_cost, time_cost, parallelism)

        encrypt_logger.info(f"Magic bytes: {MAGIC}")
        encrypt_logger.info(f"Header version: {header.VERSION}")

        crypto.secure_delete_variable(iv)
        crypto.secure_delete_variable(salt)

        encrypt_logger.info(f"Starting encryption process...")

        _encrypt_stream(input_filename, encrypted_filename, header, hmac_key, encrypt_logger, encryptor)
        crypto.secure_delete_variable(hmac_key)

        success = True

    except Exception as e:
        encrypt_logger.error(f"An unexpected error occurred during encryption: {str(e)}\n")
        raise

    finally:
        if success:
            encrypt_logger.info(f"Encryption complete. Encrypted file saved as: {encrypted_filename}")
            encrypt_logger.info("Encryption process finished successfully.")

            try:
                crypto.secure_file_delete(input_filename)
                encrypt_logger.info(f"Original file '{input_filename}' securely deleted.\n")
            except Exception as e:
                encrypt_logger.warning(f"Failed to securely delete original file: {e}\n")
        else:
            encrypt_logger.warning("Encryption failed — original file NOT deleted.\n")

def _encrypt_stream(input_filename: str, encrypted_filename: str, header: HeaderV1, hmac_key: bytes, encrypt_logger, encryptor):

    hmac_ctx = hmac.new(hmac_key, digestmod=hashlib.sha256)
    serialized_header = header.serialize()

    hmac_ctx.update(serialized_header)

    with open(input_filename, 'rb') as infile, open(encrypted_filename, 'wb') as outfile:
        outfile.write(serialized_header)

        cursor = 0
        # Track encryption progress using a progress bar (tqdm)
        with tqdm.tqdm(total=header.file_size, unit="B", unit_scale=True, desc=f"Encrypting {input_filename}") as progress:
            while chunk := infile.read(BUFFER_SIZE):
                try:
                    ciphertext = encryptor.update(chunk)
                    outfile.write(ciphertext)
                    cursor += len(chunk)
                    progress.update(len(chunk))  # Update progress bar
                except Exception as e:
                    chunk_hash = hashlib.sha256(chunk).hexdigest()
                    encrypt_logger.error(
                        f"Encryption failed at offset {cursor}, chunk hash: {chunk_hash}, error: {str(e)}")
                    raise

        # Finalize encryption and write authentication tag
        final_ciphertext = encryptor.finalize()
        outfile.write(final_ciphertext)

        auth_tag = encryptor.tag
        outfile.write(auth_tag)

        cursor += len(final_ciphertext)
        encrypt_logger.info(
            f"Final ciphertext size: {header.file_size} bytes, Auth tag size: {len(auth_tag)} bytes")

        hmac_ctx.update(auth_tag)
        outfile.write(hmac_ctx.digest())

def decrypt_file(encrypted_filename: str, password, decrypt_logger)->None:
    """This function will take in the encrypted filename and the password and decrypt the encrypted
    file."""

    """ Checking to see if the file the user has enter exist."""
    if not os.path.exists(encrypted_filename):
        decrypt_logger.error(f"File not found: {encrypted_filename}")
        raise FileNotFoundError(f"The input file '{encrypted_filename}' does not exist.")

    if not password:
        decrypt_logger.error(f"Must Enter password!")
        raise ValueError("Must enter a password!")

    decrypt_logger.debug(f"Input file '{encrypted_filename}' exists, proceeding with decryption.")

    success = False
    try:
        decrypt_logger.info(f"Decrypting file: {encrypted_filename}")

        with open(encrypted_filename, "rb") as infile:

            start_header_pos = infile.tell()
            header, raw_header = HeaderFactory.deserialize(infile)
            end_header_pos = infile.tell()

            infile.seek(header.file_size, 1)

            auth_tag = infile.read(AUTH_TAG_SIZE)
            if len(auth_tag) != AUTH_TAG_SIZE:
                decrypt_logger.warning("Corrupted file: Authentication tag missing or incorrect size.")
                raise ValueError("Corrupted file: Authentication tag missing or incorrect size.")

            decrypt_logger.debug(f"Authentication tag read successfully (size: {len(auth_tag)} bytes).")

            # Extract file extension from the header
            file_extension = header.file_type.rstrip(b"\x00").decode("utf-8")
            decrypted_filename = os.path.splitext(encrypted_filename)[0] + (
                f".{file_extension}" if file_extension else "")

            hmac_value = infile.read(HMAC_SIZE)

            decrypt_logger.debug(f"Generated decrypted filename: {decrypted_filename}")
            decrypt_logger.debug(f"File extension: {file_extension}")

            crypto = CryptoUtils(salt=header.salt, password=password)
            derived_key_material = crypto.derive_session_key(header.kdf_time, header.kdf_memory, header.kdf_parallelism)
            session_key = derived_key_material[:32]
            hmac_key = derived_key_material[32:]
            decrypt_logger.debug(f"Derived session key (first 8 bytes): {session_key.hex()[:16]}")
            crypto.secure_delete_variable(derived_key_material)

            # Compute HMAC to verify file integrity
            if not crypto.verify_hmac(hmac_key, raw_header + auth_tag, hmac_value):
                decrypt_logger.critical("HMAC verification failed. The file may be corrupted or tampered with.")
                raise ValueError("HMAC verification failed.")

            crypto.secure_delete_variable(hmac_key)

            decrypt_logger.info(f"HMAC verification successful!")

            # **STEP 2: Set up the decryption cipher**
            cipher = Cipher(algorithms.AES(session_key), modes.GCM(header.iv, auth_tag), backend=default_backend())
            decryptor = cipher.decryptor()
            crypto.secure_delete_variable(session_key)

            decrypt_logger.info(f"Starting decryption process...")

            _decrypt_stream(infile, encrypted_filename, decrypted_filename, header.file_size, decrypt_logger, end_header_pos, decryptor)

        decrypt_logger.info(f"Decryption complete. Decrypted file saved as: {decrypted_filename}")
        decrypt_logger.debug("Decryption process finished successfully.")
        success = True

    except Exception as e:
        decrypt_logger.error(f"An unexpected error occurred during decryption: {str(e)}")
        raise
    finally:
        if success:

            # Securely delete the encrypted file
            crypto.secure_file_delete(encrypted_filename)
            decrypt_logger.debug(f"Encrypted file '{encrypted_filename}' securely deleted.\n")

        else:
            decrypt_logger.warning("Decryption failed — Encrypted file NOT deleted.\n")

def _decrypt_stream(infile: BinaryIO,
                    encrypted_filename: str,
                    decrypted_filename: str,
                    file_size: int,
                    decrypt_logger,
                    start_pos: int,
                    decryptor) -> None:

    infile.seek(start_pos)
    total_decrypted_size = 0

    # Open the decrypted file for writing
    with open(decrypted_filename, "wb") as outfile:
        # Using tqdm for progress tracking
        with tqdm.tqdm(total=file_size, unit="B", unit_scale=True,
                       desc=f"Decrypting {encrypted_filename}") as progress:
            while total_decrypted_size < file_size:
                chunk_size = min(BUFFER_SIZE, file_size - total_decrypted_size)
                chunk = infile.read(chunk_size)

                try:
                    plaintext = decryptor.update(chunk)
                    outfile.write(plaintext)
                    total_decrypted_size += len(chunk)
                    progress.update(len(chunk))  # Update progress bar
                except Exception as e:
                    decrypt_logger.exception(f"Error during decryption at offset {total_decrypted_size}")
                    raise

        try:
            final_plaintext = decryptor.finalize()
            outfile.write(final_plaintext)
        except Exception as e:
            decrypt_logger.error("Decryption failed during finalization: %s", str(e))
            raise



# Example usage
if __name__ == "__main__":

    password = input("Enter password: ")
    my_logger = Logger('EncryptionLogger', 'encryption_logs.log')
    encrypt_logger = my_logger.get_logger()
    # encrypt_logger = setup_logger('EncryptionLogger', 'encryption_logs.log')
    encrypt_file('test.jpg', password, encrypt_logger)

    my_decrypt_logger = Logger('DecryptionLogger', 'decryption_logs.log')
    decrypt_logger = my_decrypt_logger.get_logger()
    # decrypt_logger = setup_logger('DecryptionLogger', 'decryption_logs.log')
    decrypt_file('test.enc', password, decrypt_logger)
