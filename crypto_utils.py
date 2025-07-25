
import os
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes, hmac as crypto_hmac
from cryptography.hazmat.backends import default_backend
import ctypes
import hmac
import hashlib

# Constants
KEY_SIZE = 32  # AES-256 requires a 32-byte key
HMAC_KEY_SIZE = 32 # HMAC requires a 32-byte key


class CryptoUtils:
    def __init__(self, salt: bytes, password: str) -> None:
        """
        Initialize CryptoUtils with a password and salt for key derivation.
        """
        self.salt = salt
        self.password = password

    def derive_session_key(self, time_cost, memory_cost, parallelism) -> bytes:
        """
            Derives a cryptographic key using Argon2id.

            Args:
                password (str): The user's password.
                salt (bytes): A unique salt value.

            Returns:
                bytes: A 32-byte session key suitable for AES-256 encryption.

            Note:
                The password will be UTF-8 encoded if passed as a string.
            """

        # WARNING: If we know that the password is a string, why are we checking it here?
        #if isinstance(self.password, str):
        #    self.password = self.password.encode()

        password_bytes = self.password.encode() if isinstance(self.password, str) else self.password

        key = hash_secret_raw(
            secret=password_bytes,
            salt=self.salt,
            time_cost = time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
            hash_len=KEY_SIZE + HMAC_KEY_SIZE,  # Output length (32 bytes for AES key and 32 bytes for HMAC_KEY)
            type=Type.ID  # Argon2id (resistant to side-channel attacks)
        )
        return key

    @staticmethod
    def compute_hmac(key: bytes, data: bytes) -> bytes:
        """
        Compute HMAC for the given data and key using the specified hash algorithm.
        """
        return hmac.new(key, data, hashlib.sha256).digest()

    @staticmethod
    def verify_hmac(key: bytes, data: bytes, expected_mac: bytes,
                    hash_alg=hashes.SHA256()) -> bool:
        """
        Verify the HMAC for the given data matches the expected MAC.

        # Compute HMAC to verify file integrity
        hmac_computed = CryptoUtils.compute_hmac(key, data)
        # if hmac_computed != expected_mac:
        if not hmac.compare_digest(hmac_computed, expected_mac):
            return False
        else:
            return True
        """
        return hmac.compare_digest(CryptoUtils.compute_hmac(key, data), expected_mac)

    @staticmethod
    def secure_file_delete(file_path: str, passes = 3) -> None:

        """
            Securely deletes a file by overwriting its contents multiple times with different patterns
            before deletion.

            Args:
                file_path (str): File to be securely deleted
                passes (int): Number of time the file will be overwritten

            Returns:
                Nothing
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File '{file_path}' not found.")

        file_size = os.path.getsize(file_path)

        with open(file_path, "r+b") as file:
            for _ in range(passes):
                file.seek(0)
                if _ % 2 == 0:
                    file.write(b"\x00" * file_size)  # Pass 1: Overwrite with zeros
                else:
                    file.write(b"\xFF" * file_size)  # Pass 2: Overwrite with ones
                file.write(os.urandom(file_size))  # Pass 3: Overwrite with random data
                file.flush()  # Ensure changes are written to disk

        os.remove(file_path)  # Delete the file

    @staticmethod
    def secure_delete_variable(var) -> None:
        """
            Securely deletes a variable from memory by overwriting its contents with random data
            before releasing the reference.

            Args:
                var: variable to be securely deleted.

            Returns:
                Nothing
        """
        if isinstance(var, (bytes, bytearray)):
            # Overwrite with random data
            size = len(var)
            random_data = os.urandom(size)

            # Convert to mutable bytearray (if not already)
            mutable_var = bytearray(var)

            # Overwrite contents with random data
            mutable_var[:] = random_data

            # Use ctypes to try to force memory overwrite
            ptr = ctypes.cast(id(mutable_var), ctypes.POINTER(ctypes.c_char * size))
            ctypes.memset(ptr, 0, size)

            # Remove reference
            del mutable_var
        else:
            raise TypeError("Only bytes or bytearray can be securely deleted.")

        # Force garbage collection
        del var
