from dataclasses import dataclass
import struct
from typing import ClassVar, BinaryIO, Type

# Constants
MAGIC = b'ENCX'
MAGIC_LEN = 4
VERSION_LEN = 1
PREFIX_FORMAT = f">{MAGIC_LEN}s B"
PREFIX_SIZE = struct.calcsize(PREFIX_FORMAT)

# === Base Header Class ===
@dataclass
class BaseHeader:
    @classmethod
    def deserialize(cls, stream: BinaryIO):
        raise NotImplementedError()

    def serialize(self) -> bytes:
        raise NotImplementedError()

@dataclass
class HeaderV1(BaseHeader):
    HEADER_FORMAT: ClassVar[str] = "4s Q 16s 12s I B B"  # file_type, file_size, salt, iv, kdf_memory, kdf_time, kdf_parallelism
    HEADER_SIZE: ClassVar[int] = struct.calcsize(HEADER_FORMAT)
    VERSION = 1

    file_type: bytes
    file_size: int
    salt: bytes
    iv: bytes
    kdf_memory: int
    kdf_time: int
    kdf_parallelism: int

    def serialize(self) -> bytes:
        body = struct.pack(
            self.HEADER_FORMAT,
            self.file_type,
            self.file_size,
            self.salt,
            self.iv,
            self.kdf_memory,
            self.kdf_time,
            self.kdf_parallelism,
        )
        return struct.pack(PREFIX_FORMAT, MAGIC, HeaderV1.VERSION) + body

    @classmethod
    def deserialize(cls, stream, prefix):
        body = stream.read(cls.HEADER_SIZE)
        fields = struct.unpack(cls.HEADER_FORMAT, body)
        return cls(*fields), (prefix + body)

# === Factory ===
class HeaderFactory:
    HEADER_MAP = {
        1: HeaderV1,
        # future: 13: HeaderV13, etc.
    }

    @staticmethod
    def deserialize(stream: BinaryIO) -> BaseHeader:
        prefix = stream.read(PREFIX_SIZE)
        magic, version = struct.unpack(PREFIX_FORMAT, prefix)

        if magic != MAGIC:
            raise ValueError(f"Invalid file magic: {magic}")

        header_cls = HeaderFactory.HEADER_MAP.get(version)
        if not header_cls:
            raise ValueError(f"Unsupported header version: {version}")

        return header_cls.deserialize(stream, prefix)