# Based on export_backup.py from the NetHSM source by Sven Anderson <sven@anderson.de>

import hashlib
import struct
from dataclasses import dataclass, field
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def _get_length(data: bytes) -> tuple[int, bytes]:
    if len(data) < 3:
        raise ValueError("Failed to read field length: unexpected EOF")
    high, low = struct.unpack(">B H", data[:3])
    return ((high << 16) + low, data[3:])


def _get_field(data: bytes) -> tuple[bytes, bytes]:
    n, data = _get_length(data)
    if len(data) < n:
        raise ValueError("Failed to extract field: unexpected EOF")
    return data[:n], data[n:]


def _decrypt(key: bytes, adata: bytes, data: bytes) -> bytes:
    iv_size = 12
    ciphertext = data[iv_size:-16]
    tag = data[-16:]
    nonce = data[:iv_size]

    cipher = Cipher(
        algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend()
    )
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(adata)

    try:
        decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted_data
    except InvalidTag:
        raise ValueError(
            "Authentication tag verification failed. The data may be tampered."
        )


@dataclass
class Backup:
    version: int
    domain_key: bytes
    data: dict[str, bytes] = field(default_factory=dict)
    backup_device_id: Optional[bytes] = None
    backup_config_store_key: Optional[bytes] = None


@dataclass
class EncryptedBackup:
    version: int
    salt: bytes
    encrypted_version: bytes
    encrypted_domain_key: bytes
    encrypted_data: list[bytes] = field(default_factory=list)
    encrypted_backup_device_id: Optional[bytes] = None
    encrypted_backup_config_store_key: Optional[bytes] = None

    @classmethod
    def parse(cls, data: bytes) -> "EncryptedBackup":
        header = b"_NETHSM_BACKUP_"
        header_len = len(header)
        if len(data) < header_len + 1 or data[:header_len] != header:
            raise ValueError("Data does not contain a NetHSM header")
        version = data[header_len]
        data = data[header_len + 1 :]

        if version not in [0, 1]:
            raise ValueError(
                f"Version mismatch on export, provided backup version is {version}, this tool expects 0 or 1"
            )

        salt, data = _get_field(data)
        encrypted_version, data = _get_field(data)
        encrypted_domain_key, data = _get_field(data)

        encrypted_backup_device_id = None
        encrypted_backup_config_store_key = None
        if version > 0:
            encrypted_backup_device_id, data = _get_field(data)
            encrypted_backup_config_store_key, data = _get_field(data)

        backup = cls(
            version=version,
            salt=salt,
            encrypted_version=encrypted_version,
            encrypted_domain_key=encrypted_domain_key,
            encrypted_backup_device_id=encrypted_backup_device_id,
            encrypted_backup_config_store_key=encrypted_backup_config_store_key,
        )

        while data:
            item, data = _get_field(data)
            backup.encrypted_data.append(item)

        return backup

    def _key(self, passphrase: str) -> bytes:
        return hashlib.scrypt(
            password=passphrase.encode(), salt=self.salt, n=16384, r=8, p=16, dklen=32
        )

    def decrypt(self, passphrase: str) -> Backup:
        key = self._key(passphrase)
        version_bytes = _decrypt(key, b"backup-version", self.encrypted_version)
        if len(version_bytes) != 1:
            raise ValueError(f"Overlong version: {version_bytes!r}")
        version = version_bytes[0]
        if version != self.version:
            raise ValueError(
                f"Internal and external version mismatch ({version} != {self.version})."
            )
        domain_key = _decrypt(key, b"domain-key", self.encrypted_domain_key)
        backup_device_id = None
        if self.encrypted_backup_device_id is not None:
            backup_device_id = _decrypt(
                key, b"backup-device-id", self.encrypted_backup_device_id
            )
        backup_config_store_key = None
        if self.encrypted_backup_config_store_key is not None:
            backup_config_store_key = _decrypt(
                key, b"backup-config-store-key", self.encrypted_backup_config_store_key
            )

        backup = Backup(
            version=version,
            domain_key=domain_key,
            backup_device_id=backup_device_id,
            backup_config_store_key=backup_config_store_key,
        )

        for item in self.encrypted_data:
            key_value_pair = _decrypt(key, b"backup", item)
            k, v = _get_field(key_value_pair)
            backup.data[k.decode()] = v

        return backup
