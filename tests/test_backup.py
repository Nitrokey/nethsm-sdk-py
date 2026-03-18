import pytest

from nethsm.backup import EncryptedBackup


def read_backup(version: int) -> bytes:
    file = f"./tests/backup/v{version}.bin"
    with open(file, "rb") as f:
        return f.read()


@pytest.mark.parametrize("version", [0, 1])
def test_backup(version: int) -> None:
    data = read_backup(version)

    encrypted = EncryptedBackup.parse(data)
    assert encrypted.version == version
    if version == 0:
        assert encrypted.encrypted_backup_device_id is None
        assert encrypted.encrypted_backup_config_store_key is None
    else:
        assert encrypted.encrypted_backup_device_id is not None
        assert encrypted.encrypted_backup_config_store_key is not None

    decrypted = encrypted.decrypt("backupbackup")
    assert decrypted.version == version
    assert "/key/mykey" in decrypted.data
    if version == 0:
        assert decrypted.backup_device_id is None
        assert decrypted.backup_config_store_key is None
    else:
        assert decrypted.backup_device_id is not None
        assert decrypted.backup_config_store_key is not None


@pytest.mark.parametrize("version", [0, 1])
def test_backup_no_header(version: int) -> None:
    data = read_backup(version)
    for n in [1, 5, 15, 42]:
        with pytest.raises(ValueError, match=r"Data does not contain a NetHSM header"):
            EncryptedBackup.parse(data[n:])


def test_backup_v1_no_trailer() -> None:
    data = read_backup(1)
    for n in [1, 5, 22, 42]:
        with pytest.raises(ValueError, match=r"Data is truncated"):
            EncryptedBackup.parse(data[:-n])
