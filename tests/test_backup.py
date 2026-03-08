import pytest

from nethsm.backup import EncryptedBackup


@pytest.mark.parametrize("version", [0, 1])
def test_backup(version: int) -> None:
    file = f"./tests/backup/v{version}.bin"
    with open(file, "rb") as f:
        data = f.read()

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
