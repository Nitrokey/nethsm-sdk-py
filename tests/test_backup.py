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
        assert encrypted.encrypted_unlock_salt is None
    else:
        assert encrypted.encrypted_unlock_salt is not None

    decrypted = encrypted.decrypt("backupbackup")
    assert decrypted.version == version
    assert "/key/mykey" in decrypted.data
    if version == 0:
        assert decrypted.unlock_salt is None
    else:
        assert decrypted.unlock_salt is not None
