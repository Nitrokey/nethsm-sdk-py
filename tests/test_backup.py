from nethsm.backup import EncryptedBackup


def test_backup() -> None:
    version = 0
    file = f"./tests/backup/v{version}.bin"

    with open(file, "rb") as f:
        data = f.read()
    encrypted = EncryptedBackup.parse(data)
    assert encrypted.version == version
    decrypted = encrypted.decrypt("backupbackup")
    assert decrypted.version == version
    assert "/key/mykey" in decrypted.data
