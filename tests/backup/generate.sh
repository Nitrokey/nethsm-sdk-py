set -e

nethsm() {
  nitropy nethsm --no-verify-tls --host localhost:8443 $@
}

nethsm-admin() {
  nethsm --username admin --password adminadmin $@
}

nethsm-operator() {
  nethsm --username operator --password operatoroperator $@
}

nethsm-backup() {
  nethsm --username backup --password backupbackup $@
}

nethsm provision --unlock-passphrase unlockunlock --admin-passphrase adminadmin

nethsm-admin set-backup-passphrase --new-passphrase backupbackup --force
nethsm-admin add-user --real-name backup --role backup --passphrase backupbackup --user-id backup
nethsm-admin add-user --real-name operator --role operator --passphrase operatoroperator --user-id operator

nethsm-admin generate-key --type curve25519 --mechanism eddsa_signature --length 128 --key-id mykey

nethsm-backup backup backup.bin
