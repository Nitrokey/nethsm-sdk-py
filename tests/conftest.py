from os import environ


class Constants:
    # test mode (ci, docker)
    TEST_MODE = environ.get("TEST_MODE", "docker")

    # docker
    IMAGE = environ.get("NETHSM_IMAGE", "nitrokey/nethsm:testing")

    TLS_PEM = "tests/tls.pem"
    CERTIFICATE_FILE = "tests/certificate.pem"

    # all test_nethsm

    # READ env variables
    HOST = environ.get("NETHSM_HOST", "127.0.0.1:8443")
    VERSION = "v1"
    VERIFY_TLS = False

    USERNAME = "admin"
    PASSWORD = "adminadmin"
    PASSPHRASE = "adminadmin"
    UNLOCK_PASSPHRASE = "unlockunlock"
    STATES = ["Unprovisioned", "Operational", "Locked"]

    # test_system_info
    FIRMWARE_VERSION = "N/A"
    SOFTWARE_VERSION = "0.9"
    HARDWARE_VERSION = "N/A"
    BUILD_TAG_LEN = 7

    # test_nethsm_users, test_nethsm_config
    UNLOCK_PASSPHRASE_CHANGED = "unlockiunlocki"
    UNLOCK_PASSPHRASE_WRONG = "unluckiunlock"
    UNLOCK_PASSPHRASE_WRONG_CASE = "UnlockiUnlocki"
    PASSPHRASE_CHANGED = "adminiadmini"
    PASSPHRASE_CHANGED2 = "admiadmiadmi"
    PASSPHRASE_WRONG = "madmadadmin"
    PASSPHRASE_WRONG_CASE = "AdminiAdmini"
    BACKUP_PASSPHRASE = "adminadmin"
    BACKUP_PASSPHRASE_CHANGED = "backupbackup"

    # test_nethsm_system
    FILENAME_BACKUP = "backupNethsm.bin"
    FILENAME_UPDATE = "update.img.bin"
    FILENAME_UPDATE_IN_TEST = "tests/update.img.bin"
    FILENAME_ENCRYPTED = "encrypted.bin"

    # test_nethsm_config
    COUNTRY = "DE"
    STATE_OR_PROVINCE = "Brandenburg"
    LOCALITY = "Teltow"
    ORGANIZATION = "NitroKey"
    ORGANIZATIONAL_UNIT = "Teltow Büro"
    COMMON_NAME = "Patryk"
    EMAIL_ADDRESS = "patryk@nitrokey.com"
    IP_ADDRESS_LOGGING = "0.0.0.0"
    IP_ADDRESS_NETWORK = "192.168.1.1"
    PORT = 514
    NETMASK = "255.255.255.0"
    GATEWAY = "0.0.0.0"
    UNATTENDED_BOOT_OFF = "off"
    UNATTENDED_BOOT_ON = "on"
    LOG_LEVEL = "info"

    # test_nethsm_keys
    TYPE = "RSA"
    MECHANISM = [
        "RSA_Signature_PKCS1",
        "RSA_Decryption_PKCS1",
        "RSA_Signature_PSS_SHA256",
        "RSA_Decryption_OAEP_SHA256",
    ]
    LENGTH = 1024
    KEY_ID_ADDED = "KeyIdAdded"
    KEY_ID_GENERATED = "KeyIdGenerated"
    KEY_ID_AES = "KeyIdAES"
    DATA = "Test data 123456"
    MODE = "PKCS1"
    # 'PKCS1', 'PSS_MD5', 'PSS_SHA1', 'PSS_SHA224', 'PSS_SHA256', 'PSS_SHA384', 'PSS_SHA512', 'EdDSA', 'ECDSA'
    # test_nethsm_users, test_nethsm_keys
    TAG1 = "Frankfurt"
    TAG2 = "Berlin"
    TAG3 = "Teltow"
    TAGS = [TAG1, TAG2, TAG3]

    class AdminUser:
        USER_ID = "admin"
        REAL_NAME = "admin"
        ROLE = "Administrator"

    class AdministratorUser:
        USER_ID = "UIAdministrator"
        REAL_NAME = "RNAdministrator"
        ROLE = "Administrator"

    class OperatorUser:
        USER_ID = "UIOperator"
        REAL_NAME = "RNOperator"
        ROLE = "Operator"

    class MetricsUser:
        USER_ID = "UIMetrics"
        REAL_NAME = "RNMetrics"
        ROLE = "Metrics"

    class BackupUser:
        USER_ID = "UIBackup"
        REAL_NAME = "RNBackup"
        ROLE = "Backup"

    DETAILS = ""
    USERS_LIST = [AdministratorUser, BackupUser, MetricsUser, OperatorUser, AdminUser]

    # nitropy nethsm --host nethsmdemo.nitrokey.com --no-verify-tls info
