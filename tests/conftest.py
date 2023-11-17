from dataclasses import dataclass
from os import environ
from typing import Literal

from nethsm import (
    DecryptMode,
    KeyMechanism,
    KeyType,
    LogLevel,
    Role,
    UnattendedBootStatus,
)


@dataclass
class UserData:
    user_id: str
    real_name: str
    role: Role


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
    UNATTENDED_BOOT_OFF = UnattendedBootStatus.OFF
    UNATTENDED_BOOT_ON = UnattendedBootStatus.ON
    LOG_LEVEL = LogLevel.INFO

    # test_nethsm_keys
    TYPE = KeyType.RSA
    MECHANISM = [
        KeyMechanism.RSA_SIGNATURE_PKCS1,
        KeyMechanism.RSA_DECRYPTION_PKCS1,
        KeyMechanism.RSA_SIGNATURE_PSS_SHA256,
        KeyMechanism.RSA_DECRYPTION_OAEP_SHA256,
    ]
    LENGTH = 1024
    KEY_ID_ADDED = "KeyIdAdded"
    KEY_ID_GENERATED = "KeyIdGenerated"
    KEY_ID_AES = "KeyIdAES"
    DATA = "Test data 123456"
    MODE = DecryptMode.PKCS1
    # 'PKCS1', 'PSS_MD5', 'PSS_SHA1', 'PSS_SHA224', 'PSS_SHA256', 'PSS_SHA384', 'PSS_SHA512', 'EdDSA', 'ECDSA'
    # test_nethsm_users, test_nethsm_keys
    TAG1 = "Frankfurt"
    TAG2 = "Berlin"
    TAG3 = "Teltow"
    TAGS = [TAG1, TAG2, TAG3]

    ADMIN_USER = UserData(user_id="admin", real_name="admin", role=Role.ADMINISTRATOR)
    ADMINISTRATOR_USER = UserData(
        user_id="UIAdministrator", real_name="RNAdministrator", role=Role.ADMINISTRATOR
    )
    OPERATOR_USER = UserData(
        user_id="UIOperator", real_name="RNOperator", role=Role.OPERATOR
    )
    METRICS_USER = UserData(
        user_id="UIMetrics", real_name="RNMetrics", role=Role.METRICS
    )
    BACKUP_USER = UserData(user_id="UIBackup", real_name="RNBackup", role=Role.BACKUP)

    DETAILS = ""
    USERS_LIST = [
        ADMINISTRATOR_USER,
        BACKUP_USER,
        METRICS_USER,
        OPERATOR_USER,
        ADMIN_USER,
    ]

    # nitropy nethsm --host nethsmdemo.nitrokey.com --no-verify-tls info
