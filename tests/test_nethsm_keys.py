import base64

import pytest
from conftest import Constants as C
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from utilities import nethsm  # noqa: F401
from utilities import (
    add_user,
    connect,
    encrypt_rsa,
    generate_rsa_key_pair,
    verify_rsa_signature,
)

import nethsm as nethsm_module

"""########## Preparation for the Tests ##########

To run these test on Ubuntu like systems in Terminal you need sudo rights.
If you want to run these tests on Ubuntu like systems in Pycharm follow this
instruction to run the script as root:
https://stackoverflow.com/questions/36530082/running-pycharm-as-root-from-launcher
"""


def add_key(nethsm):
    """Add a key pair on the NetHSM.

    If the key ID is not set, it is generated by the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""

    if C.KEY_ID_ADDED in nethsm.list_keys(None):
        nethsm.delete_key(C.KEY_ID_ADDED)

    p, q, e = generate_rsa_key_pair(1024)

    nethsm.add_key(
        key_id=C.KEY_ID_ADDED,
        type=C.TYPE,
        mechanisms=C.MECHANISM,
        prime_p=p,
        prime_q=q,
        public_exponent=e,
        data=C.DATA,
        tags=[],
    )


def generate_key_aes(nethsm):
    """Add a key pair on the NetHSM.

    If the key ID is not set, it is generated by the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""

    if C.KEY_ID_AES in nethsm.list_keys(None):
        nethsm.delete_key(C.KEY_ID_AES)

    nethsm.generate_key(
        key_id=C.KEY_ID_AES,
        type="Generic",
        mechanisms=["AES_Encryption_CBC", "AES_Decryption_CBC"],
        length=256,
    )


def generate_key(nethsm):
    """Get information about a key on the NetHSM.

    This command requires authentication as a user with the Administrator or
    Operator role."""
    try:
        nethsm.generate_key(C.TYPE, C.MECHANISM, C.LENGTH, C.KEY_ID_GENERATED)
    except nethsm_module.NetHSMError:
        pass


def add_key_tags(nethsm):
    """Add a tag for a key on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    nethsm.add_key_tag(key_id=C.KEY_ID_GENERATED, tag=C.TAG1)
    nethsm.add_key_tag(key_id=C.KEY_ID_GENERATED, tag=C.TAG2)
    nethsm.add_key_tag(key_id=C.KEY_ID_GENERATED, tag=C.TAG3)


def encrypt_data():
    """Todo: encrypt data with python for test_decrypt to work"""


"""##########Start of Tests##########"""


def test_generate_key(nethsm):
    """Generate a key pair on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    generate_key(nethsm)


def test_add_key(nethsm):
    """Add a key pair on the NetHSM.

    If the key ID is not set, it is generated by the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    add_key(nethsm)


def test_add_get_key_by_public_key(nethsm):
    """Get information about a key on the NetHSM.

    This command requires authentication as a user with the Administrator or
    Operator role."""
    add_key(nethsm)

    print("retrieving")

    nethsm.get_key_public_key(C.KEY_ID_ADDED)


def test_generate_get_key_by_id(nethsm):
    """Get information about a key on the NetHSM.

    This command requires authentication as a user with the Administrator or
    Operator role."""
    generate_key(nethsm)

    key = nethsm.get_key(C.KEY_ID_GENERATED)
    # mechanisms = ", ".join(key.mechanisms) Todo: test with multiple mech.
    assert key.type == C.TYPE
    for mechanism in key.mechanisms:
        assert mechanism in C.MECHANISM
    assert key.operations >= 0
    if key.tags:
        assert key.tags
    if key.modulus:
        assert key.modulus
    if key.public_exponent:
        assert key.public_exponent


def test_add_key_tag_get_key(nethsm):
    """Add a tag for a key on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    generate_key(nethsm)
    add_key_tags(nethsm)

    key = nethsm.get_key(C.KEY_ID_GENERATED)
    tags = key.tags
    assert C.TAG1 in tags
    assert C.TAG2 in tags
    assert C.TAG3 in tags


def test_delete_key_tag_get_key(nethsm):
    """Delete a tag for a key on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""

    add_key_tags(nethsm)

    nethsm.delete_key_tag(key_id=C.KEY_ID_GENERATED, tag=C.TAG1)
    nethsm.delete_key_tag(key_id=C.KEY_ID_GENERATED, tag=C.TAG2)
    key = nethsm.get_key(C.KEY_ID_GENERATED)

    assert C.TAG1 not in key.tags
    assert C.TAG2 not in key.tags
    assert C.TAG3 in key.tags


def test_list_get_keys(nethsm):
    """List all keys on the NetHSM.

    This command requires authentication as a user with the Administrator or
    Operator role."""
    add_key(nethsm)
    generate_key(nethsm)

    key_ids = nethsm.list_keys(None)
    for key_id in key_ids:
        key = nethsm.get_key(key_id=key_id)
        assert key.type == C.TYPE
        for mechanism in key.mechanisms:
            assert mechanism in C.MECHANISM
        assert key.operations >= 0
        if key.tags:
            assert key.tags
        if key.modulus:
            assert key.modulus
        if key.public_exponent:
            assert key.public_exponent


def test_delete_key(nethsm):
    """Delete the key pair with the given key ID on the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    generate_key(nethsm)
    add_key(nethsm)

    nethsm.delete_key(C.KEY_ID_GENERATED)
    nethsm.delete_key(C.KEY_ID_ADDED)


def test_set_get_key_certificate(nethsm):

    add_key(nethsm)
    with open(C.CERTIFICATE_FILE, "rb") as f:
        nethsm.set_key_certificate(C.KEY_ID_ADDED, f, "application/x-pem-file")
    with open(C.CERTIFICATE_FILE, "rb") as f:
        certificate = nethsm.get_key_certificate(C.KEY_ID_ADDED)
        file_cert = f.read().decode("utf-8")
        assert certificate == file_cert


def test_key_csr(nethsm):

    add_key(nethsm)

    csr = nethsm.key_csr(
        key_id=C.KEY_ID_ADDED,
        country=C.COUNTRY,
        state_or_province=C.STATE_OR_PROVINCE,
        locality=C.LOCALITY,
        organization=C.ORGANIZATION,
        organizational_unit=C.ORGANIZATIONAL_UNIT,
        common_name=C.COMMON_NAME,
        email_address=C.EMAIL_ADDRESS,
    )
    print(csr)


def test_delete_certificate(nethsm):
    """Delete a certificate for a stored key from the NetHSM.

    This command requires authentication as a user with the Administrator
    role."""

    add_key(nethsm)
    with open(C.CERTIFICATE_FILE, "rb") as f:
        nethsm.set_key_certificate(C.KEY_ID_ADDED, f, "application/x-pem-file")

    nethsm.delete_key_certificate(C.KEY_ID_ADDED)

    with pytest.raises(nethsm_module.NetHSMError):
        nethsm.get_key_certificate(C.KEY_ID_ADDED)


def test_sign(nethsm):  # mit dem privaten schlüssel signieren
    """Sign data with a secret key on the NetHSM and print the signature.

    This command requires authentication as a user with the Operator role."""
    generate_key(nethsm)
    add_user(nethsm, C.OperatorUser)
    key = nethsm.get_key_public_key(C.KEY_ID_GENERATED)

    hash_object = SHA256.new(data=C.DATA.encode())

    with connect(C.OperatorUser) as nethsm:
        signature = nethsm.sign(
            C.KEY_ID_GENERATED,
            base64.b64encode(hash_object.digest()).decode(),
            "PSS_SHA256",
        )
        print(signature)
        verify_rsa_signature(key, hash_object, base64.b64decode(signature))


def test_decrypt(nethsm):
    """Decrypt data with a secret key on the NetHSM and print the decrypted
    message.

    This command requires authentication as a user with the Operator role.
    Todo: encrypt_data() with python for test_decrypt() to work"""
    generate_key(nethsm)
    add_user(nethsm, C.OperatorUser)
    key = nethsm.get_key_public_key(C.KEY_ID_GENERATED)
    encrypted = encrypt_rsa(key, C.DATA)
    with connect(C.OperatorUser) as nethsm:
        decrypt = nethsm.decrypt(
            C.KEY_ID_GENERATED,
            base64.b64encode(encrypted).decode(),
            C.MODE,
            "arstasrta",
        )
        assert base64.b64decode(decrypt).decode() == C.DATA


def test_encrypt_decrypt(nethsm):

    generate_key_aes(nethsm)
    add_user(nethsm, C.OperatorUser)
    IV = Random.new().read(AES.block_size)

    iv_b64 = base64.b64encode(IV).decode()

    data_b64 = base64.b64encode(C.DATA.encode()).decode()

    with connect(C.OperatorUser) as nethsm:

        encrypted = nethsm.encrypt(
            C.KEY_ID_AES,
            data_b64,
            "AES_CBC",
            iv_b64,
        )
        decrypt = nethsm.decrypt(
            C.KEY_ID_AES,
            encrypted[0],
            "AES_CBC",
            iv_b64,
        )
        assert decrypt == data_b64