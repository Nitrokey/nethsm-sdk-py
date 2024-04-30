import contextlib
import datetime
import os
import subprocess
from abc import ABC, abstractmethod
from time import sleep
from typing import Iterator, Optional

import docker  # type: ignore
import podman  # type: ignore
import pytest
import urllib3
from conftest import Constants as C
from conftest import UserData
from Crypto.Cipher import PKCS1_v1_5 as PKCS115_Cipher
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

import nethsm as nethsm_module
from nethsm import Authentication, Base64, NetHSM, RsaPrivateKey


class Container(ABC):
    def restart(self) -> None:
        self.kill()
        self.start()
        self.wait()

    def wait(self) -> None:
        http = urllib3.PoolManager(cert_reqs="CERT_NONE")
        print("Waiting for container to be ready")
        while True:
            try:
                response = http.request("GET", f"https://{C.HOST}/api/v1/health/alive")
                print(f"Response: {response.status}")
                if response.status == 200:
                    break
            except Exception as e:
                print(e)
                pass
            sleep(0.5)

    @abstractmethod
    def start(self) -> None:
        ...

    @abstractmethod
    def kill(self) -> None:
        ...


class DockerContainer(Container):
    def __init__(self, client: docker.client.DockerClient, image: docker.models.images.Image) -> None:
        self.client = client
        self.image = image
        self.container = None

    def start(self) -> None:
        self.container = self.client.containers.run(
            self.image,
            "",
            ports={"8443": 8443},
            remove=True,
            detach=True,
        )

    def kill(self) -> None:
        if self.container:
            try:
                self.container.kill()
                self.container.wait()
            except docker.errors.APIError:
                pass


class PodmanContainer(Container):
    def __init__(self, client: podman.client.PodmanClient, image: podman.domain.images.Image) -> None:
        self.client = client
        self.image = image
        self.container = None

    def start(self) -> None:
        self.container = self.client.containers.run(
            self.image,
            "",
            ports={"8443": 8443},
            remove=True,
            detach=True,
        )

    def kill(self) -> None:
        if self.container:
            try:
                self.container.kill()
                self.container.wait()
            except podman.errors.APIError:
                pass


class CIContainer(Container):
    def __init__(self) -> None:
        self.process: Optional[subprocess.Popen[bytes]] = None

    def start(self) -> None:
        os.system("pkill keyfender.unix")
        os.system("pkill etcd")

        # Wait for everything to shut down, creates problems otherwise on the gitlab ci
        sleep(1)

        os.system("rm -rf /data")

        self.process = subprocess.Popen(
            [
                "/bin/sh",
                "-c",
                "/start.sh",
            ]
        )

    def kill(self) -> None:
        if self.process:
            self.process.kill()


class KeyfenderManager(ABC):
    @abstractmethod
    def spawn(self) -> Container:
        ...

    @staticmethod
    def get() -> "KeyfenderManager":
        if C.TEST_MODE == "docker":
            return KeyfenderDockerManager()
        elif C.TEST_MODE == "podman":
            return KeyfenderPodmanManager()
        elif C.TEST_MODE == "ci":
            return KeyfenderCIManager()
        else:
            raise Exception("Invalid Test Mode")


class KeyfenderDockerManager(KeyfenderManager):
    def __init__(self) -> None:
        client = docker.from_env()

        while True:
            containers = client.containers.list(
                filters={"ancestor": C.IMAGE}, ignore_removed=True
            )
            print(containers)
            if len(containers) == 0:
                break

            for container in containers:
                try:
                    container.remove(force=True)
                except docker.errors.APIError as e:
                    print(e)
                    pass
            sleep(1)

        repository, tag = C.IMAGE.split(":")
        image = client.images.pull(repository, tag=tag)

        self.client = client
        self.image = image

    def spawn(self) -> Container:
        return DockerContainer(self.client, self.image)


class KeyfenderPodmanManager(KeyfenderManager):
    def __init__(self) -> None:
        client = podman.from_env()

        while True:
            containers = client.containers.list(
                filters={"ancestor": C.IMAGE}, ignore_removed=True
            )
            print(containers)
            if len(containers) == 0:
                break

            for container in containers:
                try:
                    container.remove(force=True)
                except docker.errors.APIError as e:
                    print(e)
                    pass
            sleep(1)

        repository, tag = C.IMAGE.split(":")
        image = client.images.pull(repository, tag=tag)

        self.client = client
        self.image = image

    def spawn(self) -> Container:
        return PodmanContainer(self.client, self.image)


class KeyfenderCIManager(KeyfenderManager):
    def spawn(self) -> Container:
        return CIContainer()


@contextlib.contextmanager
def connect(user: UserData) -> Iterator[NetHSM]:
    auth = Authentication(user.user_id, C.PASSWORD)
    with nethsm_module.connect(C.HOST, auth, C.VERIFY_TLS) as nethsm_out:
        yield nethsm_out


def provision(nethsm: NetHSM) -> None:
    """Initial provisioning of a NetHSM.

    If unlock or admin passphrases are not set, they have to be entered
    interactively.  If the system time is not set, the current system time is
    used."""
    if nethsm.get_state().value == "Unprovisioned":
        system_time = datetime.datetime.now(datetime.timezone.utc)
        nethsm.provision("unlockunlock", "adminadmin", system_time)


def add_user(nethsm: NetHSM, user: UserData) -> None:
    """Create a new user on the NetHSM.

    If the real name, role or passphrase are not specified, they have to be
    specified interactively.  If the user ID is not set, it is generated by the
    NetHSM.

    This command requires authentication as a user with the Administrator
    role."""
    try:
        nethsm.get_user(user_id=user.user_id)
    except nethsm_module.NetHSMError:
        nethsm.add_user(user.real_name, user.role, C.PASSPHRASE, user.user_id)


def generate_rsa_key_pair(length_in_bit: int) -> RsaPrivateKey:
    key_pair = RSA.generate(length_in_bit)
    length_in_byte = int(length_in_bit / 8)
    # "big" byteorder is needed, it's the dominant order in networking
    p = key_pair.p.to_bytes(length_in_byte, "big")
    q = key_pair.q.to_bytes(length_in_byte, "big")
    e = key_pair.e.to_bytes(length_in_byte, "big")
    return RsaPrivateKey(
        prime_p=Base64.encode(p),
        prime_q=Base64.encode(q),
        public_exponent=Base64.encode(e),
    )


def verify_rsa_signature(
    public_key: str, message: SHA256.SHA256Hash, signature: bytes
) -> bool:
    key = RSA.importKey(public_key)
    return PKCS1_PSS.new(key).verify(message, signature)


def encrypt_rsa(public_key: str, message: str) -> bytes:
    key = RSA.importKey(public_key)
    cipher = PKCS115_Cipher.new(key)
    return cipher.encrypt(bytes(message, "utf-8"))


def lock(nethsm: NetHSM) -> None:
    if nethsm.get_state().value == "Operational":
        nethsm.lock()
    assert nethsm.get_state().value == "Locked"


def unlock(nethsm: NetHSM, unlock_passphrase: str) -> None:
    if nethsm.get_state().value == "Locked":
        nethsm.unlock(unlock_passphrase)
    assert nethsm.get_state().value == "Operational"


def set_backup_passphrase(nethsm: NetHSM) -> None:
    """Set the backup passphrase of a NetHSM.

    This command requires authentication as a user with the Administrator
    role.
    """
    nethsm.set_backup_passphrase(C.BACKUP_PASSPHRASE)


def update(nethsm: NetHSM) -> None:
    """Load an update to a NetHSM instance.

    This command requires authentication as a user with the Administrator
    role.

    Todo Further Optimization would download the latest.zip, unzip it and
    get the update from there"""

    try:
        with open(C.FILENAME_UPDATE_IN_TEST, "rb") as f:
            nethsm.update(f)
    except OSError as e:
        print(e, type(e))
        assert False


def self_sign_csr(csr: str) -> bytes:
    # Generate a private key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    parsed_csr = x509.load_pem_x509_csr(csr.encode("utf-8"))

    subject = parsed_csr.subject
    issuer = subject
    public_key = parsed_csr.public_key()
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(public_key),  # type: ignore
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )
    return cert.public_bytes(Encoding.PEM)
