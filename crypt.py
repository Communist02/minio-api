import secrets
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from argon2.low_level import hash_secret_raw, Type
from hashlib import sha256


def hash_argon2_from_password(password: str) -> bytes:
    password_bytes = password.encode()
    salt = sha256(password_bytes).digest()[:16]

    hash = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,  # 64 MiB
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )
    return hash


def hash_division(hash: bytes) -> tuple[bytes, bytes]:
    part1 = secrets.token_bytes(len(hash))
    part2 = bytes(h ^ p for h, p in zip(hash, part1))

    return part1, part2


def hash_reconstruct(part1: bytes, part2: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(part1, part2))


def key_pair_from_hash(hash: bytes) -> tuple[bytes, bytes]:
    """return pivate_key, public_key"""
    private_key = x25519.X25519PrivateKey.from_private_bytes(hash)
    public_key = private_key.public_key()

    return (
        private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    )


def random_key_pair() -> tuple[bytes, bytes]:
    """return pivate_key, public_key"""
    return key_pair_from_hash(secrets.token_bytes(32))


def asym_encrypt_key(secret_key: bytes, public_key: bytes) -> bytes:
    """Encrypts a secret key using recipient's X25519 public key and AES-GCM."""

    # Генерируем временную (ephemeral) пару ключей
    ephemeral_private_key = x25519.X25519PrivateKey.generate()
    ephemeral_public_key = ephemeral_private_key.public_key().public_bytes(encoding=serialization.Encoding.Raw,
                                                                           format=serialization.PublicFormat.Raw)

    # Загружаем публичный ключ получателя
    recipient_public_key = x25519.X25519PublicKey.from_public_bytes(public_key)

    # Вычисляем общий секрет ECDH
    shared_secret = ephemeral_private_key.exchange(recipient_public_key)

    # Производный ключ для AES-GCM через HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption-key-context',
        backend=default_backend()
    )
    aes_key = hkdf.derive(shared_secret)

    # Шифрование с использованием AES-GCM
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(
        nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(secret_key) + encryptor.finalize()

    # Объединяем компоненты: временный публичный ключ + nonce + тег + шифртекст
    return ephemeral_public_key + nonce + encryptor.tag + ciphertext


def asym_decrypt_key(encrypted_key: bytes, private_key: bytes) -> bytes:
    """Decrypts a secret key using X25519 private key and AES-GCM."""

    # Разбор компонентов из входных данных
    ephemeral_public_key = encrypted_key[:32]
    nonce = encrypted_key[32:44]
    tag = encrypted_key[44:60]
    ciphertext = encrypted_key[60:]

    # Загружаем ключи
    private_key_obj = x25519.X25519PrivateKey.from_private_bytes(private_key)
    ephemeral_pubkey = x25519.X25519PublicKey.from_public_bytes(
        ephemeral_public_key)

    # Вычисляем общий секрет ECDH
    shared_secret = private_key_obj.exchange(ephemeral_pubkey)

    # Производный ключ для AES-GCM через HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'encryption-key-context',
        backend=default_backend()
    )
    aes_key = hkdf.derive(shared_secret)

    # Расшифровка с использованием AES-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(
        nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def sym_encrypt_key(secret: bytes, aes_key: bytes) -> bytes:
    assert len(secret) == 32
    assert len(aes_key) == 32

    nonce = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(
        nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_key = encryptor.update(secret) + encryptor.finalize()
    return nonce + encrypted_key


def sym_decrypt_key(ciphertext: bytes, aes_key: bytes):
    assert len(ciphertext) == 48
    assert len(aes_key) == 32

    nonce = ciphertext[:16]
    encrypted_key = ciphertext[16:]

    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(
        nonce), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_key) + decryptor.finalize()
