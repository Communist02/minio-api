from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from argon2.low_level import hash_secret_raw, Type


# def encrypt_password(password: str) -> list[bytes]:
#     """Derives X25519 key pair from password using HKDF."""

#     password = password.encode()

#     context_info = b'mn,yghjghjghcx-context-v1'

#     hkdf = HKDF(
#         algorithm=hashes.SHA256(),
#         length=32,
#         salt=None,
#         info=context_info,
#         backend=default_backend()
#     )

#     private_bytes = hkdf.derive(password)

#     private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
#     public_key = private_key.public_key()
#     return [
#         public_key.public_bytes(
#             encoding=serialization.Encoding.Raw,
#             format=serialization.PublicFormat.Raw
#         ),
#         private_key.private_bytes(
#             encoding=serialization.Encoding.Raw,
#             format=serialization.PrivateFormat.Raw,
#             encryption_algorithm=serialization.NoEncryption()
#         )
#     ]

def encrypt_password(password: str, salt: bytes = os.urandom(16)) -> tuple[bytes, bytes, bytes]:
    """Encrypts a secret key using recipient's X25519 public key and AES-GCM. Salt minimum length is 8."""

    password_bytes = password.encode()

    # Apply Argon2id for password stretching
    stretched_key = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,  # 64 MiB
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )

    # Use stretched key as input to HKDF
    context_info = b'mn,yghjghjghcx-context-v1'
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=context_info,
        backend=default_backend()
    )
    private_bytes = hkdf.derive(stretched_key)

    private_key = x25519.X25519PrivateKey.from_private_bytes(private_bytes)
    public_key = private_key.public_key()

    return (
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ),
        private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ),
        salt  # Save this for future derivation (e.g., during decryption)
    )


def encrypt_key(secret_key: bytes, public_key: bytes) -> bytes:
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


def decrypt_key(encrypted_key: bytes, private_key: bytes) -> bytes:
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


def recover_private_key_from_password(password: str, salt: bytes) -> bytes:
    password_bytes = password.encode()

    stretched_key = hash_secret_raw(
        secret=password_bytes,
        salt=salt,
        time_cost=3,
        memory_cost=64 * 1024,
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'mn,yghjghjghcx-context-v1',
        backend=default_backend()
    )
    private_bytes = hkdf.derive(stretched_key)

    return private_bytes


password = '123456'
keys = encrypt_password(password, b'1'*8)
print(keys)

recovered_private_key = recover_private_key_from_password('123456', keys[2])

key = b'1234' * 8
enc_key = encrypt_key(key, keys[0])
dec_key = decrypt_key(enc_key, keys[1])

print(keys)
print(recovered_private_key)
print(key)
print(enc_key)
print(dec_key)
