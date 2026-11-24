import os
from Crypto.Cipher import AES, ChaCha20_Poly1305, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt

# ── Magic headers (4 bytes) ── written at the very start of every encrypted file
# Decrypt page reads these bytes to auto-detect algorithm reliably
MAGIC_HYBRID = b'HYBR'
MAGIC_CHACHA = b'CCH_'
MAGIC_AES    = b'AES_'

MAGIC_SIZE   = 4   # bytes reserved for the magic header


# ================= RSA KEYS (PASSWORD PROTECTED) =================

def generate_secure_rsa_keys(password):
    """
    RSA-2048 key pair generate karo.
    Private key password se protect hoti hai (scryptAndAES128-CBC).
    Returns: (private_key_bytes, public_key_bytes)
    """
    key = RSA.generate(2048)

    private_key = key.export_key(
        passphrase=password,
        pkcs=8,
        protection="scryptAndAES128-CBC"
    )

    public_key = key.publickey().export_key()

    return private_key, public_key


# ================= HYBRID AES + RSA =================

def encrypt_file_hybrid(input_file, output_file, public_key):
    """
    File ko RSA+AES Hybrid se encrypt karo.
    Format: [HYBR magic (4)] [encrypted_key_len (2)] [encrypted_key] [nonce (16)] [tag (16)] [ciphertext]
    """
    aes_key    = get_random_bytes(32)
    cipher_aes = AES.new(aes_key, AES.MODE_GCM)

    with open(input_file, "rb") as f:
        data = f.read()

    ciphertext, tag = cipher_aes.encrypt_and_digest(data)

    rsa_key       = RSA.import_key(public_key)
    cipher_rsa    = PKCS1_OAEP.new(rsa_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)

    with open(output_file, "wb") as f:
        f.write(MAGIC_HYBRID)                           # 4 bytes — algo identifier
        f.write(len(encrypted_key).to_bytes(2, 'big'))  # 2 bytes
        f.write(encrypted_key)
        f.write(cipher_aes.nonce)                       # 16 bytes
        f.write(tag)                                    # 16 bytes
        f.write(ciphertext)


def decrypt_file_hybrid(input_file, output_file, private_key_data, password=None):
    """
    RSA+AES Hybrid se decrypt karo.
    Automatically magic header skip karta hai agar present ho.
    """
    with open(input_file, "rb") as f:
        header = f.read(MAGIC_SIZE)
        # Agar magic header nahi mila (old files), rewind karo
        if header != MAGIC_HYBRID:
            f.seek(0)

        key_len       = int.from_bytes(f.read(2), 'big')
        encrypted_key = f.read(key_len)
        nonce         = f.read(16)
        tag           = f.read(16)
        ciphertext    = f.read()

    rsa_key    = RSA.import_key(private_key_data, passphrase=password)
    cipher_rsa = PKCS1_OAEP.new(rsa_key)
    aes_key    = cipher_rsa.decrypt(encrypted_key)

    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    data       = cipher_aes.decrypt_and_verify(ciphertext, tag)

    with open(output_file, "wb") as f:
        f.write(data)


# ================= ChaCha20-Poly1305 =================

def encrypt_chacha_strong(input_file, output_file, password):
    """
    Format: [CCH_ magic (4)] [salt (16)] [nonce (12)] [tag (16)] [ciphertext]
    """
    salt   = get_random_bytes(16)
    key    = scrypt(password.encode(), salt, 32, N=2**15, r=8, p=1)
    cipher = ChaCha20_Poly1305.new(key=key)

    with open(input_file, "rb") as f:
        data = f.read()

    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(output_file, "wb") as f:
        f.write(MAGIC_CHACHA)           # 4 bytes — algo identifier
        f.write(salt)                   # 16 bytes
        f.write(cipher.nonce)           # 12 bytes
        f.write(tag)                    # 16 bytes
        f.write(ciphertext)


def decrypt_chacha_strong(input_file, output_file, password):
    """
    Automatically magic header skip karta hai agar present ho.
    """
    with open(input_file, "rb") as f:
        header = f.read(MAGIC_SIZE)
        if header != MAGIC_CHACHA:
            f.seek(0)   # old file — no header

        salt       = f.read(16)
        nonce      = f.read(12)
        tag        = f.read(16)
        ciphertext = f.read()

    key    = scrypt(password.encode(), salt, 32, N=2**15, r=8, p=1)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    data   = cipher.decrypt_and_verify(ciphertext, tag)

    with open(output_file, "wb") as f:
        f.write(data)


# ================= AES-256-GCM =================

def encrypt_aes(input_file, output_file, password, key_size=32):
    """
    Format: [AES_ magic (4)] [salt (16)] [nonce (16)] [tag (16)] [ciphertext]
    """
    salt   = get_random_bytes(16)
    key    = scrypt(password.encode(), salt, key_size, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM)

    with open(input_file, "rb") as f:
        data = f.read()

    ciphertext, tag = cipher.encrypt_and_digest(data)

    with open(output_file, "wb") as f:
        f.write(MAGIC_AES)      # 4 bytes — algo identifier
        f.write(salt)           # 16 bytes
        f.write(cipher.nonce)   # 16 bytes
        f.write(tag)            # 16 bytes
        f.write(ciphertext)


def decrypt_aes(input_file, output_file, password, key_size=32):
    """
    Automatically magic header skip karta hai agar present ho.
    """
    with open(input_file, "rb") as f:
        header = f.read(MAGIC_SIZE)
        if header != MAGIC_AES:
            f.seek(0)   # old file — no header

        salt       = f.read(16)
        nonce      = f.read(16)
        tag        = f.read(16)
        ciphertext = f.read()

    key    = scrypt(password.encode(), salt, key_size, N=2**14, r=8, p=1)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    data   = cipher.decrypt_and_verify(ciphertext, tag)

    with open(output_file, "wb") as f:
        f.write(data)


# ================= ALGO DETECTION (backend helper) =================

def detect_algo_from_file(filepath):
    """
    File ke pehle 4 bytes padh ke algorithm detect karo.
    Returns: 'HYBRID' | 'CHACHA' | 'AES' | None
    """
    try:
        with open(filepath, "rb") as f:
            magic = f.read(MAGIC_SIZE)
        if magic == MAGIC_HYBRID:
            return 'HYBRID'
        if magic == MAGIC_CHACHA:
            return 'CHACHA'
        if magic == MAGIC_AES:
            return 'AES'
    except Exception:
        pass
    return None