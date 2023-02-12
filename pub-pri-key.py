import base58
import hashlib
import ecdsa
import os

'''
pip install base58
pip install ecdsa
'''

def create_wif(private_key_hex:str) -> str:
    private_key_bytes = bytes.fromhex(private_key_hex)
    prefix = b'\x80'
    extended_key = prefix + private_key_bytes
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = base58.b58encode(extended_key + checksum)
    return wif.decode('utf-8')


def create_private_key():
    entropy = os.urandom(32)
    entropy = int.from_bytes(entropy, byteorder='big')
    private_key = hashlib.sha256(str(entropy).encode()).hexdigest()
    return private_key


def wif_to_public_key(wif_key:str) -> str:
    private_key = base58.b58decode(wif_key)[1:-4]
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    return '04' + verifying_key.to_string().hex()


def compress_public_key(public_key:str) -> str:
    if public_key[0:2] != '04':
        raise ValueError('Invalid public key')
    x = int(public_key[2:66], 16)
    y = int(public_key[66:], 16)
    if (y % 2) == 0:
        public_key = '02' + format(x, '064x')
    else:
        public_key = '03' + format(x, '064x')
    return public_key

#wif_key = "5KMjtT3FcbCkdcbNYDMaTT8hGRbTwpj2fFHirSkqazvw4QSWsgk"

Entropy = create_private_key()
print("Private Key: %s"%Entropy)

wif = create_wif(Entropy)
print("WIF Key: %s"% wif)

pubkey = wif_to_public_key(wif)
print("Original Public Key: %s"%pubkey)

public_key = compress_public_key(pubkey)
print("Compress Public Key: %s"%public_key)
