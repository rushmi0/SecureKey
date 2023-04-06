import binascii
import hmac
import hashlib
import ecdsa
import struct
import base58
from ecdsa.curves import SECP256k1
from ecdsa.ecdsa import int_to_string, string_to_int


#chain m
# generate a seed byte sequence S of a chosen length (beween 128 and 512 bits)
seed = binascii.unhexlify("000102030405060708090a0b0c0d0e0f")

#calculate HMAC-SHA512 of seed Key= "Bitcoin seed" Data = seed
I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()

# Divide HMAC into "Left" and "Right" section of 32 bytes each :)
Il, Ir = I[:32], I[32:]

# Serialization format can be found at: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format

# left section of HMAC: source to generate keypair
secret = Il

# right section of HMAC: chain code
chain = Ir

# Version string for mainnet extended private keys
xprv = binascii.unhexlify("0488ade4")

# Version string for mainnet extended public keys
xpub = binascii.unhexlify("0488b21e")

# Child depth; parent increments its own by one when assigning this
depth = b"\x00"


# Parent fingerprint,
fpr = b'\0\0\0\0'

# Child index
index = 0

# >L -> big endian -> the way of storing values starting from most significant value in sequence
child = struct.pack('>L', index)

k_priv = ecdsa.SigningKey.from_string(secret, curve=SECP256k1)
K_priv = k_priv.get_verifying_key()


# ser256(p): serializes integer p as a 32-byte sequence
data_priv = b'\x00' + (k_priv.to_string())

# serialization the coordinate pair P = (x,y) as a byte sequence using SEC1's compressed form
if K_priv.pubkey.point.y() & 1:
    data_pub = b'\3'+int_to_string(K_priv.pubkey.point.x())
else:
    data_pub = b'\2'+int_to_string(K_priv.pubkey.point.x())

raw_priv = xprv + depth + fpr + child + chain + data_priv
raw_pub = xpub + depth + fpr + child + chain + data_pub

# Double hash using SHA256
hashed_xprv = hashlib.sha256(raw_priv).digest()
hashed_xprv = hashlib.sha256(hashed_xprv).digest()
hashed_xpub = hashlib.sha256(raw_pub).digest()
hashed_xpub = hashlib.sha256(hashed_xpub).digest()

# Append 4 bytes of checksum
raw_priv += hashed_xprv[:4]
raw_pub += hashed_xpub[:4]

# Return base58
print(base58.b58encode(raw_priv).decode())
print(base58.b58encode(raw_pub).decode())

