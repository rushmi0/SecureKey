import hashlib
import binascii
import hmac


def b58encode(v: bytes) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

    p, acc = 1, 0
    for c in reversed(v):
        acc += p * c
        p = p << 8

    string = ""
    while acc:
        acc, idx = divmod(acc, 58)
        string = alphabet[idx : idx + 1] + string
    return string


def to_master_key(seed: bytes, testnet: bool = False) -> str:
    if len(seed) != 64:
        raise ValueError("Provided seed should have length of 64")

    # Compute HMAC-SHA512 of seed
    seed = hmac.new(b"Bitcoin seed", seed, digestmod=hashlib.sha512).digest()

    # Serialization format can be found at: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki#Serialization_format
    xprv = b"\x04\x88\xad\xe4"  # Version for private mainnet

    if testnet:
        xprv = b"\x04\x35\x83\x94"  # Version for private testnet

    xprv += b"\x00" * 9  # Depth, parent fingerprint, and child number
    xprv += seed[32:]  # Chain code
    xprv += b"\x00" + seed[:32]  # Master key

    # Double hash using SHA256
    hashed_xprv = hashlib.sha256(xprv).digest()
    hashed_xprv = hashlib.sha256(hashed_xprv).digest()

    # Append 4 bytes of checksum
    xprv += hashed_xprv[:4]

    return b58encode(xprv)


def to_master_keyV2(seed: bytes, testnet: bool = False) -> str:
    if len(seed) != 64:
        raise ValueError("Provided seed should have length of 64")

    # Compute HMAC-SHA512 of seed
    seed_hash = hmac.new(b"Bitcoin seed", seed, digestmod=hashlib.sha512).digest()

    xprv = b"\x04\x88\xad\xe4"  # Version for private mainnet

    depth = b"\x00" * 9

    xprv_parts = [xprv, depth, seed_hash[32:], b"\x00" + seed_hash[:32]]

    # Concatenate xprv_parts into a single byte string
    xprv_bytes = b"".join(xprv_parts)

    # Double hash using SHA256
    hashed_xprv = hashlib.sha256(xprv_bytes).digest()
    hashed_xprv = hashlib.sha256(hashed_xprv).digest()

    # Append 4 bytes of checksum
    xprv_bytes += hashed_xprv[:4]

    return b58encode(xprv_bytes)


def main():
    mnemonic = "worth noise runway direct patrol border maze smart fade door month pumpkin"
    print(f"mnemonic \n {mnemonic}")
    passphrase = "นึกแล้วมึงต้องอ่าน"
    print(f"Passphrase:\n {passphrase}")

    password = mnemonic.encode('utf-8')
    salt = f"mnemonic{passphrase}".encode('utf-8')
    iterations = 2048
    keylength = 64
    digest = hashlib.sha512

    master = hashlib.pbkdf2_hmac(digest().name, password, salt, iterations, keylength)
    print(len(master), master)
    seed = binascii.hexlify(master).decode('utf-8')
    print(f"BIP39 Seed:\n {seed}\n")

    print(to_master_key(master))
    print(to_master_keyV2(master))


if __name__ == "__main__":
    main()
