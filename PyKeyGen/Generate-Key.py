#!/usr/bin/env python3

import hashlib
import base58  # https://pypi.org/project/base58/
import ecdsa  # https://pypi.org/project/ecdsa/
import time
import os

ENTROPY_LENGTH = 512  # ปรับแก้จำนวน Bytes ตามต้องการ
LOOP_TIME = 62000000 


def create_wif(private_key_hex: str) -> str:
    """ Prefix + Private Key + Checksum """

    private_key_bytes = bytes.fromhex(private_key_hex)
    prefix = b'\x80'
    extended_key = prefix + private_key_bytes
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = base58.b58encode(extended_key + checksum)
    return wif.decode('utf-8')


def create_wif_compressed(private_key_hex: str) -> str:
    """ Prefix + Private Key + Compressed + Checksum """

    private_key_bytes = bytes.fromhex(private_key_hex)
    prefix = b'\x80'
    compressed = b'\x01'
    extended_key = prefix + private_key_bytes
    checksum = hashlib.sha256(hashlib.sha256(extended_key).digest()).digest()[:4]
    wif = base58.b58encode(extended_key + compressed + checksum)
    return wif.decode('utf-8')


def random():
    byte_value = os.urandom(ENTROPY_LENGTH)
    int_value = int.from_bytes(byte_value, byteorder='big')
    encoded_value = str(int_value).encode('utf-8')

    for i in range(LOOP_TIME):
        t = time.localtime()
        milliseconds = int(round(time.time() * 1000 % 1000))
        current_time = time.strftime("%H:%M:%S", t) + ":" + str(milliseconds)

        data = encoded_value + current_time.encode('utf-8')
        hash_obj = hashlib.sha256(data)
        hash_result = hash_obj.hexdigest()
        encoded_value = hash_result.encode('utf-8')

    return hash_result


def wif_to_public_key(wif_key: str) -> str:
    private_key = base58.b58decode(wif_key)[1:-4]
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    return '04' + verifying_key.to_string().hex()


def compress_public_key(public_key: str) -> str:
    if public_key[0:2] != '04':
        raise ValueError('Invalid Public Key')
    x = int(public_key[2:66], 16)
    # print("The coordinates of point X: %s length\n> %s\n" % (len(str(x)), x))

    y = int(public_key[66:], 16)
    # print("The coordinates of point Y: %s length\n> %s\n" % (len(str(y)), y))

    if (y % 2) == 0:
        public_key = '02' + format(x, '064x')
    else:
        public_key = '03' + format(x, '064x')
    return public_key


def line():
    print("---" * 30 + "\n")


def main():
    Entropy = random()

    # line()
    wif = create_wif(Entropy)
    wif_compress = create_wif_compressed(Entropy)
    pubkey = wif_to_public_key(wif)
    public_key = compress_public_key(pubkey)

    #private_key = base58.b58decode(wif_compress)[1:-4]
    #print("Private Key:\n> %s\n" % (private_key.hex()))


    line()
    print("Private Key: \n> %s\n" % Entropy)
    line()

    print("WIF Key:\n> %s\n" % (wif))
    print("Public Key:\n> %s\n" % (pubkey))
    line()

    print("[Compress] WIF Key:\n> %s\n" % (wif_compress))
    print("[Compress] Public Key:\n> %s\n" % (public_key))
    line()




if __name__ == "__main__":
    main()
