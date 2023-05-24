import os
import random
import hashlib

from mnemonic import Mnemonic


def binary_to_bytes(s):
    v = int(s, 2)
    b = bytearray()
    while v:
        b.append(v & 0xff)
        v >>= 8
    return bytes(b[::-1])

def binary_mnemonic(data: bytes) -> str:
    # decimal = int(data.hex(), 16)
    # original_entropy = bin(decimal)[2:].zfill(len(data.hex()) * 4)
    entropy_hash = hashlib.sha256(data).hexdigest()

    # convert bytes to binary
    entropy = bin(int.from_bytes(data, byteorder="big"))[2:].zfill(len(data) * 8)

    # convert hex to binary
    entropy_hash_bin = bin(int(entropy_hash, 16))[2:]

    # checksum
    checksum = entropy_hash_bin.zfill(256)[: len(data) * 8 // 32]

    combine = entropy + checksum
    return combine, checksum

def get_path(file) -> str:
    return os.path.join(os.path.dirname(__file__), file)

def get_mnemonic(Seed: str) -> str:
    pieces = [Seed[0][i:(i + 11)] for i in range(0, len(Seed[0]), 11)]
    mnemonic = []
    index = []

    with open(get_path("english.txt")) as path:
        wordlist = path.readlines()

    for piece in pieces:
        i = int(piece, 2)
        index.append(i)
        word = wordlist[i].strip()
        mnemonic.append(word)
        #word1 = wordlist[i].strip("\n,")
        print(f"{piece} \t {i:4} +1  \t {word}")

    return " ".join(mnemonic)


def mnemonic_to_seed_binary(word) -> str:
    seed = Mnemonic("english").to_seed(word)
    hex_seed = seed.hex()
    decimal_seed = int(hex_seed, 16)

    original_entropy = bin(decimal_seed)[2:].zfill(len(hex_seed) * 4)
    pieces = [original_entropy[i:(i + 11)] for i in range(0, len(original_entropy), 11)]

    print(len(original_entropy))
    return pieces

def main():
    binary = ''.join([str(random.randint(0, 1)) for _ in range(128)])
    entropy = binary_to_bytes(binary)

    seed = binary_mnemonic(entropy)
    mnemonic = get_mnemonic(seed)

    index = mnemonic.split(" ")

    #print("Entropy [%s]\n> %s" % (len(binary), binary))
    #print("Checksum [%s]\n> %s" % (len(Seed[1]), Seed[1]))
    #print("Seed [%s]\n> %s" % (len(Seed[0]), Seed[0]))
    print("\nMnemonic Word [%s]\n> %s" % (len(index), mnemonic))

if __name__ == "__main__":
    main()
