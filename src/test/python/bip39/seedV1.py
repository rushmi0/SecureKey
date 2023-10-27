import hashlib
import random


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
    entropy = bin(int.from_bytes(data, byteorder="big"))[2:]#.zfill(len(data) * 8)

    # convert hex to binary
    entropy_hash_bin = bin(int(entropy_hash, 16))[2:]

    # checksum
    checksum = entropy_hash_bin[: len(data) * 8 // 32]

    # checksum :: 01011100
    _checksum = entropy_hash_bin.zfill(256)#[: len(data) * 8 // 32]

    combine = entropy + checksum
    return combine, checksum


def main():
    #binary = ''.join([str(random.randint(0, 1)) for _ in range(128)])
    #binary = "10101000110101000100101111100100111000011110111000101010001000001100000010101101110100000010011110110001101101010001111111001110"
    binary = "1001110101101000110101110110101001110110000011000100010111110110101010110010100111000111010001100001010011010001001000000111011110011000111110011010000110000001101010001000111010111110111000110010101101000011010101101110110000001100011110001000000010100010"

    print(len(binary), binary)

    entropy_byte = binary_to_bytes(binary)
    seed = binary_mnemonic(entropy_byte)

    # แบ่งออกมาเป็น ชิ้นละ 11bit
    pieces = [seed[0][i:(i + 11)] for i in range(0, len(seed[0]), 11)]

    print(len(seed[0]), seed)
    print(pieces)

    numbers = [1, 2, 3, 4, 5]

    print([str(number).zfill(5) for number in numbers])


if __name__ == "__main__":
    main()