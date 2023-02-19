import hashlib
import os

ENTROPY_LENGTH = 64        #  ปรับแก้จำนวน Bytes ตามต้องการ
LIMIT = 62000000           #  50วินาที

def random():
    byte_value = os.urandom(ENTROPY_LENGTH)
    int_value = int.from_bytes(byte_value, byteorder='big')
    encoded_value = str(int_value).encode('utf-8')

    for i in range(LIMIT):
        hash_obj = hashlib.sha256(encoded_value)
        hash_result = hash_obj.hexdigest()
        encoded_value = hash_result.encode('utf-8')
    return  hash_result


def main():
    Entropy = random()
    print("Private Key: \n> %s\n"%Entropy)


if __name__ == "__main__":
    main()