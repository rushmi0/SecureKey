import hashlib
import base58 # https://pypi.org/project/base58/
import ecdsa # https://pypi.org/project/ecdsa/
import os


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
    byte_value = os.urandom(64)
    int_value = int.from_bytes(byte_value, byteorder='big')
    str_value = str(int_value).encode('utf-8')

    '''
    ฟังก์ชัน random() สุ่มค่ามา 64 Bytes แปลงรูปลักษณ์เป็นเลขฐาน10 แล้วนำไป Hash ซ้ำๆ ด้วย Sha256 13000000 ครั้ง 
    เพื่อป้องกันการ Boost Force หา Private Key เจอง่าย ๆ ต้องใช้เวลาประมาณ 10วินาที ทำให้ยากที่จะเดา ต่อให้มีพลังการคำนวน
    สูงมากๆ แต่ๆ ความเป็นไปได้ของ Sha256 มันมหาศาล
    
    ค่า Hash สุดท้ายจะถูกส่งออกเป็น สตริงเลขฐาน16
    
    '''
    
    for i in range(13000000):
        hash_obj = hashlib.sha256(str_value)
        hash_result = hash_obj.hexdigest()
        str_value = hash_result.encode('utf-8')

    return  hash_result


def wif_to_public_key(wif_key: str) -> str:
    private_key = base58.b58decode(wif_key)[1:-4]
    signing_key = ecdsa.SigningKey.from_string(private_key, curve=ecdsa.SECP256k1)
    verifying_key = signing_key.get_verifying_key()
    return '04' + verifying_key.to_string().hex()


def compress_public_key(public_key: str) -> str:
    if public_key[0:2] != '04':
        raise ValueError('Invalid Public Key')
    x = int(public_key[2:66], 16)
    #print("The coordinates of point X: %s length\n> %s\n" % (len(str(x)), x))

    y = int(public_key[66:], 16)
    #print("The coordinates of point Y: %s length\n> %s\n" % (len(str(y)), y))

    if (y % 2) == 0:
        public_key = '02' + format(x, '064x')
    else:
        public_key = '03' + format(x, '064x')
    return public_key


def main():
    Entropy = random()

    wif = create_wif(Entropy)
    print("WIF Key: %s lengthn\n> %s\n" % (len(wif), wif))

    wif_compress = create_wif_compressed(Entropy)
    print("WIF Key [Compress]: %s length\n> %s\n" % (len(wif_compress), wif_compress))

    pubkey = wif_to_public_key(wif)
    print("Original Public Key: %s length\n> %s\n" % (len(pubkey), pubkey))

    private_key = base58.b58decode(wif_compress)[1:-4]
    print("Private Key: %s length\n> %s\n" % (len(private_key), private_key.hex()))

    public_key = compress_public_key(pubkey)
    print("Public Key [Compress]: %s length\n> %s" % (len(public_key), public_key))


if __name__ == "__main__":
    main()
