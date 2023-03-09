# การสร้าง WIF Private Key

**WIF** มาจากคำว่า **Wallet Import Format** เป็นรูปแบบมาตรฐาน **Private Key สำหรับ Bitcoin** เพราะด้วยรูปลักษณ์ Private Key เดิมๆ แล้วเป็นเลขฐาน16 ชุดหนึ่ง มันข้อนข้างดูยากมาก ๆ WIF Key จึงทำมาเพื่อให้รูปลักษณ์มันดูง่ายขึ้น ช่วยลดความผิดพลาดจากการกรอก Private Key ผิด


## ติดตั้ง Module สำหรับ Python
```sh
pip install base58
pip install ecdsa
```

```angular2html
python3

import base58
import ecdsa
exit()
```

## ถ้าทำตามด้านบนแล้วยังใช้ไม่ได้
โหลด File นั้นมาเลย แล้วแตก File จากนั้นเข้าไปข้างใน เราจะคัดลอก Module ไปที่ python3.10 library root
- สำหรับ **Ubuntu, Debian** 
```angular2html
sudo cp -r base58 /usr/bin/python3.10
sudo cp -r ecdsa /usr/bin/python3.10
```

## ขั้นตอนการสร้าง WIF Key
ทั้งหมดนี้ทำในรูปลักษณ์ Bytes



## 1. Prefix

ตัวเลขหน้าสุด ส่วนนี้เป็นตัวกำหนดว่า Private Key นี้ใช้สำหรับ Network อะไร

### Mainnet 
เป็นโครงข่ายที่ใช้งานจริง
- **Mainnet** ⟵ **0x80**

![Prefix 80](https://user-images.githubusercontent.com/120770468/223716525-bf57e5a4-0f43-4a28-9ae1-c2dca94dc857.png)

### Testnet
เป็นโครงข่ายที่ถูกใช้สำหรับการทดลองอะไรก็ตาม หรือทดลอง Protocol ใหม่ ๆ ก่อนที่จะนำไปใช้งานจริง เพื่อไม่ให้เกิดความเสียหายในการใช้งานจริง (การใช้งานไม่มีค่าใช้จ่าย) 

- **Testnet** ⟵ **0xEF**

![Prefix EF](https://user-images.githubusercontent.com/120770468/223721619-fc7db06d-21b5-4439-8568-63219fe248d4.png)

## 2. Private Key 
สร้าง Private Key โดยนำค่าสุ่มไป Hash ด้วย [SHA256](https://emn178.github.io/online-tools/sha256.html)

### **ผลลัพธ์ SHA256 Hash**
```sh
f845e3161183529214554ce0a746ed6326b2c02d40a72fae692206d40ebdaf86
```

![Entropy](https://user-images.githubusercontent.com/120770468/223761504-3afb9649-6304-4a87-bfd2-9bc3e311ddaf.png)

### **ผลลัพธ์ SHA256 รูปลักษณ์ Bytes ในภาษา Python**
```angular2html
b'\xf8E\xe3\x16\x11\x83R\x92\x14UL\xe0\xa7F\xedc&\xb2\xc0-@\xa7/\xaei"\x06\xd4\x0e\xbd\xaf\x86'
```

## 3. Compression (optional)
เป็นตัวกำหนดว่า Private Key นี้ใช้สำหรับสร้าง Public Key แบบบีบอัด ส่วนนี้เป็นตัวเลือกครับ จะใช้หรือไม่ใช้ก็ได้ ไม่บังคับ
- **Compressed** ⟵ 0x01

![Compression](https://user-images.githubusercontent.com/120770468/223742705-428d9c67-8318-4fb9-8d16-ec00287037e3.png)


## 4. Checksum
นำค่า **Prefix + Private Key** มาต่อกัน **(เน้นย้ำว่าทำใน รูปลักษณ์ Bytes)** จากนั้นนำไปเข้า SHA256 Hash. นำผลลัพธ์ที่ได้ตัดเอาเฉพาะ 4 Bytes แรกมันคือค่า Checksum

ตัวอย่างนี้ เป็นรูปลักษณ์ Bytes จากภาษา Python ใช้เป็นเลขฐาน16 ขั้นตัวเลขด้วย **\x**

### นำ **Prefix** มาต่อกับ **Private Key**
```angular2html
b'\x80\xf8E\xe3\x16\x11\x83R\x92\x14UL\xe0\xa7F\xedc&\xb2\xc0-@\xa7/\xaei"\x06\xd4\x0e\xbd\xaf\x86'
```

![concatenate](https://user-images.githubusercontent.com/120770468/223755565-209589fb-6ecb-43a4-b956-30d8aa0120ee.png)

### **[Prefix + Private Key]** หลังจากเชื่อมต่อกันแล้วนำไป Hash ด้วย **[SHA256]**
```angular2html
b'\xf3\xc9\xd8\x10\xc2\xd9<J\x13\xc4D\xf1f\xc0\xac\xf4\xd0\xdf\x08\x92#\x141\x11\x82\x85\xd6\x8c\xb3\xc6\xca#'
```

![Hash](https://user-images.githubusercontent.com/120770468/223757335-b85070da-93a8-4906-884e-bc26e9c49aa4.png)

### หา **Checksum** โดยนำผลลัพธ์ที่ได้ตัดเอามาเฉพาะ 4 Bytes แรก
```angular2html
b'\xf3\xc9\xd8\x10'
```

![Checksum](https://user-images.githubusercontent.com/120770468/223770066-744054be-6a1e-46f2-b663-a607d6aec098.png)

## 5. Base58 Encode
สุดท้ายนี้นำค่าทั้งหมดมาเชื่อมต่อกันตามลำดับ **(รูปลักษณ์ Bytes)** แล้วนำมาเข้ารหัสด้วย Base58. การเข้ารหัสนี้ไม่ได้ทำเพื่อความปลอดภัย เพียงแต่ทำให้รูปแบบมันดูง่ายขึ้น ลดความผิดพลาดจากการ กรอกผิดหรือจำสับสน

- **Base58** (**Prefix** + **Private Key** + **Checksum**)
```angular2html
5KhdP7F1FpTDEa7LYtaMxJA6LjUBPXCdWFqkv1b5pDqTFkFWi7h
```

![version 1](https://user-images.githubusercontent.com/120770468/223781588-21b7cfa5-bc57-4c22-aa38-feb3e80a1f03.png)



- **Base58** (**Prefix** + **Private Key** + **Compressed** + **Checksum**)
```angular2html
L5YKaaYp8QSgzu8yHkeFV4j8a6SxrQJL88WCpybSFRersccZgJqM
```

![version 2](https://user-images.githubusercontent.com/120770468/223783386-3c19ec13-9f52-4782-b259-120350caef51.png)
