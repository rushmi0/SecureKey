# การสร้าง WIF Private Key

**WIF** มาจากคำว่า **Wallet Import Format** เป็นรูปแบบมาตรฐาน **Private Key สำหรับ Bitcoin** เพราะด้วยรูปลักษณ์ Private Key เดิมๆ แล้วเป็นเลขฐาน16 ชุดหนึ่ง มันข้อนข้างดูยากมาก ๆ WIF Key จึงทำมาเพื่อให้รูปลักษณ์มันดูง่ายขึ้น ช่วยลดความผิดพลาดจากการกรอก Private Key ผิด


## ขั้นตอนการสร้าง WIF Key
ทั้งหมดนี้ทำในรูปลักษณ์ Bytes


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


## 1. Prefix

เป็นตัวกำหนดว่า Private Key นี้ใช้สำหรับ Network อะไร
- **Mainnet** ⟵ **0x80**
- **Testnet** ⟵ **0xEF**

## 2. Private Key 
นำค่าสุ่มมาชุดหนึ่งไป Hash ด้วย SHA256

- **ผลลัพธ์ SHA256 Hash**
```sh
c51a52e294165cfde3342e8c12c5f3370d29d12401c03803fe34de78c80b1804
```

- **Bytes**
```angular2html
b'\xc5\x1aR\xe2\x94\x16\\\xfd\xe34.\x8c\x12\xc5\xf37\r)\xd1$\x01\xc08\x03\xfe4\xdex\xc8\x0b\x18\x04'
```

## 3. Compression (optional)
เป็นตัวกำหนดว่า Private Key นี้ใช้สำหรับสร้าง Public Key แบบบีบอัด ส่วนนี้เป็นตัวเลือกครับ จะใช้หรือไม่ใช้ก็ได้ ไม่บังคับ
- **Compressed** ⟵ 0x01

## 4. Checksum
นำค่า **Prefix + Private Key** มาต่อกัน **(เน้นย้ำว่าทำใน รูปลักษณ์ Bytes)** จากนั้นนำไปเข้า SHA256 Hash. นำผลลัพธ์ที่ได้ตัดเอาเฉพาะ 4 Bytes แรกมันคือค่า Checksum

ตัวอย่างนี้ เป็นรูปลักษณ์ Bytes จากภาษา Python ใช้เป็นเลขฐาน16 ขั้นตัวเลขด้วย **\x**

- **Prefix** (Mainnet)
```angular2html
b'\x80'
```

- **Private Key**
```angular2html
b'\xc5\x1aR\xe2\x94\x16\\\xfd\xe34.\x8c\x12\xc5\xf37\r)\xd1$\x01\xc08\x03\xfe4\xdex\xc8\x0b\x18\x04'
```

- **Prefix + Private Key**
```angular2html
b'\x80\xc5\x1aR\xe2\x94\x16\\\xfd\xe34.\x8c\x12\xc5\xf37\r)\xd1$\x01\xc08\x03\xfe4\xdex\xc8\x0b\x18\x04'
```

- **[Prefix + Private Key]** ⟶ **[SHA256]**
```angular2html
b'\x03\xb3\x11{\xaa+Qa\x8e\x14\x98\xab\xfd\x98\xdd\xc4\x92n\xaa\xaa\x8d\x8d\x01\nH1\xa1<\xe3\xdb\x1e\xbd'
```

- **[SHA256]** ⟶ **[First 4 Bytes]** ⟶ **Checksum**
```angular2html
b'\x03\xb3\x11{'
```

## 5. Base58 Encode
สุดท้ายนี้นำค่าทั้งหมดมาต่อกันตามลำดับ **(รูปลักษณ์ Bytes)** แล้วเข้ารหัสด้วย Base58. การเข้ารหัสนี้ไม่ได้ทำเพื่อความปลอดภัย เพียงแต่ทำให้มันดูง่าย ลดความผิดพลาดต่าง ๆ

- **Base58**(**Prefix** + **Private Key** + **Checksum**)
```angular2html
5KK6JrgvjhCttVbJ7NzohxQJkYzRpff9d5spV7JRJ3QoYd1A2pA
```

![Frame 10](https://user-images.githubusercontent.com/120770468/223154670-7b5fa3ce-b2fd-479b-833f-6a3b2b967b5f.png)

##

- **Base58**(**Prefix** + **Private Key** + **Compressed** + **Checksum**)
```angular2html
L3prRpKEBSTW2HCNXA699mXsMECUZPdP4GXJb4otEDe4SZc7ooEa
```

![Frame 11](https://user-images.githubusercontent.com/120770468/223154981-78f2860f-fc3e-4de4-94d7-b723d0eceb19.png)
