# การสร้าง Private Key, Public key

1. สร้าง Private Key :: เริ่มจากสุ่มตัวเลขมาชุดหนึ่งแล้วนำไป Hash ด้วย SHA256

[Private Key] -> a0ba26949cc38720bb9d3d7553bc6705163a0fa3df5600f86e26b6806beccd79

2. สร้าง WIF Key ::  WIF Key มาจากคำว่า Wallet Import Format, ทำเพื่อแปลง Private Key ให้เป็นรูปลักษณ์มันดูง่ายขึ้น.
WIF Key นั้นประกอบไปด้วย prefix + [Private Key] + Compressed + Checksum

0x80 = สำหรับใช้งานใน mainnet, 0xef = สำหรับใช้งานใน testnet

[WIF Key] -> 5K35988eqKa5THSqNMSJTy7ubMcWwNRMyiKPsycdBhcTf2Gu28y


อ้างอิง:
https://learnmeabitcoin.com/technical/wif
