# WIF Private Key

WIF มาจากคำว่า Wallet Import Format เป็นรูปแบบมาตรฐาน Private Key สำหรับ Bitcoin เพราะด้วยรูปลักษณ์ Private Key เดิมๆ แล้วเป็นเลขฐาน16 จุดหนึ่ง มันข้อนข้างยากดูยากมาก ๆ WIF Key จึงทำมาเพื่อให้รูปลักษณ์มันดูง่าย ขึ้น ช่วยลดความผิดพลาดจากการกรอก Private Key ผิด


## ส่วนประกอบและขั้นตอนการสร้าง WIF Key

1. Prefix เป็นตัวกำหนดว่า Private Key นี้ใช้สำหรับ Network อะไร
- Mainnet = 0x80
- Testnet = 0xEF


