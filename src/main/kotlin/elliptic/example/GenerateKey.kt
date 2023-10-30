package elliptic.example


import elliptic.ECPublicKey.compressed
import elliptic.ECPublicKey.toPoint
import elliptic.ECPublicKey.toPublicKey
import java.math.BigInteger
import java.security.SecureRandom

fun main() {

    //val privateKey = BigInteger(256, SecureRandom())
    //val privateKey = BigInteger("7f7ff03d123792d6ac594bfa67bf6d0c0ab55b6b1fdb6249303fe861f1ccba9a", 16)
    val privateKey = BigInteger("b70bc5f36fed881ee37add82bd42875e6f0b4e2803c821777e6aa6cad8c7e094", 16)
    println("[H] Private key: ${privateKey.toString(16)}")
    println("Private key: $privateKey")

    // * สร้าง Public Key จาก Private Key โดยผลลัพธ์ที่ได้จะเป็นพิกัดจุดบนเส้นโค้งวงรี
    val curvePoint = privateKey.toPoint()
    println("\nKey Point: $curvePoint")

    // * แปลงจุดบนเส้นโค้งวงรีให้อยู่ในรูปแบบของ Public Key ผลลัพธ์ที่ได้จะเป็นค่า Hex ลักษณะที่ได้ขึ้นต้นด้วย "04" และมีขนาด Byte ทั้งหมด 65 bytes
    val publicKeyPoint = privateKey.toPublicKey()
    println("[U] Public Key: $publicKeyPoint")

    // * แปลงจุดบนเส้นโค้งวงรีให้อยู่ในรูปแบบของ Public Key ผลลัพธ์ที่ได้จะเป็นค่า Hex ลักษณะที่ได้ขึ้นต้นด้วย "02" หรือ "03" และมีขนาด Byte ทั้งหมด 33 bytes
    val compress = publicKeyPoint.compressed()
    println("[C] Public Key: $compress")

    // e4b2c64f0e4e54abb34d5624cd040e05ecc77f0c467cc46e2cc4d5be98abe3e3
}
