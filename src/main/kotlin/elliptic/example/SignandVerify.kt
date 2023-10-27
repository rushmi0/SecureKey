package elliptic.example

import elliptic.EllipticCurve.multiplyPoint
import elliptic.PointField
import elliptic.Signature.ECDSA
import elliptic.Signature.ECDSA.derRecovered
import elliptic.Signature.ECDSA.toDERencode
import util.ShiftTo.ByteArrayToHex
import java.math.BigInteger
import java.security.MessageDigest

fun main() {

    //val privateKey = BigInteger(256, SecureRandom())
    val privateKey = BigInteger("97ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a", 16)

    // * สร้าง Public Key จาก Private Key โดยผลลัพธ์ที่ได้จะเป็นพิกัดจุดบนเส้นโค้งวงรี
    val curvePoint: PointField = multiplyPoint(privateKey)
    println("\nKey PointField: $curvePoint")

    // * ข้อความที่จะลงนาม
    val message = "Hello World"
    println("Message: $message")

    // * นำข้อความที่จะลงนามไปทำการ Hash โดยใช้ฟังก์ชัน SHA-256
    val digest = MessageDigest.getInstance("SHA-256")
    val hash = digest.digest(message.toByteArray()).ByteArrayToHex()

    // แปลงค่า Hash ให้อยู่ในรูปของ BigInteger เลขฐาน 10
    val hashInt = BigInteger(hash, 16)

    // * ลงนามข้อความ
    val signature: Pair<BigInteger, BigInteger> = ECDSA.sign(privateKey, hashInt)
    println("Signature: $signature")


    // * ตัวอย่างขั้นตอนการตรวจสอบลายเซ็น
    val publicKeyPoint: PointField = multiplyPoint(privateKey)

    // * แปลงลายเซ็นให้อยู่ในรูปของ DER format โดยผลลัพธ์ที่ได้จะเป็นค่า Hex ที่มีขนาด 64 bytes เหตุผลที่ต้องแปลงเป็นรูปแบบนี้เนื่องจากเราจะนำไปใช้กับฟังก์ชัน VerifySignature ที่เขียนขึ้นมา
    val der: String = toDERencode(signature)
    println("Der format: $der")

    // * นำลายเซ็นที่อยู่ในรูปของ DER format มาทำการ Recover ค่า r และ s ออกมา
    val signatureRecovered: Pair<BigInteger, BigInteger>? = derRecovered(der)
    val r: BigInteger? = signatureRecovered?.first
    val s: BigInteger? = signatureRecovered?.second
    println("Signature Recovered: \n\tr = $r \n\ts = $s")

    // * ตรวจสอบลายเซ็น
    val verify: Boolean = ECDSA.verify(publicKeyPoint, hashInt, signature)
    println("Verify: $verify")



}