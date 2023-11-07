package elliptic.example.signature


import elliptic.ECPublicKey.compressed
import elliptic.ECPublicKey.pointRecovery
import elliptic.ECPublicKey.toPoint
import elliptic.ECPublicKey.toPublicKey
import elliptic.EllipticCurve.addPoint
import elliptic.EllipticCurve.modinv
import elliptic.EllipticCurve.multiplyPoint
import elliptic.PointField
import elliptic.Secp256K1
import elliptic.Signature.ECDSA

import util.ShiftTo.ByteArrayToHex
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom

object TestECDSA {


    /*
    * https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
    */

    // * Parameters secp256k1
    private val curveDomain: Secp256K1.CurveParams = Secp256K1.getCurveParams()
    private val N: BigInteger = curveDomain.N

    // * สร้างลายเซ็น โดยรับค่า private key และ message ที่ต้องการลงลายเซ็น และคืนค่าเป็นคู่ของ BigInteger (r, s)
    fun sign(
        privateKey: BigInteger,
        message: BigInteger
    ): Pair<BigInteger, BigInteger> {
        val m = message
        //val k = BigInteger("42854675228720239947134362876390869888553449708741430898694136287991817016610")

        val k = BigInteger(256, SecureRandom())

        val point: PointField = multiplyPoint(k)

        val kInv: BigInteger = modinv(k, N)

        val r: BigInteger = point.x % N

        var s = (m + r * privateKey) * kInv % N
        // var s: BigInteger = ((m + r * privateKey) * kInv) % N

        // * https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
        if (s > N.shiftRight(1)) {
            s = N - s
        }

        return Pair(r, s)
    }

    fun verify(
        publicKeyPoint: PointField,
        message: BigInteger,
        signature: Pair<BigInteger, BigInteger>
    ): Boolean {
        val (r, s) = signature

        val w = modinv(s, N)
        val u1 = (message * w) % N
        val u2 = (r * w) % N

        val point1 = multiplyPoint(u1)
        val point2 = multiplyPoint(u2, publicKeyPoint)

        val point = addPoint(point1, point2)

        val x = point.x % N

        return x == r
    }


}


fun main() {

    //val privateKey = BigInteger(256, SecureRandom())
    //val privateKey = BigInteger("97ddae0f3a25b92268175400149d65d6887b9cefaf28ea2c078e05cdc15a3c0a", 16)
    val privateKey = BigInteger("25fc758699f0d46d177764f79ddd8d76256f0204299a3c5da88f5d12e61ba9c7", 16)

//    val message = BigInteger("Hello World".SHA256().ByteArrayToHex(), 16)
//
//    val xValue: String = privateKey.toPublicKey().compressed()
//
//    val original = xValue.pointRecovery()!!
//
//    val signature: Pair<BigInteger, BigInteger> = TestECDSA.sign(privateKey, message)
//
//    val verify1: Boolean = TestECDSA.verify(original, message, signature)
//
//    println("Private Key hex ${privateKey.toByteArray().size} bytes: \n${privateKey.DeciToHex().splitHexData()}")
//    println("signature: \n s : ${signature.first.DeciToHex()} ${signature.first.toByteArray().size} Bytes \n r : ${signature.second.DeciToHex()} ${signature.second.toByteArray().size} Bytes")
//    println("verify: $verify1")


    val curvePoint: PointField = privateKey.toPoint()
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
    val publicKeyPointl: PointField = multiplyPoint(privateKey)
    println(publicKeyPointl)



    val publicKeyPoint = privateKey.toPublicKey().compressed().pointRecovery()
    println(publicKeyPoint)

    // * ตรวจสอบลายเซ็น
    val verify: Boolean = TestECDSA.verify(publicKeyPoint, hashInt, signature)
    println("Verify: $verify")


}