package elliptic.Signature


import elliptic.EllipticCurve.addPoint
import elliptic.EllipticCurve.modinv
import elliptic.EllipticCurve.multiplyPoint
import elliptic.PointField
import elliptic.Secp256K1
import java.math.BigInteger
import java.security.SecureRandom

/*
* สร้างลายเซ็นและตรวจสอบ ECDSA
* */

object ECDSA {

    /*
    * https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
    */

    // * Parameters secp256k1
    private val curveDomain: Secp256K1.CurveParams = Secp256K1.getCurveParams()
    private val N: BigInteger = curveDomain.N

    fun sign(privateKey: BigInteger, message: BigInteger): Pair<BigInteger, BigInteger> {
        val m = message
        //val k = BigInteger("42854675228720239947134362876390869888553449708741430898694136287991817016610")
        val k = BigInteger(256, SecureRandom())

        val point: PointField = multiplyPoint(k)
        val kInv: BigInteger = modinv(k, N)

        val r: BigInteger = point.x % N
        var s: BigInteger = ((m + r * privateKey) * kInv) % N

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

    // * https://github.com/bitcoin/bips/blob/master/bip-0066.mediawiki
    // เมธอดสำหรับแปลงลายเซ็นให้อยู่ในรูปของ DER format
    // โดยรับคู่ของ BigInteger ที่แทนลายเซ็น (r, s) เป็น input
    fun toDERencode(signature: Pair<BigInteger, BigInteger>): String {
        // แยกค่า r และ s จากคู่ของ BigInteger
        val (r, s) = signature

        // แปลงค่า r และ s ให้อยู่ในรูปของ bytes
        val rb = r.toByteArray()
        val sb = s.toByteArray()

        // สร้าง bytes สำหรับเก็บค่า r ในรูปแบบ DER
        val der_r = byteArrayOf(0x02.toByte()) + rb.size.toByte() + rb

        // สร้าง bytes สำหรับเก็บค่า s ในรูปแบบ DER
        val der_s = byteArrayOf(0x02.toByte()) + sb.size.toByte() + sb

        // สร้าง bytes สำหรับเก็บลายเซ็นในรูปแบบ DER ที่รวมค่า r และ s
        val der_sig = byteArrayOf(0x30.toByte()) + (der_r.size + der_s.size).toByte() + der_r + der_s

        // แปลง bytes ในรูปของ DER ให้อยู่ในรูปของ hexadecimal string
        return der_sig.joinToString("") { "%02x".format(it) }
    }



    // เมธอดสำหรับถอดรหัสลายเซ็นในรูปของ DER
    // และคืนค่าเป็นคู่ของ BigInteger (r, s)
    fun derRecovered(derSignature: String): Pair<BigInteger, BigInteger>? {
        try {
            // แปลงรหัสลายเซ็นในรูปของ DER จากฐาน 16 เป็น bytes
            val derBytes = derSignature.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

            // ตรวจสอบความถูกต้องของรูปแบบ DER
            if (derBytes.size < 8 || derBytes[0] != 0x30.toByte() || derBytes[2] != 0x02.toByte()) {
                println("รูปแบบ DER ไม่ถูกต้อง")
                return null
            }

            // คำนวณความยาวของ r และ s
            val lenR = derBytes[3].toInt()
            val lenS = derBytes[lenR + 5].toInt()

            // ดึง bytes ที่เกี่ยวข้องกับ r และ s
            val rBytes = derBytes.copyOfRange(4, 4 + lenR)
            val sBytes = derBytes.copyOfRange(6 + lenR, 6 + lenR + lenS)

            // แปลง bytes เป็น BigInteger โดยไม่เอาเครื่องหมายลบ (positive)
            val r = BigInteger(1, rBytes)
            val s = BigInteger(1, sBytes)

            return Pair(r, s)
        } catch (e: Exception) {
            println("ไม่สามารถถอดรหัสลายเซ็น: ${e.message}")
            return null
        }
    }

}