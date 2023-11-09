package elliptic


import elliptic.ECPublicKey.verifyPoint
import elliptic.EllipticCurve.P
import elliptic.EllipticCurve.A
import elliptic.EllipticCurve.B
import elliptic.EllipticCurve.multiplyPoint
import elliptic.Signature.Schnorr.hasEvenY

import util.ShiftTo.ByteArrayToBigInteger
import util.ShiftTo.ByteArrayToHex
import util.ShiftTo.HexToByteArray

import java.math.BigInteger

object ECPublicKey {


    /*
    * ปรับแต่ง Public key
    * */


    /*
    * `isPointOnCurve` Method นี้ใช้เพื่อตรวจสอบว่าจุดที่รับเข้ามานั้นอยู่บนเส้นโค้งวงรีหรือไม่
    * โดยการรับค่า point เพื่อนำไปคำนวณตามสมการเส้นโค้งวงรี และตรวจสอบว่าสมการที่ได้มีค่าเท่ากันหรือไม่ และจะคืนค่าเป็น true หากสมการมีค่าเท่ากัน
    * */
    fun isPointOnCurve(point: PointField?): Boolean {
        val (x, y) = point
        // ! ถ้าค่า point ที่รับเข้ามาเป็น null ให้ส่งค่า Exception กลับไป
            ?: throw IllegalArgumentException("`isPointOnCurve` Method Point is null")

        // * ตรวจสอบว่าจุดนั้นเป็นไปตามสมการเส้นโค้งวงรี หรือไม่: y^2 = x^3 + Ax + B (mod P)
        val leftSide = (y * y) % P // leftSide เป็นค่า y^2 และรนำไป mod P
        val rightSide = (x.pow(3) + A * x + B) % P // rightSide เป็นค่า x^3 + Ax + B และรนำไป mod P

        return leftSide == rightSide
    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


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


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    // รับค่า private key และคืนค่า public key ในรูปแบบพิกัดบนเส้นโค้งวงรี พิกัด x และ y จะเป็นค่า BigInteger เลขฐาน 10
    private fun generatePoint(k: BigInteger): PointField {
        // คำนวณค่าพิกัดบนเส้นโค้งวงรีจาก private key
        val point = multiplyPoint(k)

        // ตรวจสอบว่าจุดที่ได้มานั้นอยู่บนเส้นโค้งวงรีหรือไม่
        if (!isPointOnCurve(point)) {
            throw IllegalArgumentException("Invalid private key")
        }

        // คืนค่าพิกัดบนเส้นโค้งวงรี
        return point
    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    private fun fullPublicKeyPoint(k: BigInteger): String {
        try {
            val point: PointField = multiplyPoint(k)
            val xHex: String = point.x.toString(16)
            val yHex: String = point.y.toString(16)

            val xSize: Int = xHex.HexToByteArray().size //xHex.length
            val ySize: Int = yHex.HexToByteArray().size//yHex.length

            val max = maxOf(xSize, ySize)

            when {
                xSize != max -> {
                    val padding: String = "0".repeat(max - xSize)
                    return "04$padding$xHex$yHex"
                }
                ySize != max -> {
                    val padding: String = "0".repeat(max - ySize)
                    return "04$xHex$padding$yHex"
                }
            }
            return "04$xHex$yHex"
        } catch (e: IllegalArgumentException) {
            println("Invalid private key: ${e.message}")
            return null.toString()
        } catch (e: Exception) {
            println("Failed to generate the public key: ${e.message}")
            return null.toString()
        }
    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    private fun groupSelection(publicKey: String): String {


        val keyByteArray = publicKey.HexToByteArray().copyOfRange(1, publicKey.HexToByteArray().size)

        // วัดขนาด `keyByteArray` แลพหารด้วย 2 เพื่อแบ่งครึ่ง
        val middle = keyByteArray.size / 2

        // แบ่งครึ่งข้อมูล `keyByteArray` ออกเป็น 2 ส่วน
        val xOnly = keyByteArray.copyOfRange(0, middle).ByteArrayToHex()
        val yOnly = keyByteArray.copyOfRange(middle, keyByteArray.size).ByteArrayToHex()

        // ทำการแยกพิกัด x ออกมาจาก public key รูปแบบเต็ม
        val x = BigInteger(xOnly, 16)

        // ทำการแยกพิกัด y ออกมาจาก public key รูปแบบเต็ม
        val y = BigInteger(yOnly, 16)

        // ตรวจสอบว่า y เป็นเลขคู่หรือไม่ เพื่อเลือก group key ที่เหมาะสมเนื่องจากมี 2 กลุ่ม
        return if (y and BigInteger.ONE == BigInteger.ZERO) {
            "02" + x.toString(16).padStart(middle * 2, '0')
        } else {
            "03" + x.toString(16).padStart(middle * 2, '0')
        }
    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    /**
     * < pseudocode >
     *  Fail if x ≥ p.
     *  Let c = x3 + 7 mod p.
     *  Let y = c(p+1)/4 mod p.
     *  Fail if c ≠ y2 mod p.
     * Return the unique point P such that x(P) = x and y(P) = y if y mod 2 = 0 or y(P) = p-y otherwise.
     * */
    fun BigInteger.evaluatePoint(): PointField {
        require(this < P) { "The public key must be less than the field size." }

        val c = (this.pow(3) + B) % P

        val y = c.modPow((P + 1.toBigInteger()) / 4.toBigInteger(), P)

        return PointField(
            this,
            if (y.hasEvenY()) y else P - y
        )
    }


    private fun publicKeyGroup(xGroupOnly: String): PointField {

        val byteArray = xGroupOnly.HexToByteArray()
        val xCoord = byteArray.copyOfRange(1, byteArray.size).ByteArrayToBigInteger()
        val isYEven = byteArray[0] == 2.toByte()

        val xCubed = xCoord.modPow(BigInteger.valueOf(3), P)
        val Ax = xCoord.multiply(A).mod(P)
        val ySquared = xCubed.add(Ax).add(B).mod(P)

        val y = ySquared.modPow(P.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), P)
        val isYSquareEven = y.mod(BigInteger.TWO) == BigInteger.ZERO
        val computedY = if (isYSquareEven != isYEven) P.subtract(y) else y

        return PointField(xCoord, computedY)
    }




    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    // `keyRecovery` ใช้สำหรับแปรง Public Key Hex ให้อยู่ในรูปแบบของ พิกัดบนเส้นโค้งวงรี (x, y)
    fun String.pointRecovery(): PointField {

        //val record = this.HexToByteArray().size

        //val receive = this.HexToByteArray()

        return when (this.HexToByteArray().size) {
            33 -> {
                publicKeyGroup(this)
            }

            32 -> {
                BigInteger(this, 16).evaluatePoint()
            }

            else -> {
                // แจ้งข้อผิดพลาดเมื่อขนาดของ public key ไม่ถูกต้อง
                throw IllegalArgumentException("Invalid public key")
            }
        }

    }


    fun BigInteger.toPublicKey(): String {
        return fullPublicKeyPoint(this)
    }

    // `compressed` ใช้สำหรับแปรง Public Key Hex
    fun String.compressed(): String {
        return groupSelection(this)
    }

    // `toPoint` ใช้สำหรับแปรง Private Key รูปแบบเลขฐาน 10 ให้อยู่ในรูปแบบของ พิดกัดบนเส้นโค้งวงรี (x, y)
    fun BigInteger.toPoint(): PointField {
        return generatePoint(this)
    }

    // `verifyPoint` ใช้ในกรณีที่ต้องการตรวจสอบว่าจุดบนเส้นโค้งวงรีนั้นอยู่บนเส้นโค้งวงรีหรือไม่
    fun PointField.verifyPoint(): Boolean {
        return isPointOnCurve(this)
    }

}

/*
fun main() {


    val x = BigInteger("54937464590658530654488624268151724241105264383655924818230768164485909069475")
    val p = BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663")

    // หาค่า y จาก x โดยใช้สมการของเส้นโค้ง secp256k1
    val ySquared = (x.pow(3) + B) % p

    // หาค่า y โดยใช้ modular square root
    val y = ySquared.modPow((p + 1.toBigInteger()) / 4.toBigInteger(), p)

    // หาค่า y ที่สอดคล้องกับ x
    if (y.modPow(2.toBigInteger(), p) == ySquared) {
        println("ค่า y ที่สอดคล้องกับ x คือ: $y")
    } else {
        println("ไม่มีค่า y ที่สอดคล้องกับ x ใน secp256k1")
    }

    val point = PointField(x, y)
    val verifyY = point.verifyPoint()
    println(verifyY)


}*/