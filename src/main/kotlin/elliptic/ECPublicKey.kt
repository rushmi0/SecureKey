package elliptic

import elliptic.ECPublicKey.toPublicKey
import elliptic.ECPublicKey.verifyPoint
import elliptic.EllipticCurve.P
import elliptic.EllipticCurve.A
import elliptic.EllipticCurve.B
import elliptic.EllipticCurve.multiplyPoint

import util.ShiftTo.ByteArrayToBigInteger
import util.ShiftTo.ByteArrayToHex
import util.ShiftTo.HexToByteArray

import java.math.BigInteger
import java.security.SecureRandom

object ECPublicKey {


    /*
    * ปรับแต่ง Public key
    * */


    /*
    * `isPointOnCurve` Method นี้ใช้เพื่อตรวจสอบว่าจุดที่รับเข้ามานั้นอยู่บนเส้นโค้งวงรีหรือไม่
    * โดยการรับค่า point เพื่อนำไปคำนวณตามสมการเส้นโค้งวงรี และตรวจสอบว่าสมการที่ได้มีค่าเท่ากันหรือไม่ และจะคืนค่าเป็น true หากสมการมีค่าเท่ากัน
    * */
    private fun isPointOnCurve(point: PointField?): Boolean {
        val (x, y) = point
        // ! ถ้าค่า point ที่รับเข้ามาเป็น null ให้ส่งค่า Exception กลับไป
            ?: throw IllegalArgumentException("`isPointOnCurve` Method Point is null")

        // * ตรวจสอบว่าจุดนั้นเป็นไปตามสมการเส้นโค้งวงรี หรือไม่: y^2 = x^3 + Ax + B (mod P)
        val leftSide = (y * y) % P // leftSide เป็นค่า y^2 และรนำไป mod P
        val rightSide = (x.pow(3) + A * x + B) % P // rightSide เป็นค่า x^3 + Ax + B และรนำไป mod P

        return leftSide == rightSide
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


    private fun decompressPublicKeyGroup(xGroupOnly: String): PointField? {
        try {

            // แปลง compressed public key ในรูปแบบ Hex เป็น ByteArray
            val xOnlyByteArray: ByteArray = xGroupOnly.HexToByteArray()

            // ดึงค่า x coordinate จาก ByteArray
            val xCoord: BigInteger = xOnlyByteArray.copyOfRange(1, xOnlyByteArray.size).ByteArrayToBigInteger()

            val xSize = xOnlyByteArray.copyOfRange(1, xOnlyByteArray.size).size

            when {

                xOnlyByteArray.size -1 == xSize && (xOnlyByteArray[0] == 2.toByte() || xOnlyByteArray[0] == 3.toByte()) -> {

                    // ตรวจสอบว่า y เป็นเลขคู่หรือไม่
                    val isYEven: Boolean = xOnlyByteArray[0] == 2.toByte()

                    // คำนวณค่า x^3 (mod P)
                    val xCubed: BigInteger = xCoord.modPow(BigInteger.valueOf(3), P)

                    // คำนวณ Ax (mod P)
                    val Ax: BigInteger = xCoord.multiply(A) % P

                    // คำนวณ y^2 = x^3 + Ax + B (mod P)
                    val ySquared: BigInteger = xCubed.add(Ax).add(B) % P

                    // คำนวณค่า y จาก y^2 โดยใช้ square root
                    val y: BigInteger = ySquared.modPow(
                        P.add(BigInteger.ONE).divide(BigInteger.valueOf(4)),  // (P + 1) / 4
                        P // mod P
                    )

                    // ตรวจสอบว่า y^2 เป็นเลขคู่หรือไม่
                    val isYSquareEven: Boolean = y.mod(BigInteger("2")) == BigInteger.ZERO

                    // คำนวณค่า y โดยแก้ไขเครื่องหมายตามผลลัพธ์ที่ได้จากการตรวจสอบ
                    val computedY: BigInteger = if (isYSquareEven != isYEven) P.subtract(y) else y

                    // สร้าง PointField จาก x และ y ที่ได้
                    return PointField(xCoord, computedY)
                }
                
                
            }



        } catch (e: IllegalArgumentException) {
            println("Invalid public key: ${e.message}")
            return null
        } catch (e: Exception) {
            println("Failed to decompress the public key: ${e.message}")
            return null
        }

        return null
    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\

    // Extension Function


    // `keyRecovery` ใช้สำหรับแปรง Public Key Hex ให้อยู่ในรูปแบบของ พิกัดบนเส้นโค้งวงรี (x, y)
    fun String.keyRecovery(): PointField? {
        return decompressPublicKeyGroup(this)
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


fun main() {

    val privateKey = BigInteger(256, SecureRandom())
    println("Private Key: $privateKey")

    val publicKey = privateKey.toPublicKey()
    println("Public Key: $publicKey")



    val x = BigInteger("103443196931634335679118344570783123314721420590483894750891048854236441600995")
    val p = BigInteger("115792089237316195423570985008687907853269984665640564039457584007908834671663")

    // หาค่า y จาก x โดยใช้สมการของเส้นโค้ง secp256k1
    val ySquared = (x.pow(3) + EllipticCurve.B) % p

    // หาค่า y โดยใช้ modular square root
    val y = ySquared.modPow((p + 1.toBigInteger()) / 4.toBigInteger(), p)

    // หาค่า y ที่สอดคล้องกับ x
    if (y.modPow(2.toBigInteger(), p) == ySquared) {
        println("ค่า y ที่สอดคล้องกับ x คือ: $y")
    } else {
        println("ไม่มีค่า y ที่สอดคล้องกับ x ใน secp256k1")
    }

    val point = PointField(x, y)
    val verify = point.verifyPoint()
    println(verify)


}