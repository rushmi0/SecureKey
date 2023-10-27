package elliptic

import elliptic.EllipticCurve.curve
import util.ShiftTo.ByteArrayToBigInteger
import util.ShiftTo.HexToByteArray
import java.math.BigInteger

object ECPublicKey {


    /*
    * ปรับแต่ง Public key
    * */

    private fun fullPublicKeyPoint(k: BigInteger): String {
        try {
            val point: PointField = EllipticCurve.multiplyPoint(k)
            val xHex: String = point.x.toString(16)
            val yHex: String = point.y.toString(16)

            val xSize: Int = xHex.HexToByteArray().size
            val ySize: Int = yHex.HexToByteArray().size

            // คำนวณขนาดของ public key Hex
            val size: Int = (xHex.length + yHex.length) / 2

            if (size != 64) {
                // เมื่อขนาดของ public key Hex ไม่เท่ากับ 64 Bytes ให้ทำการแก้ไข โดยขนาดของค่าพิกัด x และ y จะต้องเท่ากัน 32 Bytes เสมอ
                when {
                    // เมื่อขนาดของพกัด x ไม่เท่ากับ 32 Bytes
                    xSize != 32 -> {
                        // แทรก "0" หน้าสุดเพื่อให้ขนาดเท่ากับ 32 Bytes
                        val padding: String = "0".repeat(32 - xSize)

                        // สร้าง public key ใหม่โดยแทรก "0" หน้าสุดเฉพาะพิกัด x เท่านั้น
                        return "04$padding$xHex$yHex"
                    }
                    // เมื่อขนาดของพกัด y ไม่เท่ากับ 32 Bytes
                    ySize != 32 -> {
                        // แทรก "0" หน้าสุดเพื่อให้ขนาดเท่ากับ 32 Bytes
                        val padding: String = "0".repeat(32 - ySize)

                        // สร้าง public key ใหม่โดยแทรก "0" หน้าสุดเฉพาะพิกัด y เท่านั้น
                        return "04$xHex$padding$yHex"
                    }
                }
            }
            return "04$xHex$yHex"
        } catch (e: Exception) {
            throw IllegalArgumentException("ข้อผิดพลาดในการคำนวณ public key: ${e.message}")
        }
    }




    private fun groupSelection(publicKey: String): String {

        // ตรวจสอบว่า public key มีความยาว 130 และไม่มีเครื่องหมาย "04" นำหน้า
        if (publicKey.length == 130 && publicKey.substring(0, 2) != "04") {
            throw IllegalArgumentException("Invalid Public Key")
        }

        // ทำการแยกพิกัด x ออกมาจาก public key รูปแบบเต็ม
        val x = BigInteger(publicKey.substring(2, 66), 16)

        // ทำการแยกพิกัด y ออกมาจาก public key รูปแบบเต็ม
        val y = BigInteger(publicKey.substring(66), 16)

        // ตรวจสอบว่า y เป็นเลขคู่หรือไม่ เพื่อเลือก group key ที่เหมาะสมเนื่องจากมี 2 กลุ่ม
        return if (y and BigInteger.ONE == BigInteger.ZERO) {
            "02" + x.toString(16).padStart(64, '0')
        } else {
            "03" + x.toString(16).padStart(64, '0')
        }
    }

    private fun decompressPublicKey(compressedPublicKey: String): PointField? {
        try {
            // แปลง compressed public key ในรูปแบบ Hex เป็น ByteArray
            val byteArray: ByteArray = compressedPublicKey.HexToByteArray()

            // ดึงค่า x coordinate จาก ByteArray
            val xCoord: BigInteger = byteArray.copyOfRange(1, byteArray.size).ByteArrayToBigInteger()

            // ตรวจสอบว่า y เป็นเลขคู่หรือไม่
            val isYEven: Boolean = byteArray[0] == 2.toByte()

            // คำนวณค่า x^3 (mod P)
            val xCubed: BigInteger = xCoord.modPow(BigInteger.valueOf(3), curve.P)

            // คำนวณ Ax (mod P)
            val Ax: BigInteger = xCoord.multiply(curve.A) % curve.P

            // คำนวณ y^2 = x^3 + Ax + B (mod P)
            val ySquared: BigInteger = xCubed.add(Ax).add(curve.B) % curve.P

            // คำนวณค่า y จาก y^2 โดยใช้ square root
            val y: BigInteger = ySquared.modPow(curve.P.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), curve.P)

            // ตรวจสอบว่า y^2 เป็นเลขคู่หรือไม่
            val isYSquareEven: Boolean = y.mod(BigInteger("2")) == BigInteger.ZERO

            // คำนวณค่า y โดยแก้ไขเครื่องหมายตามผลลัพธ์ที่ได้จากการตรวจสอบ
            val computedY: BigInteger = if (isYSquareEven != isYEven) curve.P.subtract(y) else y

            // สร้าง PointField จาก x และ y ที่ได้
            return PointField(xCoord, computedY)
        } catch (e: IllegalArgumentException) {
            println("Invalid public key: ${e.message}")
            return null
        } catch (e: Exception) {
            println("Failed to decompress the public key: ${e.message}")
            return null
        }

    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    fun String.keyRecovery(): PointField? {
        return decompressPublicKey(this)
    }

    fun BigInteger.toPublicKey(): String {
        return fullPublicKeyPoint(this)
    }

    fun String.compressed(): String {
        return groupSelection(this)
    }

}