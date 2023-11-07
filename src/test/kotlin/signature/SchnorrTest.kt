package signature


import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test

import elliptic.ECPublicKey.toPoint
import elliptic.Signature.Schnorr
import util.Hashing.SHA256
import util.ShiftTo.ByteArrayToBigInteger

import java.math.BigInteger

class SchnorrTest {



    /*
    @Test
    fun testSignAndVerify() {
        // สร้าง private key แบบสุ่ม
        val privateKey = BigInteger(256, java.security.SecureRandom())

        // สร้าง message
        val message: ByteArray = "I am a fish".SHA256()

        // สร้าง signature จาก private key และ message
        val signature = Schnorr.sign(privateKey, message.ByteArrayToBigInteger())

        // สร้าง public key จาก private key
        val publicKey = privateKey.toPoint().x.toByteArray()

        // ตรวจสอบว่า signature ที่สร้างขึ้นมานั้นถูกต้องหรือไม่
        val result = Schnorr.verify(publicKey, message, signature)

        // แสดงผลลัพธ์ ถ้าเป็น true แสดงว่า signature ถูกต้อง
        Assertions.assertTrue(result)
    }


    @Test
    fun testInvalidSignature() {
        // สร้าง private key แบบสุ่ม
        val privateKey1 = BigInteger(256, java.security.SecureRandom())
        val privateKey2 = BigInteger(256, java.security.SecureRandom())

        // สร้าง message
        val message: ByteArray = "I am a fish".SHA256()

        // สร้าง signature จาก private key อันแรก
        val signature1 = Schnorr.sign(privateKey1, message.ByteArrayToBigInteger())

        // สร้าง signature จาก private key อันที่สอง
        val signature2 = Schnorr.sign(privateKey2, message.ByteArrayToBigInteger())

        // สร้าง public key จาก private key อันที่สอง
        val publicKey2 = privateKey2.toPoint().x.toByteArray()
        val result = Schnorr.verify(publicKey2, message, signature1)

        // แสดงผลลัพธ์ ถ้าเป็น false แสดงว่า signature ไม่ถูกต้อง
        Assertions.assertFalse(result)
    }
     */


}
