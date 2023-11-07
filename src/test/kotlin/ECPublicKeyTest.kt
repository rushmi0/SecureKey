import elliptic.ECPublicKey.compressed
import elliptic.ECPublicKey.evaluatePoint
import elliptic.ECPublicKey.isPointOnCurve
import elliptic.ECPublicKey.pointRecovery
import elliptic.ECPublicKey.toPoint
import elliptic.ECPublicKey.toPublicKey
import elliptic.EllipticCurve
import elliptic.PointField
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import util.ShiftTo.DeciToHex
import util.ShiftTo.HexToByteArray

import java.math.BigInteger


@DisplayName("ทดสอบคลาส ECPublicKey")
class ECPublicKeyTest {

    // กำหนดตัวแปรเก็บค่า private key
    private lateinit var privateKey: BigInteger
    private lateinit var publicKeyPoint: PointField
    private lateinit var publicKeyCompressed: String
    private lateinit var publicKeyUncompressed: String

    @BeforeEach
    @DisplayName("กำหนดค่าเริ่มต้น")
    fun setupDefaultValues() {

        // กำหนดค่า private key เพื่อใช้ในการทดสอบ
        privateKey = BigInteger("25fc758699f0d46d177764f79ddd8d76256f0204299a3c5da88f5d12e61ba9c7", 16)

        // กำหนดค่า public key ในรูปแบบพิกัด (x, y) บนเส้นโค้ง elliptic curve
        publicKeyPoint = PointField(
            x = BigInteger("f1ec849cd828a5076db404768add72c29351b57d60b41eea5f1085baf9b2045a", 16),
            y = BigInteger("3bae7479360ed73cf66456dfd2c666b3d0d5d674d5d5a5f6799a9ce1c37d64d1", 16),
        )

        // ค่า public key แบบบีบอัด รูปแบบเลขฐาน 16 มีขนาดความยาว 33 bytes
        publicKeyCompressed = "03f1ec849cd828a5076db404768add72c29351b57d60b41eea5f1085baf9b2045a"

        // ค่า public key แบบไม่บีบอัด รูปแบบเลขฐาน 16 มีขนาดความยาว 65 bytes
        publicKeyUncompressed =
            "04f1ec849cd828a5076db404768add72c29351b57d60b41eea5f1085baf9b2045a3bae7479360ed73cf66456dfd2c666b3d0d5d674d5d5a5f6799a9ce1c37d64d1"
    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    @Test
    @DisplayName("ทดสอบ เรียกใช้งาน toPublicKey() เพื่อสร้าง public key")
    fun testToPublicKey() {
        val uncompressedPublicKey = privateKey.toPublicKey()

        Assertions.assertEquals(
            65,
            uncompressedPublicKey.HexToByteArray().size
        )

        Assertions.assertEquals(
            publicKeyUncompressed,
            uncompressedPublicKey
        )
    }

    @Test
    @DisplayName("ทดสอบ เรียกใช้งาน compressed() เพื่อสร้าง public key แบบบีบอัด")
    fun testCompressed() {
        val publicKey = privateKey.toPublicKey().compressed()

        Assertions.assertEquals(
            33,
            publicKey.HexToByteArray().size
        )

        Assertions.assertEquals(
            publicKeyCompressed,
            publicKey
        )
    }



    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    // ทดสอบ เรียกใช้งาน `isPointOnCurve()` เพื่อตรวจสอบว่า public key อยู่บนเส้นโค้ง elliptic curve ผลลัพธ์เป็นจริง
    @Test
    @DisplayName("ทดสอบ เรียกใช้งาน isPointOnCurve() : คืนค่า true่")
    fun testisPointOnCurveTrue() {
        val verifyPoint = isPointOnCurve(privateKey.toPoint())
        val modelPoint = isPointOnCurve(publicKeyPoint)
        Assertions.assertTrue(verifyPoint)
        Assertions.assertEquals(
            verifyPoint,
            modelPoint,
            "Public key ไม่ตรงกับค่าที่คาดหวัง \nค่าที่คาดหวัง: $modelPoint \nค่าที่ได้จากการทดสอบ: $verifyPoint"
        )
    }



    // ทดสอบ เรียกใช้งาน `isPointOnCurve()` เพื่อตรวจสอบว่า public key อยู่บนเส้นโค้ง elliptic curve ผลลัพธ์เป็นเท็จ
    @Test
    @DisplayName("ทดสอบ เรียกใช้งาน isPointOnCurve() : คืนค่า false")
    fun testisPointOnCurveFalse() {
        val inValinPoint = PointField(
            x = BigInteger("f1ec849cd828a5076db404768add72c29351b57d60b41eea5f1085baf9b2045a", 16),
            y = BigInteger("3bae7479360ed73cf66456dfd2c666b3d0d5d674d5d5a5f6799a9ce1c37d64d", 16),
        )
        val verifyPoint = isPointOnCurve(inValinPoint)

        Assertions.assertFalse(verifyPoint)

        Assertions.assertEquals(
            verifyPoint,
            false
        )
    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    @Test
    fun testPointRecovery() {

        val keyPoint: PointField = privateKey.toPublicKey().compressed().pointRecovery()
        Assertions.assertEquals(
            publicKeyPoint,
            keyPoint
        )

    }

    @Test
    @DisplayName("ทดสอบ เรียกใช้งาน evaluatePoint() เพื่อคำนวณค่า y")
    fun testEvaluatePoint() {

        val keyPointXonly: PointField = privateKey.toPoint().x.evaluatePoint()
        Assertions.assertEquals(
            publicKeyPoint,
            keyPointXonly
        )

        val keyPoint: PointField = privateKey.toPoint().x.DeciToHex().pointRecovery()
        Assertions.assertEquals(
            publicKeyPoint,
            keyPoint
        )

    }



    /*
    @Test
    fun testEvaluatePoint() {
        val publicKey = privateKey.toPoint().x.toByteArray()
        val compressedPublicKey = publicKey.compressed()
        val uncompressedPublicKey = compressedPublicKey.toPublicKey()
        val point = uncompressedPublicKey.toPoint()
        Assertions.assertEquals(point, uncompressedPublicKey.evaluatePoint())
    }



    @Test
    fun testPointRecovery() {
        val publicKey = privateKey.toPoint().x.toByteArray()
        val compressedPublicKey = publicKey.compressed()
        val uncompressedPublicKey = compressedPublicKey.toPublicKey()
        val point = uncompressedPublicKey.toPoint()
        val recoveredPoint = pointRecovery(point.x, point.y, point.yBit)
        Assertions.assertEquals(point, recoveredPoint)
    }
     */

}