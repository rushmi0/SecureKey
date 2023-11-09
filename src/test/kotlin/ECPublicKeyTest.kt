import elliptic.ECPublicKey.compressed
import elliptic.ECPublicKey.evaluatePoint
import elliptic.ECPublicKey.isPointOnCurve
import elliptic.ECPublicKey.pointRecovery
import elliptic.ECPublicKey.toPoint
import elliptic.ECPublicKey.toPublicKey
import elliptic.EllipticCurve.multiplyPoint

import elliptic.PointField
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Test
import util.Hashing.SHA256
import util.ShiftTo.DeciToHex
import util.ShiftTo.HexToByteArray

import java.math.BigInteger
import java.security.SecureRandom

@DisplayName("ทดสอบคลาส ECPublicKey")
open class ECPublicKeyTest {

    lateinit var random: ByteArray

    lateinit var nonce: ByteArray
    lateinit var message: ByteArray
    lateinit var signTarget: String
    lateinit var signPointTarget: Pair<BigInteger, BigInteger>

    // กำหนดตัวแปรเก็บค่า private key
    lateinit var privateKey: BigInteger
    lateinit var publicKeyXHex: String
    lateinit var publicKeyPoint: PointField
    lateinit var publicKeyDynamic: PointField
    lateinit var publicKeyCompressed: String
    lateinit var publicKeyUncompressed: String

    @BeforeEach
    @DisplayName("กำหนดค่าเริ่มต้น")
    fun setupDefaultValues() {


        fun generateAuxRand(): ByteArray {
            while (true) {
                val auxRand = BigInteger(256, SecureRandom()).DeciToHex().HexToByteArray()
                if (auxRand.size == 32) {
                    return auxRand
                }
            }
        }

        // กำหนดค่า random ในการทดสอบ
        random = generateAuxRand()

        // กำหนดค่า nonce ในการทดสอบ
        nonce = BigInteger("2455993b2c90f1c459bae2c7b09704ab0f10406f84e1acd35610e8867b430bd8", 16).toByteArray()

        message = "I am a fish".SHA256()

        signTarget = "5c8d863a091fde5ca72cbc30fd9a49ac0abc8c26d0b83bf080dd4838ced0c8f7c1562a67330a191e310e5839001d047933b4d84c317920c5c5e59da8e9dc9c09"
        // 4847384999190158545709892993003531849746990492407371070766663107746474172611452108267489312004708437202159181050345856585202289880875236064222950194977801
        signPointTarget = Pair(
            BigInteger("41862833904442557158276244070279884087836456129182286835997566401078635841783"),
            BigInteger("87448621279737506928047426130927537666855239366944637572166791512575140731913")
        )

        // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\

        // กำหนดค่า private key เพื่อใช้ในการทดสอบ
        privateKey = BigInteger("25fc758699f0d46d177764f79ddd8d76256f0204299a3c5da88f5d12e61ba9c7", 16)

        // กำหนดค่า public key พิกัด X ในรูปแบบเลขฐาน 16 มีขนาดความยาว 32 bytes
        publicKeyXHex = "f1ec849cd828a5076db404768add72c29351b57d60b41eea5f1085baf9b2045a"

        // กำหนดค่า public key ในรูปแบบพิกัด (x, y) บนเส้นโค้ง elliptic curve
        publicKeyPoint = PointField(
            x = BigInteger("109425287674888529967061023908045177545342372981171741638737825913363439420506"),
            y = BigInteger("26994693326106899108400221961201137498071272943049114705041999196335860704465"),
        )

        publicKeyDynamic = multiplyPoint(privateKey)

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
        val verifyPoint = isPointOnCurve(publicKeyDynamic)
        val modelPoint = isPointOnCurve(publicKeyPoint)
        Assertions.assertTrue(verifyPoint)
        Assertions.assertEquals(
            verifyPoint,
            modelPoint
        )
    }



    // ทดสอบ เรียกใช้งาน `isPointOnCurve()` เพื่อตรวจสอบว่า public key อยู่บนเส้นโค้ง elliptic curve ผลลัพธ์เป็นเท็จ
    @Test
    @DisplayName("ทดสอบ เรียกใช้งาน isPointOnCurve() : คืนค่า false")
    fun testisPointOnCurveFalse() {
        // PointField(x=109425287674888529967061023908045177545342372981171741638737825913363439420506, y=88797395911209296315170763047486770355198711722591449334415584811572973967198)
        val inValinPoint = PointField(
            x = BigInteger("109425287674888529967061023908045177545342372981171741638737825913363439420506"),
            y = BigInteger("88797395911209296315170763047486770355198711722591449334415584811572973967198"),
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
    fun testFindY() {

        val key33Bytes: PointField = privateKey.toPublicKey().compressed().pointRecovery()
        Assertions.assertEquals(
            publicKeyPoint,
            key33Bytes
        )

        val key32Bytes: PointField = publicKeyXHex.pointRecovery()
        Assertions.assertEquals(
            publicKeyPoint,
            key32Bytes
        )

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



}