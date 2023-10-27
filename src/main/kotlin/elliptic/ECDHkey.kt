package elliptic


import elliptic.ECPublicKey.keyRecovery
import elliptic.EllipticCurve.multiplyPoint
import java.math.BigInteger

object ECDHkey {

    /**
     *
     * `ECDH Key` มีชื่อเรียกเฉพาะคือ `ECDH Shared Secret` หรือ `Elliptic Curve Diffie-Hellman Shared Secret`
     * `ECDH Shared Secret` คือคีย์ลับที่สร้างขึ้นระหว่างสองฝ่ายโดยใช้อัลกอริทึม ECDH (Elliptic Curve Diffie-Hellman)
     * โดยใช้คีย์สาธารณะและคีย์ส่วนตัวของฝ่ายแต่ละฝ่าย นำมาคำนวณกัน จะได้คีย์ลับที่เป็นค่าเดียวกัน ซึ่งจะนำไปใช้เป็นคีย์สำหรับการเข้ารหัสและถอดรหัสข้อมูล โดยใช้วิธีการเข้ารหัสแบบสมมาตร (Symmetric Encryption)
     *
     * */



    // ใช้สำหรับสร้าง Shared Key ระหว่าง 2 ฝ่าย เรียกว่า ECDH (Elliptic Curve Diffie-Hellman)
    fun sharedSecret(
        // Public Key ของฝ่ายตรงข้าม
        publicKey: String,
        // Private Key ของตัวเอง
        privateKey: BigInteger
    ): String {

        // แปลง public key ให้อยู่ในรูปของ PointField นั้นก็คือ (x, y) ซึ่งเป็นพิกัดบนเส้นโค้งวงรี
        val point: PointField = publicKey.keyRecovery()
            ?: throw IllegalArgumentException("Invalid or unsupported public key format")

        val curvePoint = multiplyPoint(
            privateKey, // นี่เป็นค่า Private Key ของตัวเอง

            // นี่คือค่า x และ y ของจุดบนเส้นโค้งวงรีที่มาจาก public key ของฝ่ายตรงข้าม
            point
        )

        return curvePoint.x.toString(16)
    }


}