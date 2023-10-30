package elliptic.example.encrypt


import java.security.SecureRandom
import java.security.spec.KeySpec
import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

object AES256 {

    private const val KEY_LENGTH = 256 // ขนาดของ Key ที่จะใช้ในการ Encrypt และ Decrypt
    private const val ITERATION_COUNT = 65536

    fun encrypt(
        strToEncrypt: String,
        secretKey: String,
        salt: String = ""
    ): String? {

        val secureRandom = SecureRandom()

        val iv = ByteArray(16)

        secureRandom.nextBytes(iv)

        val ivspec = IvParameterSpec(iv)

        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")

        // สร้างตัวแปร valueHex เพื่อแปลง ค่า factory เป็น Hex
        //val valueHex = factory.toString().BinaryToHex()


        // สร้างตัวแปร spec เพื่อเก็บค่า PBEKeySpec ที่เป็น Hex
        val spec: KeySpec = PBEKeySpec(
            secretKey.toCharArray(),
            salt.toByteArray(),
            ITERATION_COUNT,
            KEY_LENGTH
        )

        // สร้างตัวแปร tmp เพื่อเก็บค่า factory.generateSecret(spec) ที่เป็น Hex
        val tmp = factory.generateSecret(spec)

        //
        val secretKeySpec = SecretKeySpec(
            tmp.encoded,
            "AES"
        )

        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

        cipher.init(
            Cipher.ENCRYPT_MODE,
            secretKeySpec,
            ivspec
        )

        val cipherText = cipher.doFinal(strToEncrypt.toByteArray(charset("UTF-8")))

        val encryptedData = ByteArray(iv.size + cipherText.size)

        System.arraycopy(
            iv,
            0,
            encryptedData,
            0,
            iv.size
        )

        System.arraycopy(
            cipherText,
            0,
            encryptedData,
            iv.size,
            cipherText.size
        )

        return Base64.getEncoder().encodeToString(encryptedData)

    }


    fun decrypt(
        strToDecrypt: String?,
        secretKey: String,
        salt: String = ""
    ): String? {
        return try {
            val encryptedData = Base64.getDecoder().decode(strToDecrypt)
            val iv = ByteArray(16)
            System.arraycopy(encryptedData, 0, iv, 0, iv.size)
            val ivspec = IvParameterSpec(iv)
            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
            val spec: KeySpec = PBEKeySpec(secretKey.toCharArray(), salt.toByteArray(), ITERATION_COUNT, KEY_LENGTH)
            val tmp = factory.generateSecret(spec)
            val secretKeySpec = SecretKeySpec(tmp.encoded, "AES")
            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivspec)
            val cipherText = ByteArray(encryptedData.size - 16)
            System.arraycopy(encryptedData, 16, cipherText, 0, cipherText.size)
            val decryptedText = cipher.doFinal(cipherText)
            String(decryptedText, charset("UTF-8"))
        } catch (e: java.lang.Exception) {
            // Handle the exception properly
            e.printStackTrace()
            null
        }
    }



}


fun main() {

    // สร้างตัวอย่างการ Encrypt และ Decrypt
    val plainText = "ข้อมูลจะถูก Encrypt ด้วย AES"

    // นี้คือ Key ความลับสำหรับ Encrypt และ Decrypt
    val secretKey = "รหัสผ่านสำหรับการ Encrypt"

    // นี้คือ Salt ที่ใช้ในการสร้าง Key ความลับ
    val salt = "1234 ไม่รู้"

    // ทำการ Encrypt ข้อมูล
    val encryptedText = AES256.encrypt(plainText, secretKey, salt)

    // ทำการ Decrypt ข้อมูล
    val decryptedText = AES256.decrypt(encryptedText, secretKey, salt)

    // แสดงผลลัพธ์
    println("ข้อมูลที่ถูก Encrypt: $encryptedText")
    println("ข้อมูลที่ถูก Decrypt: $decryptedText")

}