package elliptic.example

import java.util.*
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

fun main() {
    // ข้อมูลเพื่อ Encrypt
    val plainText = "ข้อมูลจะถูก Encrypt ด้วย AES"
    val password = "รหัสผ่านสำหรับการ Encrypt" // รหัสผ่านที่จะใช้ในการสร้างคีย์

    try {
        // สร้าง IV (Initialization Vector)
        val iv = IvParameterSpec(ByteArray(16))

        // สร้างคีย์จากรหัสผ่าน (password-based key derivation)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val spec = PBEKeySpec(
            password.toCharArray(),
            iv.iv,
            65536,
            256
        )
        val tmp = factory.generateSecret(spec)
        val secretKey = SecretKeySpec(tmp.encoded, "AES")

        // สร้าง Cipher
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv)

        // Encrypt ข้อมูล
        val encryptedBytes = cipher.doFinal(plainText.toByteArray())

        // แปลงผลลัพธ์เป็น Base64 เพื่อจะสามารถเก็บหรือส่งผ่านได้
        val encryptedText = String(Base64.getEncoder().encode(encryptedBytes))
        println("ข้อมูลที่ถูก Encrypt: $encryptedText")
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
