package elliptic.example.encrypt


import util.ShiftTo.HexToByteArray
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import java.util.Base64

fun encrypt(data: String, key: String): String {
    try {
        // Validate key length (AES 128 requires 16 bytes key)
        //require(key.HexToByteArray().size == 32) { "Key must be 32 characters long (128 bits)." }

        // Convert the key and data to byte arrays
        val keyBytes = key.toByteArray()
        val dataBytes = data.toByteArray()

        // Create a key specification
        val keySpec = SecretKeySpec(keyBytes, "AES")

        // Create an initialization vector (IV)
        val iv = IvParameterSpec(ByteArray(16))

        // Create a cipher and initialize it for encryption
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv)

        // Encrypt the data
        val encryptedData = cipher.doFinal(dataBytes)

        // Encode the encrypted data as a base64 string
        val encryptedDataString = Base64.getEncoder().encodeToString(encryptedData)

        return encryptedDataString
    } catch (e: Exception) {
        e.printStackTrace()
    }
    return ""
}

fun main() {
    val dataToEncrypt = "ข้อมูลที่คุณต้องการเข้ารหัส"
    val key = "46f0b750309a8dcf131bd18e362bb6a419a06c0431d40e8d34072b33caadeb9b"

    val encryptedData = encrypt(dataToEncrypt, key)
    println("ข้อมูลที่เข้ารหัส: $encryptedData")
}
