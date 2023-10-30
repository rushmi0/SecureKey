package elliptic.example.encrypt

import java.nio.charset.StandardCharsets
import java.security.InvalidAlgorithmParameterException
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.security.spec.InvalidKeySpecException
import java.security.spec.KeySpec
import java.util.*
import javax.crypto.*
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec


object AESExample {


    private const val SECRET_KEY = "123456789"
    private const val SALTVALUE = "abcdefg"


    fun encrypt( strToEncrypt: String): String? {
        try {

            val iv = byteArrayOf(
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
            )
            val ivspec = IvParameterSpec(iv)

            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")

            val spec: KeySpec = PBEKeySpec(
                SECRET_KEY.toCharArray(),
                SALTVALUE.toByteArray(),
                65536,
                256
            )

            val tmp = factory.generateSecret(spec)

            val secretKey = SecretKeySpec(tmp.encoded, "AES")

            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")

            cipher.init(
                Cipher.ENCRYPT_MODE,
                secretKey,
                ivspec
            )

            return Base64.getEncoder()
                .encodeToString(cipher.doFinal(strToEncrypt.toByteArray(StandardCharsets.UTF_8)))

        } catch (e: InvalidAlgorithmParameterException) {
            println("Error occured during encryption: $e")
        } catch (e: InvalidKeyException) {
            println("Error occured during encryption: $e")
        } catch (e: NoSuchAlgorithmException) {
            println("Error occured during encryption: $e")
        } catch (e: InvalidKeySpecException) {
            println("Error occured during encryption: $e")
        } catch (e: BadPaddingException) {
            println("Error occured during encryption: $e")
        } catch (e: IllegalBlockSizeException) {
            println("Error occured during encryption: $e")
        } catch (e: NoSuchPaddingException) {
            println("Error occured during encryption: $e")
        }
        return null
    }


    fun decrypt(strToDecrypt: String?): String? {
        try {

            val iv = byteArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
            val ivspec = IvParameterSpec(iv)

            val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")

            val spec: KeySpec = PBEKeySpec(
                SECRET_KEY.toCharArray(),
                SALTVALUE.toByteArray(),
                65536,
                256
            )

            val tmp = factory.generateSecret(spec)

            val secretKey = SecretKeySpec(tmp.encoded, "AES")

            val cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING")

            cipher.init(
                Cipher.DECRYPT_MODE,
                secretKey,
                ivspec
            )

            return String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)))

        } catch (e: InvalidAlgorithmParameterException) {
            println("Error occured during decryption: $e")
        } catch (e: InvalidKeyException) {
            println("Error occured during decryption: $e")
        } catch (e: NoSuchAlgorithmException) {
            println("Error occured during decryption: $e")
        } catch (e: InvalidKeySpecException) {
            println("Error occured during decryption: $e")
        } catch (e: BadPaddingException) {
            println("Error occured during decryption: $e")
        } catch (e: IllegalBlockSizeException) {
            println("Error occured during decryption: $e")
        } catch (e: NoSuchPaddingException) {
            println("Error occured during decryption: $e")
        }
        return null
    }


    @JvmStatic
    fun main(args: Array<String>) {

        val originalval = "AES Encryption"

        val encryptedval = encrypt(originalval)

        val decryptedval = decrypt(encryptedval)
        println("Original value: $originalval")

        println("Encrypted value: $encryptedval")
        println("Decrypted value: $decryptedval")
    }
}