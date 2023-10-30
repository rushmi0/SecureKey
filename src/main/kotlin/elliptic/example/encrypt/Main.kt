package elliptic.example.encrypt

import util.ShiftTo.HexToByteArray
import java.security.Key
import java.security.SecureRandom
import java.util.*
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec


fun main() {

    /**
     * Private Key A: 78259801880556228373214193755537384691115084873851560772251393181251309866804
     * Private Key B: 107294905647052855626682769911966444436679883199378128858648303689163762787595
     *
     * Public Key A: 036933d7ead29b3983d17007e9d8b77d0f2568f92576d3469f7c68b6817d13275d
     * Public Key B: 02839973fd23622cc88cbf0b462134ec5e92f2f40ffaef8ca29d34d1e8b12b9c78
     *
     * Shared Key A: 20dff24120a1e6df60396f27345588a9f054a4c329f3ee73c7083822364db36d
     * Shared Key B: 20dff24120a1e6df60396f27345588a9f054a4c329f3ee73c7083822364db36d
     * */

    // นี้คือตัวอย่าง NIP-04 : Encrypted Direct Message

    val sharedX = "38654e616007f816efa21fb773f14149cad9cfdd3ea2df7909c2a17ef247f2ed"
    val text = "YourPlainTextMessageHere"
    val ourPubKey = "036933d7ead29b3983d17007e9d8b77d0f2568f92576d3469f7c68b6817d13275d"
    val theirPublicKey = "02839973fd23622cc88cbf0b462134ec5e92f2f40ffaef8ca29d34d1e8b12b9c78"

    val iv = ByteArray(16)
    val random = SecureRandom()
    random.nextBytes(iv)

    val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
    val secretKey: Key = SecretKeySpec(sharedX.HexToByteArray(), "AES")
    val ivParameterSpec = IvParameterSpec(iv)
    cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParameterSpec)
    val encryptedBytes = cipher.doFinal(text.toByteArray(charset("UTF-8")))
    val encryptedMessage = Base64.getEncoder().encodeToString(encryptedBytes)
    val ivBase64 = Base64.getEncoder().encodeToString(iv)

    val event: MutableMap<String, Any> = HashMap()
    event["pubkey"] = ourPubKey
    event["created_at"] = Date().time / 1000
    event["kind"] = 4
    val tag: MutableMap<String, String> = HashMap()
    tag["p"] = theirPublicKey
    event["tags"] = arrayOf<Any>(tag)
    event["content"] = "$encryptedMessage?iv=$ivBase64"

    println(event)
}