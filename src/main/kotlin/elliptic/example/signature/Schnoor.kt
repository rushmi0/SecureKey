package elliptic.example.signature

import elliptic.ECPublicKey.compressed
import elliptic.ECPublicKey.toPublicKey
import elliptic.Signature.Schnorr
import util.Hashing.SHA256
import util.ShiftTo.ByteArrayToBigInteger
import util.ShiftTo.DeciToHex
import java.math.BigInteger
import java.security.SecureRandom


fun main() {

    val privateKey = BigInteger(256, SecureRandom())

    //val privateKey = BigInteger("83815085818061553551680724484383113567819967948708730975173007970516951616417")

    val message: ByteArray = "I am a fish".SHA256()

    val xValue: String = privateKey.toPublicKey().compressed() // PublicKey x value

    val signature = Schnorr.sign(privateKey, message.ByteArrayToBigInteger())

    val verify: Boolean = Schnorr.verify(xValue, message, signature)

    println("Private Key hex ${privateKey.toByteArray().size} bytes: ${privateKey.DeciToHex()}")
    println("signature: \n s : ${signature.first.DeciToHex()} ${signature.first.toByteArray().size} Bytes \n r : ${signature.second.DeciToHex()} ${signature.second.toByteArray().size} Bytes")
    println("verify: $verify")


}