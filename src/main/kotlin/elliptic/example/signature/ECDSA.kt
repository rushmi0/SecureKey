package elliptic.example.signature

import elliptic.ECPublicKey.compressed

import elliptic.ECPublicKey.toPublicKey
import elliptic.Signature.ECDSA
import util.Hashing.SHA256

import util.ShiftTo.ByteArrayToHex
import util.ShiftTo.DeciToHex
import java.math.BigInteger
import java.security.SecureRandom


fun main() {

    val privateKey = BigInteger(256, SecureRandom())

    val message = BigInteger("Hello World".SHA256().ByteArrayToHex(), 16)

    val xValue: String = privateKey.toPublicKey().compressed()

    val signature: Pair<BigInteger, BigInteger> = ECDSA.sign(privateKey, message)

    val verify: Boolean = ECDSA.verify(xValue, message, signature)

    println("Private Key hex ${privateKey.toByteArray().size} bytes: ${privateKey.DeciToHex()}")
    println("signature: \n s : ${signature.first.DeciToHex()} ${signature.first.toByteArray().size} Bytes \n r : ${signature.second.DeciToHex()} ${signature.second.toByteArray().size} Bytes")
    println("verify: $verify")

}