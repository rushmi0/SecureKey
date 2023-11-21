package elliptic.Signature


import util.ShiftTo.DeciToHex
import util.ShiftTo.HexToByteArray
import java.math.BigInteger
import java.security.MessageDigest
import java.util.*

val DEBUG = false

val p = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
val n = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

val G = Pair(
    BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
    BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
)

typealias Point = Pair<BigInteger, BigInteger>

fun taggedHash(tag: String, msg: ByteArray): ByteArray {
    val tagHash = MessageDigest.getInstance("SHA-256").digest(tag.toByteArray())
    val fullMsg = tagHash + tagHash + msg
    return MessageDigest.getInstance("SHA-256").digest(fullMsg)
}

fun isInfinity(P: Point?): Boolean = P == null

fun x(P: Point): BigInteger {
    require(!isInfinity(P)) { "Point must not be infinity." }
    return P.first
}

fun y(P: Point): BigInteger {
    require(!isInfinity(P)) { "Point must not be infinity." }
    return P.second
}

fun pointAdd(P1: Point?, P2: Point?): Point? {
    if (P1 == null) {
        return P2
    }
    if (P2 == null) {
        return P1
    }
    if (x(P1) == x(P2) && y(P1) != y(P2)) {
        return null
    }
    val lam = if (P1 == P2) {
        (3.toBigInteger() * x(P1).pow(2) * (2.toBigInteger() * y(P1)).modInverse(p)) % p
    } else {
        ((y(P2) - y(P1)) * (x(P2) - x(P1)).modInverse(p)) % p
    }
    val x3 = (lam.pow(2) - x(P1) - x(P2)).mod(p)
    return Pair(x3, (lam * (x(P1) - x3) - y(P1)).mod(p))
}

fun pointMul(P: Point?, n: BigInteger): Point? {
    var R: Point? = null
    var currentPoint = P
    for (i in 0 .. 256) {
        if (n.testBit(i)) {
            R = pointAdd(R, currentPoint)
        }
        currentPoint = pointAdd(currentPoint, currentPoint)
    }
    return R
}

fun bytesFromInt(x: BigInteger): ByteArray = x.toByteArray()

fun bytesFromPoint(P: Point): ByteArray = bytesFromInt(x(P))

fun xorBytes(b0: ByteArray, b1: ByteArray): ByteArray =
    ByteArray(b0.size) { i -> (b0[i].toInt() xor b1[i].toInt()).toByte() }

fun liftX(x: BigInteger): Point? {
    if (x >= p) {
        return null
    }
    val ySq = (x.pow(3) + 7.toBigInteger()).mod(p)
    val y = ySq.modPow(p.add(BigInteger.ONE).divide(BigInteger("4")), p)
    if (y.modPow(BigInteger("2"), p) != ySq) {
        return null
    }
    return Pair(x, if (y.testBit(0)) y else p - y)
}

fun intFromBytes(b: ByteArray): BigInteger = BigInteger(1, b)

fun hashSha256(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(b)

fun hasEvenY(P: Point): Boolean {
    require(!isInfinity(P)) { "Point must not be infinity." }
    return y(P).mod(BigInteger("2")) == BigInteger.ZERO
}

fun pubkeyGen(seckey: ByteArray): ByteArray {
    val d0 = intFromBytes(seckey)
    require(d0 in BigInteger.ONE..(n - BigInteger.ONE)) { "The secret key must be an integer in the range 1..n-1." }
    val P = pointMul(G, d0)
    require(P != null) { "Point multiplication resulted in infinity." }
    return bytesFromPoint(P)
}

fun schnorrSign(msg: ByteArray, seckey: ByteArray, auxRand: ByteArray): ByteArray {
    val d0 = intFromBytes(seckey)
    require(d0 in BigInteger.ONE .. n) { "The secret key must be an integer in the range 1..n-1." }
    require(auxRand.size == 32) { "auxRand must be 32 bytes." }

    val P = pointMul(G, d0)
    require(P != null) { "Point multiplication resulted in infinity." }

    val d = if (hasEvenY(P)) d0 else n - d0
    val t = xorBytes(bytesFromInt(d), taggedHash("BIP0340/aux", auxRand))

    val k0 = intFromBytes(taggedHash("BIP0340/nonce", t + bytesFromPoint(P) + msg)) % n
    require(k0 != BigInteger.ZERO) { "Failure. This happens only with negligible probability." }

    val R = pointMul(G, k0)
    require(R != null) { "Point multiplication resulted in infinity." }
    val k = if (!hasEvenY(R)) n - k0 else k0

    val e = intFromBytes(taggedHash("BIP0340/challenge", bytesFromPoint(R) + bytesFromPoint(P) + msg)) % n

    val sig = bytesFromPoint(R) + bytesFromInt((k + e * d) % n)
    require(schnorrVerify(msg, bytesFromPoint(P), sig)) { "The created signature does not pass verification." }

    return sig
}

fun schnorrVerify(msg: ByteArray, pubkey: ByteArray, sig: ByteArray): Boolean {
    require(pubkey.size == 32) { "The public key must be a 32-byte array." }
    require(sig.size == 64) { "The signature must be a 64-byte array." }

    val P = liftX(intFromBytes(pubkey))
    val r = intFromBytes(sig.sliceArray(0 .. 32))
    val s = intFromBytes(sig.sliceArray(32 .. 64))

    require(P != null && r < p && s < n) { "Invalid public key, r, or s." }

    val e = intFromBytes(taggedHash("BIP0340/challenge", sig.sliceArray(0 .. 32) + pubkey + msg)) % n

    val R = pointAdd(pointMul(G, s), pointMul(P, n - e))
    require(R != null && hasEvenY(R) && x(R) == r) { "Verification failed." }

    return true
}

fun main() {
    val random = Random()
    val privateKey = ByteArray(32)
    random.nextBytes(privateKey)

    val publicKey = pubkeyGen(privateKey)
    println("Public key: ${publicKey.joinToString("") { "%02x".format(it) }}")
    val message = "4c7dbc46486ad9569442d69b558db99a2612c4f003e6631b593942f531e67fd4"
    val sk = BigInteger("93c9d847baaf9ee2a4b65674f2cb3bafb36cc6aa6d9afae863117c1a745b1861", 16)
    val pk = pubkeyGen(sk.DeciToHex().HexToByteArray())
    println("My public key: ${pk.joinToString("") { "%02x".format(it) }}")

    val signature = "3878c9af545e6f28b71646a67e658ee7fbec1c531cd5981f8b6fdd8b8bd0ee3779d70190dee926a0f9b5ba0b42d244d6bf42643830209b3381a71c24b1fbc762"
    val msg = message.HexToByteArray()
    val sig = signature.HexToByteArray()

    val verify = schnorrVerify(msg, pk, sig)
    println("My signature verify: $verify")

    val pubKeyPoint = pointMul(G, intFromBytes(privateKey))
    val p = pubKeyPoint?.let { bytesFromPoint(it) }
    println("Public key point: ${p?.joinToString("") { "%02x".format(it) }}")

    val auxRand = "2455993b2c90f1c459bae2c7b09704ab0f10406f84e1acd35610e8867b430bd8".HexToByteArray()
    val newSignature = schnorrSign(msg, privateKey, auxRand)
    val verifyNew = schnorrVerify(msg, pk, newSignature)
    println("New signature verify: $verifyNew")
}
