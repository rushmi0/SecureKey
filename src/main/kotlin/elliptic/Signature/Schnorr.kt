package elliptic.Signature


import elliptic.ECPublicKey.toPoint
import elliptic.EllipticCurve
import elliptic.EllipticCurve.multiplyPoint
import elliptic.PointField
import elliptic.Secp256K1
import elliptic.Signature.Schnorr.generateAuxRand
import fr.acinq.secp256k1.Secp256k1
import util.Hashing.SHA256
import util.ShiftTo.ByteArrayToBigInteger
import util.ShiftTo.ByteArrayToHex
import util.ShiftTo.DeciToHex
import util.ShiftTo.HexToByteArray
import java.math.BigInteger
import java.security.SecureRandom


/*
* สร้างลายเซ็นและตรวจสอบ Schnorr Signature
* https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#user-content-Public_Key_Generation
* */


object Schnorr {


    // * Parameters secp256k1
    private val curveDomain: Secp256K1.CurveParams = Secp256K1.getCurveParams()
    private val N: BigInteger = curveDomain.N
    private val P: BigInteger = curveDomain.P
    private val B: BigInteger = curveDomain.B


    fun BigInteger.hasEvenY(): Boolean = this.mod(BigInteger.TWO) == BigInteger.ZERO

    /**
     * lift_x(x) is equivalent to the following pseudocode:
     *  Fail if x ≥ p.
     *  Let c = x3 + 7 mod p.
     *  Let y = c(p+1)/4 mod p.
     *  Fail if c ≠ y2 mod p.
     * Return the unique point P such that x(P) = x and y(P) = y if y mod 2 = 0 or y(P) = p-y otherwise.
     * */
    private fun evaluatePoint(pubkey: BigInteger): PointField {
        require(pubkey < P) { "The public key must be less than the field size." }

        val c = (pubkey.pow(3) + B) % P

        val y = c.modPow((P + 1.toBigInteger()) / 4.toBigInteger(), P)

        return PointField(
            pubkey,
            if (y.hasEvenY()) y else P - y
        )
    }

    fun lift_x(x: BigInteger): PointField? {
        // Fail if x ≥ p.
        if (x >= P) {
            return null
        }


        val c = x.modPow(BigInteger.valueOf(3), P).add(BigInteger.valueOf(7)).mod(P)
        val yCandidate = c.modPow(P.add(BigInteger.ONE).divide(BigInteger.valueOf(4)), P)

        // Fail if c ≠ y^2 mod P
        if (c != yCandidate.modPow(BigInteger.valueOf(2), P)) {
            return null
        }

        // Calculate y(P)
        val y = if (yCandidate.mod(BigInteger.valueOf(2)) == BigInteger.ZERO) {
            yCandidate
        } else {
            P.subtract(yCandidate)
        }

        return PointField(x, y)
    }


    private fun hashTagged(tag: String, data: ByteArray): ByteArray {
        val tagBytes: ByteArray = tag.SHA256()

        val com = tagBytes.copyOfRange(0, tagBytes.size) + tagBytes.copyOfRange(0, tagBytes.size) + data
        return com.SHA256()
    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    /**
     * The algorithm Sign(sk, m) is defined as:
     * Let d' = int(sk)
     * Fail if d' = 0 or d' ≥ n
     * Let P = d'⋅G
     * Let d = d' if has_even_y(P), otherwise let d = n - d' .
     * Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a)[11].
     * Let rand = hashBIP0340/nonce(t || bytes(P) || m)[12].
     * Let k' = int(rand) mod n[13].
     * Fail if k' = 0.
     * Let R = k'⋅G.
     * Let k = k' if has_even_y(R), otherwise let k = n - k' .
     * Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
     * Let sig = bytes(R) || bytes((k + ed) mod n).
     * If Verify(bytes(P), m, sig) (see below) returns failure, abort[14].
     * Return the signature sig.
     * */


    fun generateAuxRand(): ByteArray {
        while (true) {
            val auxRand = BigInteger(256, SecureRandom()).DeciToHex().HexToByteArray()
            if (auxRand.size == 32) {
                return auxRand
            }
        }
    }


    private fun signWithRetry(
        privateKey: BigInteger,
        message: BigInteger,
    ): Pair<BigInteger, BigInteger> {
        var maxRetries = 20
        while (maxRetries > 0) {
            try {
                return signSchnorr(privateKey, message)
            } catch (e: Exception) {
                maxRetries--
            }
        }
        throw RuntimeException("Failure. This happens only with negligible probability.")
    }


    fun signSchnorr(
        privateKey: BigInteger,
        message: BigInteger
    ): Pair<BigInteger, BigInteger> {
        require(privateKey < N) { "The private key must be less than the curve order." }

        val auxRand = generateAuxRand()
        val auxSize = auxRand.size

        val P: PointField = multiplyPoint(privateKey)

        val d: BigInteger = if (P.y.hasEvenY()) {
            privateKey
        } else {
            N - privateKey
        }

        val t: ByteArray = d.DeciToHex().HexToByteArray() + hashTagged(
            "BIP0340/aux",
            auxRand
        )


        val rand: ByteArray = hashTagged(
            "BIP0340/nonce",
            t + P.x.DeciToHex().HexToByteArray() + message.DeciToHex().HexToByteArray()
        )

        val kPrime = rand.ByteArrayToBigInteger() % N
        if (kPrime == BigInteger.ZERO) {
            throw RuntimeException("Failure. This happens only with negligible probability.")
        }


        val R: PointField = if (multiplyPoint(kPrime).y.hasEvenY()) {
            multiplyPoint(kPrime)
        } else {
            multiplyPoint(N - kPrime)
        }


        val e: BigInteger = hashTagged(
            "BIP0340/challenge",
            R.x.DeciToHex().HexToByteArray() + P.x.DeciToHex().HexToByteArray() + message.DeciToHex().HexToByteArray()
        ).ByteArrayToBigInteger() % N

        val r: BigInteger = R.x
        val s: BigInteger = (kPrime + (e * d)) % N

        val verify: Boolean =
            verifySchnorr(message.DeciToHex().HexToByteArray(), P.x.DeciToHex().HexToByteArray(), Pair(r, s))
        if (!verify && r.toByteArray().size == 32 && s.toByteArray().size == 32) {
            // เริ่มสร้างลายเซ็นใหม่เมื่อการตรวจสอบไม่ผ่าน
            return signWithRetry(privateKey, message)
        }

        return Pair(r, s)

    }

    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    fun sign(
        privateKey: BigInteger,
        message: BigInteger
    ): String {
        val (r, s) = signSchnorr(privateKey, message)
        return r.DeciToHex() + s.DeciToHex()
    }

    fun verify(
        message: ByteArray,
        pubkey: ByteArray,
        signature: String
    ): Boolean {
        require(pubkey.size == 32) { "The public key must be a 32-byte array." }
        require(signature.HexToByteArray().size == 64) { "The signature must be a 64-byte array." }

        val record = signature.length

        // แบ่งครึ่ง String
        val halfLength = record / 2

        val r = signature.substring(0, halfLength).HexToByteArray().ByteArrayToBigInteger()
        val s = signature.substring(halfLength, record).HexToByteArray().ByteArrayToBigInteger()

        return verifySchnorr(message, pubkey, Pair(r, s))
    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    /**
     * The algorithm Verify(pk, m, sig) is defined as:
     *  Let P = lift_x(int(pk)); fail if that fails.
     *  Let r = int(sig[0:32]); fail if r ≥ p.
     *  Let s = int(sig[32:64]); fail if s ≥ n.
     *  Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
     *  Let R = s⋅G - e⋅P.
     *  Fail if is_infinite(R).
     *  Fail if not has_even_y(R).
     *  Fail if x(R) ≠ r.
     * */

    fun verifySchnorr(
        message: ByteArray,
        pubkey: ByteArray,
        signature: Pair<BigInteger, BigInteger>
    ): Boolean {

        val (r, s) = signature

        if (r >= P || s >= N) {
            return false
        }

        val P: PointField? = lift_x(pubkey.ByteArrayToBigInteger())

        //val buf: ByteArray = r.DeciToHex().HexToByteArray() + pubkey + message
        val buf: ByteArray = r.toByteArray() + P!!.x.toString(16).HexToByteArray() + message

        val e: BigInteger = hashTagged("BIP0340/challenge", buf).ByteArrayToBigInteger() % N

        val R: PointField = EllipticCurve.addPoint(
            multiplyPoint(s),
            multiplyPoint(N - e, P)
        )

        return R.y.hasEvenY() && R.x == r
    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


}

fun libVerify(
    data: ByteArray,
    pubKey: ByteArray,
    sig: ByteArray
): Boolean {
    return Secp256k1.verifySchnorr(sig, data, pubKey)
}

fun main() {


    //val privateKey = BigInteger("25fc758699f0d46d177764f79ddd8d76256f0204299a3c5da88f5d12e61ba9c7", 16)

    //val privateKey = BigInteger("1457876265edee2739302ce0996cfc387e00026cc5a87c9f23d571039bc5b904", 16)
    //val privateKey = BigInteger("5328cb703097a064ea27873eb6d1b97232ab096b6e21f6f7afa3684a2e249431", 16)
    val privateKey = generateAuxRand().ByteArrayToBigInteger()
    //val privateKey = BigInteger("aff185dfbd83468d5bb43779c580d517b9ee6b1e59602db91d8ed9d0e865c5c1", 16)


    val message: ByteArray = "I am a fish".SHA256()

    val xValue: ByteArray = privateKey.toPoint().x.DeciToHex().HexToByteArray() // PublicKey x value
    val recover = Schnorr.lift_x(privateKey)
    println("recover: $recover")
    val signature = Schnorr.sign(privateKey, message.ByteArrayToBigInteger())
    //val signature = "304502205c7a11d1f55ac84ed6085830edb781daa098a8ebe08e06c5ce636a7e6e36b14e02210085925ce97dc35463a48122ce22ce3bbb445c54df7586c2354a05593be0db73c1"
    val verify: Boolean = Schnorr.verify(message, xValue, signature)

    println(multiplyPoint(privateKey))
    println(message.ByteArrayToHex())

    println("Private Key: ${privateKey.DeciToHex()} size ${privateKey.DeciToHex().HexToByteArray().size} bytes")
    println("Public Key X: ${privateKey.toPoint().x.toString(16)}")

    println("Signature size ${signature.HexToByteArray().size} bytes: $signature")
    println("my verify: $verify")

    val libver = libVerify(message, xValue, signature.HexToByteArray())
    println("secp256k1-kmp-jni verify: $libver")


//    var num = 1
//    while (true) {
//        val privateKey = generateAuxRand().ByteArrayToBigInteger()
//
//        val message: ByteArray = "I am a fish".SHA256()
//
//        val xValue: ByteArray = privateKey.toPoint().x.DeciToHex().HexToByteArray() // PublicKey x value
//        val signature = Schnorr.sign(privateKey, message.ByteArrayToBigInteger())
//        val verify: Boolean = Schnorr.verify(message, xValue, signature)
//
//        num++
//        if (!verify) {
//            println("\nCount: $num")
//            println(multiplyPoint(privateKey))
//            println("Message: ${message.ByteArrayToHex()}")
//
//            println("Private Key: ${privateKey.DeciToHex()} size ${privateKey.DeciToHex().HexToByteArray().size} bytes")
//            println("Signature size ${signature.HexToByteArray().size} bytes: $signature")
//            println("verify: $verify")
//            break
//        } else {
//            println("Count $num : verify $verify")
//        }
//
//    }


}