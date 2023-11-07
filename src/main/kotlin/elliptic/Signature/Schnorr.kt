package elliptic.Signature



import elliptic.ECPublicKey.evaluatePoint
import elliptic.ECPublicKey.pointRecovery
import elliptic.EllipticCurve
import elliptic.EllipticCurve.multiplyPoint
import elliptic.PointField
import elliptic.Secp256K1
import util.Hashing.SHA256
import util.ShiftTo.ByteArrayToBigInteger
import util.ShiftTo.DeciToHex
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


    private fun hashTagged(data: ByteArray, tag: String? = null): ByteArray {
        val tagBytes: ByteArray = tag?.SHA256() ?: ByteArray(0)

        val com = tagBytes.copyOfRange(0, tagBytes.size) + tagBytes.copyOfRange(0, tagBytes.size) + data
        return com.SHA256()
    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    /**
     * < pseudocode >
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


    private fun generateAuxRand(): ByteArray {
        while (true) {
            val auxRand = BigInteger(256, SecureRandom()).toByteArray()
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
                return sign(privateKey, message)
            } catch (e: Exception) {
                maxRetries--
            }
        }
        throw RuntimeException("Failure. This happens only with negligible probability.")
    }


    fun sign(
        privateKey: BigInteger,
        message: BigInteger,
    ): Pair<BigInteger, BigInteger> {
        require(privateKey < N) { "The private key must be less than the curve order." }
        //require(maxRetries > 20) { "Max retries should be greater than 20." }

        val auxRand = generateAuxRand()

        val P: PointField = multiplyPoint(privateKey)

        val d: BigInteger = if (P.y.hasEvenY()) {
            privateKey
        } else {
            N - privateKey
        }

        val t: ByteArray = d.toByteArray() + hashTagged(
            auxRand,
            "BIP0340/aux"
        )
        
        val rand: ByteArray = hashTagged(
            t + P.x.toByteArray() + message.toByteArray(),
            "BIP0340/nonce"
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
            R.x.toByteArray() + P.x.toByteArray() + message.toByteArray(),
            "BIP0340/challenge"
        ).ByteArrayToBigInteger() % N


        val r: BigInteger = R.x
        val s: BigInteger = (kPrime + (e * d)) % N

        val verify: Boolean = verify(
            P.x.DeciToHex(), // ข้อความที่จะเซ็น
            message.toByteArray(), // ค่า x จาก public key
            Pair(r, s) // ลายเซ็น
        )

//        if (!verify) {
//            // เริ่มสร้างลายเซ็นใหม่เมื่อการตรวจสอบไม่ผ่าน
//            return signWithRetry(privateKey, message)
//        }

        return Pair(r, s)

    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    /**
     * < pseudocode >
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


    fun verify(
        pubkey: String,
        message: ByteArray,
        signature: Pair<BigInteger, BigInteger>
    ): Boolean {
        val (r, s) = signature

        if (r >= P || s >= N) {
            return false
        }

        val P: PointField = pubkey.pointRecovery() ?: return false

        val e: BigInteger = hashTagged(
            r.toByteArray() + pubkey.toByteArray() + message,
            "BIP0340/challenge"
        ).ByteArrayToBigInteger() % N

        val R: PointField = EllipticCurve.addPoint(
            multiplyPoint(s),
            multiplyPoint(N - e, P)
        )

        return R.y.hasEvenY() && R.x == r
    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


}
