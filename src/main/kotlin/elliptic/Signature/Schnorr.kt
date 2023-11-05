package elliptic.Signature


import elliptic.ECPublicKey.toPoint
import elliptic.EllipticCurve
import elliptic.EllipticCurve.multiplyPoint
import elliptic.PointField
import elliptic.Secp256K1
import util.Hashing.SHA256
import util.ShiftTo.ByteArrayToBigInteger
import util.ShiftTo.ByteArrayToHex
import util.ShiftTo.DeciToBin
import util.ShiftTo.DeciToHex
import util.ShiftTo.HexToByteArray
import java.math.BigInteger
import java.security.SecureRandom


/*
* สร้างลายเซ็นและตรวจสอบ Schnorr Signature
* https://medium.com/bitbees/what-the-heck-is-schnorr-52ef5dba289f
* https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki#user-content-Public_Key_Generation
* */

// ! Schnorr Signature ยังใช้ไม่ได้

object Schnorr {


    // * Parameters secp256k1
    private val curveDomain: Secp256K1.CurveParams = Secp256K1.getCurveParams()
    private val N: BigInteger = curveDomain.N
    private val P: BigInteger = curveDomain.P
    private val B: BigInteger = curveDomain.B




    private fun BigInteger.hasEvenY(): Boolean = this.mod(BigInteger.TWO) == BigInteger.ZERO

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
            if (y.mod(BigInteger.TWO) == BigInteger.ZERO) y else P - y
        )
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


    fun sign(
        privateKey: BigInteger,
        message: BigInteger
    ): String {
        require(privateKey < N) { "The private key must be less than the curve order." }

        //val nonce = BigInteger(256, SecureRandom())

        val P: PointField = multiplyPoint(privateKey)

        val d: BigInteger = if (P.y.hasEvenY()) {
            privateKey
        } else {
            N - privateKey
        }

        val t: ByteArray = d.DeciToHex().HexToByteArray() + hashTagged("BIP0340/aux", privateKey.DeciToHex().HexToByteArray())

        val set1 = t + P.x.DeciToHex().HexToByteArray() + message.DeciToBin().HexToByteArray()

        val rand: ByteArray = hashTagged("BIP0340/nonce", set1)

        val kPrime = rand.ByteArrayToBigInteger() % N

        if (kPrime == BigInteger.ZERO) {
            sign(privateKey, message)
        }

        val R: PointField = if (multiplyPoint(kPrime).y.hasEvenY()) {
            multiplyPoint(kPrime)
        } else {
            multiplyPoint(N - kPrime)
        }

        val set2: ByteArray = R.x.DeciToHex().HexToByteArray() + P.x.DeciToHex().HexToByteArray() + message.DeciToBin().HexToByteArray()

        val e: BigInteger = hashTagged("BIP0340/challenge", set2).ByteArrayToBigInteger() % N

        val sig: ByteArray = R.x.DeciToHex().HexToByteArray() + ((kPrime + (e * d)) % N).DeciToHex().HexToByteArray()

        return sig.ByteArrayToHex()

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


    fun verify(
        message: ByteArray,
        pubkey: ByteArray,
        signature: Pair<BigInteger, BigInteger>
    ): Boolean {

        val (r, s) = signature

        if (r >= P || s >= N) {
            return false
        }

        val P: PointField = evaluatePoint(pubkey.ByteArrayToBigInteger())

        val buf: ByteArray = r.DeciToHex().HexToByteArray() + pubkey + message

        val e: BigInteger = hashTagged("BIP0340/challenge", buf).ByteArrayToBigInteger() % N

        val R: PointField = EllipticCurve.addPoint(
            multiplyPoint(s),
            multiplyPoint(N - e, P)
        )

        return R.y.hasEvenY() && R.x == r
    }



    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


}


fun main() {

    val privateKey = BigInteger(256, SecureRandom())
//    val privateKey =
//        BigInteger("83815085818061553551680724484383113567819967948708730975173007970516951616417")

    val message: ByteArray = "I am a fish".SHA256()

    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\

    // ! TEST: Schnorr sign [failed]

    val signature: String = Schnorr.sign(privateKey, message.ByteArrayToBigInteger())
    println("Signature size ${signature.HexToByteArray().size} bytes: $signature")

    val xValue: ByteArray = privateKey.toPoint().x.DeciToHex().HexToByteArray() // PublicKey x value

    val r: BigInteger = signature.HexToByteArray().copyOfRange(0, 32).ByteArrayToBigInteger()
    val s: BigInteger = signature.HexToByteArray().copyOfRange(32, 64).ByteArrayToBigInteger()

    println("r: ${r.DeciToHex().HexToByteArray().size} ${r.DeciToHex()}")
    println("s: ${s.DeciToHex().HexToByteArray().size} ${s.DeciToHex()}")

    val verify: Boolean = Schnorr.verify(message, xValue, Pair(r, s))
    println("verify: $verify")


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\

    // ! TEST: Schnorr verify [success]

//    val pubkey =
//        BigInteger("54937464590658530654488624268151724241105264383655924818230768164485909069475").toByteArray()
//    val sig = "a538dd030d1985afede868e1a885bb8153d1c70c8dd6800ac0fd47a0a0c9471f0ee8ed2ae8af02f8167c4e3b4d601a6d5bd60a91ba31f6f5b48ccad1385574d0".HexToByteArray()
//    val data = "a538dd030d1985afede868e1a885bb8153d1c70c8dd6800ac0fd47a0a0c9471f0ee8ed2ae8af02f8167c4e3b4d601a6d5bd60a91ba31f6f5b48ccad1385574d0"
//    println("sig: ${data.length}")
//
//    val r: BigInteger = sig.copyOfRange(0, 32).ByteArrayToBigInteger()
//    val s: BigInteger = sig.copyOfRange(32, 64).ByteArrayToBigInteger()
//
//    val verify = Schnorr.verify(message, pubkey, Pair(r, s))
//    println("verify: $verify")

}