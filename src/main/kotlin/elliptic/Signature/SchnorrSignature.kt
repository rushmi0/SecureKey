package elliptic.Signature



import elliptic.EllipticCurve
import elliptic.EllipticCurve.multiplyPoint
import elliptic.PointField
import elliptic.Secp256K1
import elliptic.Signature.Schnorr.verifySchnorr
import elliptic.example.sha256
import util.Hashing.SHA256
import util.ShiftTo.ByteArrayToBigInteger
import util.ShiftTo.ByteArrayToHex
import util.ShiftTo.DeciToHex
import util.ShiftTo.HexToByteArray
import java.math.BigInteger
import java.security.MessageDigest
import java.security.SecureRandom


    /*
    * สร้างลายเซ็นและตรวจสอบ Schnorr Signature
    * https://medium.com/bitbees/what-the-heck-is-schnorr-52ef5dba289f
    * */

    // ! Schnorr Signature ยังใช้ไม่ได้

object Schnorr {


    // * Parameters secp256k1
    private val curveDomain: Secp256K1.CurveParams = Secp256K1.getCurveParams()
    private val N: BigInteger = curveDomain.N


    /**
     *
     * Default Signing
     * Input:
     *
     * The secret key sk: a 32-byte array
     * The message m: a byte array
     * Auxiliary random data a: a 32-byte array
     * The algorithm Sign(sk, m) is defined as:
     * Let d' = int(sk)
     * Fail if d' = 0 or d' ≥ n
     * Let P = d'⋅G
     * Let d = d' if has_even_y(P), otherwise let d = n - d' .
     * Let t be the byte-wise xor of bytes(d) and hashBIP0340/aux(a)
     * Let rand = hashBIP0340/nonce(t || bytes(P) || m)[12].
     * Let k' = int(rand) mod n[13].
     * Fail if k' = 0.
     * Let R = k'⋅G.
     * Let k = k' if has_even_y(R), otherwise let k = n - k' .
     * Let e = int(hashBIP0340/challenge(bytes(R) || bytes(P) || m)) mod n.
     * Let sig = bytes(R) || bytes((k + ed) mod n).
     * If Verify(bytes(P), m, sig) (see below) returns failure, abort[14].
     * Return the signature sig.
     *
     * */


    fun sign(privateKey: BigInteger, message: BigInteger): Pair<BigInteger, BigInteger> {

        //val z = BigInteger(256, SecureRandom())
        val z  = BigInteger("110655284954766081346317613323703528534091090228545886155032378548212604540415")
        val R = multiplyPoint(z) // R เป็นคือที่ใช้ในการสร้างลายเซ็น

        val r = R.x % N // พิกัด x ของ R

        val hashInput = r.toByteArray() + multiplyPoint(privateKey).x.toByteArray() + message.toByteArray()
        val hash = hashInput.ByteArrayToHex().SHA256().ByteArrayToHex() // Hash256(r || P || m)

        val k = privateKey
        val s = (z + BigInteger(hash, 16) * k) % N // s = z + Hash256(r || P || m) * k

        return Pair(r, s)
    }



    /**
     *
     * `Verification`
     * Input:
     *  The public key pk: a 32-byte array
     *  The message m: a byte array
     * A signature sig: a 64-byte array
     *
     * The algorithm Verify(pk, m, sig) is defined as:
     *  Let P = lift_x(int(pk)); fail if that fails.
     *  Let r = int(sig[0:32]); fail if r ≥ p.
     *  Let s = int(sig[32:64]); fail if s ≥ n.
     *  Let e = int(hashBIP0340/challenge(bytes(r) || bytes(P) || m)) mod n.
     *  Let R = s⋅G - e⋅P.
     *  Fail if is_infinite(R).
     *  Fail if not has_even_y(R).
     *  Fail if x(R) ≠ r.
     *
     *  Return success iff no failure occurred before reaching this point.
     *
     * */

    private fun hashThis(tag: String, data: ByteArray): ByteArray {
        val tagBytes: ByteArray = tag.SHA256()

        val com = tagBytes.copyOfRange(0, tagBytes.size) + tagBytes.copyOfRange(0, tagBytes.size) + data
        return com.SHA256()
    }


    fun verifySchnorr(
        message: ByteArray,
        pubkey: ByteArray,
        signature: Pair<BigInteger, BigInteger>
    ): Boolean {

        val (r, s) = signature

        if (r >= EllipticCurve.P || s >= EllipticCurve.P) {
            return false
        }

        val P: PointField = evaluatePoint(pubkey.ByteArrayToBigInteger())

        // pX, pY สำหรับ Debug เพื่อดูข้อมูลที่ใช้ในการคำนวณ
        //val pX: BigInteger = P.x
        //val pY: BigInteger = P.y

        val buf: ByteArray = r.DeciToHex().HexToByteArray() + pubkey + message

        val e: BigInteger = hashThis("BIP0340/challenge", buf).ByteArrayToBigInteger() % EllipticCurve.N

        val R: PointField = EllipticCurve.addPoint(
            multiplyPoint(s),
            multiplyPoint(EllipticCurve.N - e, P)
        )

        return R.y.mod(BigInteger.TWO) == BigInteger.ZERO && R.x == r
    }


    private fun evaluatePoint(pubkey: BigInteger): PointField {
        val ySquared = (pubkey.pow(3) + EllipticCurve.B) % EllipticCurve.P

        // หาค่า y โดยใช้ modular square root
        val y = ySquared.modPow((EllipticCurve.P + 1.toBigInteger()) / 4.toBigInteger(), EllipticCurve.P)

        // ถ้า y^2 mod P เท่ากับ ySquared แสดงว่า y ที่หามานั้นถูกต้อง
        return if (y.modPow(2.toBigInteger(), EllipticCurve.P) == ySquared) {
            PointField(pubkey, y)
        } else {
            PointField(pubkey, EllipticCurve.P - y)
        }
    }

}

fun main() {

    val pubkey = BigInteger("54937464590658530654488624268151724241105264383655924818230768164485909069475").toByteArray()

    val message = sha256("I am a fish".toByteArray())


    val sig =
        "a538dd030d1985afede868e1a885bb8153d1c70c8dd6800ac0fd47a0a0c9471f0ee8ed2ae8af02f8167c4e3b4d601a6d5bd60a91ba31f6f5b48ccad1385574d0".HexToByteArray()

    val r: BigInteger = sig.copyOfRange(0, 32).ByteArrayToBigInteger()
    val s: BigInteger = sig.copyOfRange(32, 64).ByteArrayToBigInteger()

    val verify = verifySchnorr(message, pubkey, Pair(r, s))
    println("verify: $verify")

}