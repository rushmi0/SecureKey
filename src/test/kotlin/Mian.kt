package elliptic.example


import elliptic.EllipticCurve.addPoint
import elliptic.EllipticCurve.multiplyPoint
import elliptic.PointField
import util.Hashing.SHA256
import util.ShiftTo.ByteArrayToBigInteger
import util.ShiftTo.HexToByteArray
import java.math.BigInteger


// �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\

// secp256k1
val A = BigInteger.ZERO
val B = BigInteger.valueOf(7)
val P = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
val N = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
val H = BigInteger.ONE
val G = PointField(
    BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
    BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
)

// �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


fun hashThis(tag: String, data: ByteArray): ByteArray {
    val tagBytes: ByteArray = tag.SHA256()

    val com = tagBytes.copyOfRange(0, tagBytes.size) + tagBytes.copyOfRange(0, tagBytes.size) + data
    return com.SHA256()
}


fun verify(
    message: ByteArray,
    pubkey: ByteArray,
    signature: Pair<BigInteger, BigInteger>
): Boolean {

    val (r, s) = signature

    if (r >= P || s >= P) {
        return false
    }

    val P = evaluatePoint(pubkey.ByteArrayToBigInteger())

    val buf = r.toByteArray() + pubkey + message

    val e = hashThis("BIP0340/challenge", buf).ByteArrayToBigInteger() % N

    val R = addPoint(
        multiplyPoint(s),
        multiplyPoint(N - e, P)
    )

    return R.y.mod(BigInteger.TWO) == BigInteger.ZERO && R.x == r
}


fun evaluatePoint(pubkey: BigInteger): PointField {
    val ySquared = (pubkey.pow(3) + B) % P

    // หาค่า y โดยใช้ modular square root
    val y = ySquared.modPow((P + 1.toBigInteger()) / 4.toBigInteger(), P)

    // ถ้า y^2 mod P เท่ากับ ySquared แสดงว่า y ที่หามานั้นถูกต้อง
    return if (y.modPow(2.toBigInteger(), P) == ySquared) {
        PointField(pubkey, y)
    } else {
        PointField(pubkey, P - y)
    }
}


fun main() {

    val pubkey = BigInteger("54937464590658530654488624268151724241105264383655924818230768164485909069475").toByteArray()

    val message = sha256("I am a fish".toByteArray())


    val sig =
        "a538dd030d1985afede868e1a885bb8153d1c70c8dd6800ac0fd47a0a0c9471f0ee8ed2ae8af02f8167c4e3b4d601a6d5bd60a91ba31f6f5b48ccad1385574d0".HexToByteArray()

    val tx = evaluatePoint(pubkey.ByteArrayToBigInteger())
    println(tx.y)
    println("69189577718294475764016648675070143388750778154222602670589620281384266822858")

    val r: BigInteger = sig.copyOfRange(0, 32).ByteArrayToBigInteger()
    val s: BigInteger = sig.copyOfRange(32, 64).ByteArrayToBigInteger()

    val verify = verify(message, pubkey, Pair(r, s))
    println("verify: $verify")

}