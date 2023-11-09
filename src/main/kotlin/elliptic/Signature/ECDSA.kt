package elliptic.Signature


import elliptic.ECPublicKey.pointRecovery
import elliptic.EllipticCurve.addPoint
import elliptic.EllipticCurve.modinv
import elliptic.EllipticCurve.multiplyPoint
import elliptic.PointField
import elliptic.Secp256K1
import java.math.BigInteger
import java.security.SecureRandom

/*
* สร้างลายเซ็นและตรวจสอบ ECDSA
* */

object ECDSA {


    /*
* https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki
*/

    // * Parameters secp256k1
    private val curveDomain: Secp256K1.CurveParams = Secp256K1.getCurveParams()
    private val N: BigInteger = curveDomain.N


    fun sign() {

    }

    fun verify() {

    }



    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


    // * สร้างลายเซ็น โดยรับค่า private key และ message ที่ต้องการลงลายเซ็น และคืนค่าเป็นคู่ของ BigInteger (r, s)

    fun signECDSA(
        privateKey: BigInteger,
        message: BigInteger
    ): Pair<BigInteger, BigInteger> {
        val m = message
        //val k = BigInteger("42854675228720239947134362876390869888553449708741430898694136287991817016610")

        val k = BigInteger(256, SecureRandom())

        val point: PointField = multiplyPoint(k)

        val kInv: BigInteger = modinv(k, N)

        val r: BigInteger = point.x % N

        var s = (m + r * privateKey) * kInv % N
        // var s: BigInteger = ((m + r * privateKey) * kInv) % N

        // * https://github.com/bitcoin/bips/blob/master/bip-0146.mediawiki
        if (s > N.shiftRight(1)) {
            s = N - s
        }

        return Pair(r, s)
    }

    fun verifyECDSA(
        publicKeyPoint: String,
        message: BigInteger,
        signature: Pair<BigInteger, BigInteger>
    ): Boolean {
        val (r, s) = signature

        val w: BigInteger = modinv(s, N)
        val u1: BigInteger = (message * w) % N
        val u2: BigInteger = (r * w) % N

        val point1: PointField = multiplyPoint(u1)
        val point2: PointField = multiplyPoint(
            u2,
            publicKeyPoint.pointRecovery()
        )

        val point: PointField = addPoint(point1, point2)

        val x: BigInteger = point.x % N

        return x == r
    }


}