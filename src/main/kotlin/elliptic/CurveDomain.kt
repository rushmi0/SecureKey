package elliptic


import java.math.BigInteger

class CurveDomain(name: String) {

    // < https://www.secg.org/sec2-v2.pdf >

    val params = when (name) {


        // มีขนาด Public Key Bytes ทั้งหมด 64 Bytes
        "secp192k1" -> {
            val A = BigInteger.ZERO
            val B = BigInteger.valueOf(3)
            val P = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37", 16)
            val N = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D", 16)
            val H = BigInteger.ONE

            val G = PointField(
                BigInteger("DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D", 16),
                BigInteger("9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D", 16)
            )
            ParametersField(A, B, P, N, G, H)
        }


        // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


        "secp192r1" -> {
            val A = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC", 16)
            val B = BigInteger("64210519E59C80E70FA7E9AB72243049FEB8DEECC146B9B1", 16)
            val P = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF", 16)
            val N = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831", 16)
            val H = BigInteger.ONE
            val G = PointField(
                BigInteger("188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF1012", 16),
                BigInteger("07192B95FFC8DA78631011ED6B24CDD573F977A11E794811", 16)
            )
            ParametersField(A, B, P, N, G, H)
        }


        // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


        "secp256k1" -> {
            val A = BigInteger.ZERO
            val B = BigInteger.valueOf(7)
            val P = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
            val N = BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
            val H = BigInteger.ONE
            val G = PointField(
                BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16),
                BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
            )
            ParametersField(A, B, P, N, G, H)
        }


        // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


        else -> throw IllegalArgumentException("Invalid curve name")
    }
}


fun main() {

    val curve = CurveDomain("secp256k1").params
    //val curve = CurveDomain("secp192k1").params
    println(curve.A)
    println(curve.B)
    println(curve.P)
    println(curve.N)
    println(curve.G)
}
