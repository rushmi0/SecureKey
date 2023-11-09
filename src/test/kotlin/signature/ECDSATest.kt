package signature

import ECPublicKeyTest
import elliptic.Signature.ECDSA
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import util.Hashing.SHA256
import util.ShiftTo.ByteArrayToBigInteger
import util.ShiftTo.ByteArrayToHex
import util.ShiftTo.DeciToHex
import java.math.BigInteger

class ECDSATest : ECPublicKeyTest() {


    @Test
    fun testSigAndVerifyWithECDSA() {

        val message = BigInteger("Hello World".SHA256().ByteArrayToHex(), 16)

        val signature = ECDSA.signECDSA(privateKey, message)

        val verify = ECDSA.verifyECDSA(publicKeyCompressed, message, signature)

        Assertions.assertTrue(verify)

//        println("Private Key hex ${privateKey.toByteArray().size} bytes: ${privateKey.DeciToHex()}")
//        println("signature: \n s : ${signature.first.DeciToHex()} ${signature.first.toByteArray().size} Bytes \n r : ${signature.second.DeciToHex()} ${signature.second.toByteArray().size} Bytes")
//        println("verify: $verify")
    }


}