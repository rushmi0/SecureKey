package util

import util.ShiftTo.ByteArrayToHex
import util.ShiftTo.HexToByteArray
import java.security.MessageDigest

object Hashing {

    fun ByteArray.doubleSHA256(): ByteArray {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val firstHash = sha256.digest(this)
        return sha256.digest(firstHash)
    }

    fun ByteArray._SHA256(): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(this)
    }

    fun String.SHA256(): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(this.HexToByteArray()).ByteArrayToHex()
    }

    fun ByteArray.SHA256(): String {
        val digest = MessageDigest.getInstance("SHA-256")
        return digest.digest(this).ByteArrayToHex()
    }


}