package util


import java.math.BigInteger
import java.util.*

object ShiftTo {

    private val HEX_ARRAY: CharArray = "0123456789abcdef".toCharArray()
    private val hexDigits: String = "0123456789abcdef"


    fun String.HexToBinary(): String {
        val stringBuilder = StringBuilder(length * 4)

        for (hexChar in this) {
            val decimalValue = hexDigits.indexOf(hexChar)
            val binaryChunk = decimalValue.toString(2).padStart(4, '0')
            stringBuilder.append(binaryChunk)
        }

        return stringBuilder.toString()
    }


    fun String.BinaryToHex(): String {
        require(length % 4 == 0) { "Invalid binary string length" }

        val stringBuilder = StringBuilder(length / 4)
        for (i in 0 until length step 4) {
            val binarySegment = substring(i, i + 4)
            val decimalValue = binarySegment.toInt(2)
            val hexDigit = decimalValue.toString(16)
            stringBuilder.append(hexDigit)
        }
        return stringBuilder.toString()
    }

    fun ByteArray.ByteArrayToBigInteger(): BigInteger {
        return BigInteger(1, this)
    }


    fun String.BinaryToByteArray(): ByteArray {
        return this.chunked(8).map { it.toInt(2).toByte() }.toByteArray()
    }

    fun ByteArray.ByteArrayToBinary(): String {
        return joinToString("") { byte -> byte.toUByte().toString(2).padStart(8, '0') }
    }

    fun ByteArray.ByteArrayToHex(): String {
        return joinToString("") { byte -> byte.toUByte().toString(16).padStart(2, '0') }
    }



    fun BigInteger.DeciToHex(): String {
        var number = this
        val result = StringBuilder()

        if (number == BigInteger.ZERO) {
            return "0"
        }

        while (number > BigInteger.ZERO) {
            val remainder = number % BigInteger.valueOf(16)
            result.insert(0, hexDigits[remainder.toInt()])
            number /= BigInteger.valueOf(16)
        }

        return result.toString()
    }


    fun BigInteger.DeciToBin(): String {
        var decimalValue = this
        var binaryResult = ""

        if (decimalValue == BigInteger.ZERO) {
            return "0"
        }

        while (decimalValue > BigInteger.ZERO) {
            val remainder = decimalValue % BigInteger.valueOf(2)
            binaryResult = remainder.toString() + binaryResult
            decimalValue /= BigInteger.valueOf(2)
        }

        return binaryResult
    }




    fun Int.DeciToByte(): ByteArray {
        val bytes = ByteArray(4)
        bytes[0] = (this shr 24 and 0xFF).toByte()
        bytes[1] = (this shr 16 and 0xFF).toByte()
        bytes[2] = (this shr 8 and 0xFF).toByte()
        bytes[3] = (this and 0xFF).toByte()
        return bytes
    }


    fun Long.DeciToByte(): ByteArray {
        val bytes = ByteArray(8)
        bytes[0] = (this shr 56 and 0xFF).toByte()
        bytes[1] = (this shr 48 and 0xFF).toByte()
        bytes[2] = (this shr 40 and 0xFF).toByte()
        bytes[3] = (this shr 32 and 0xFF).toByte()
        bytes[4] = (this shr 24 and 0xFF).toByte()
        bytes[5] = (this shr 16 and 0xFF).toByte()
        bytes[6] = (this shr 8 and 0xFF).toByte()
        bytes[7] = (this and 0xFF).toByte()
        return bytes
    }


    fun Int.DeciToHex(): String {
        var number = this
        val result = StringBuilder()

        if (number == 0) {
            return "0"
        }

        while (number > 0) {
            val remainder = number % 16
            result.insert(0, hexDigits[remainder])
            number /= 16
        }
        return result.toString()
    }


    fun Byte.ByteToHex(): String {
        val hex = CharArray(2)
        hex[0] = hexDigits[(this.toInt() shr 4) and 0x0f]
        hex[1] = hexDigits[this.toInt() and 0x0f]
        return String(hex)
    }


    fun ByteArray.ByteArrayToList(): List<Int> {
        val integers = mutableListOf<Int>()
        for (i in this.indices) {
            integers.add(this[i].toInt() and 0xff)
        }
        return integers
    }


    fun Int.DeciToHexByte(): String {
        return "%02X".format(this)
    }


    fun String.FlipByteOrder(): String {
        return this.chunked(2).reversed().joinToString("")
    }


    fun String.HexToByteArray(): ByteArray = ByteArray(this.length / 2) { this.substring(it * 2, it * 2 + 2).toInt(16).toByte() }

    /*
    fun String.HexToByteArray(): ByteArray {
        val hex = this.replace("", "")
        val byteArray = ByteArray(hex.length / 2)
        for (i in byteArray.indices) {
            byteArray[i] = hex.substring(2 * i, 2 * i + 2).toInt(16).toByte()
        }
        return byteArray
    }*/

    /*
    fun String.HexToByteArray(): ByteArray {
        val len = this.length
        val buf = ByteArray(len / 2)
        for (i in 0 until len step 2) {
            buf[i / 2] = ((this[i].digitToInt(16) shl 4) + this[i + 1].digitToInt(16)).toByte()
        }
        return buf
    }
     */

    fun String.littleEndianToDeci(): Long {
        var result: Long = 0
        var multiplier: Long = 1

        val bytes = this.HexToByteArray()
        for (element in bytes) {
            val byteValue: Long = element.toLong() and 0xFF
            result += byteValue * multiplier
            multiplier *= 256
        }
        return result
    }


    fun String.splitHexData(): List<String> {
        val result = mutableListOf<String>()

        for (i in indices step 2) {
            val hex = this.substring(i, i + 2)
            result.add(hex)
        }

        return result
    }


    fun String.decodeBase58(): String {
        return Base58.decode(this).ByteArrayToHex()
    }

    fun String.encodeBase58(): String {
        return Base58.encode(this.HexToByteArray())
    }

    fun String.encodeBase64(): String {
        return Base64.getEncoder().encodeToString(this.HexToByteArray())
    }

    fun String.decodeBase64(): String {
        return Base64.getDecoder().decode(this).ByteArrayToHex()
    }



}