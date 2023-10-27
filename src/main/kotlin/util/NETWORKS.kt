package util

import util.ShiftTo.ByteArrayToHex
import java.nio.ByteBuffer
import java.nio.ByteOrder

object NETWORKS {


    val VERSION: Map<Int, Any> = mapOf(
        1 to ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(1).array().ByteArrayToHex(),
        2 to ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(2).array().ByteArrayToHex()
    )

    val MAIN: Map<String, Any> = mapOf(
        "name" to "Mainnet",
        "wif" to byteArrayOf(0x80.toByte()).ByteArrayToHex(),
        "p2pkh" to byteArrayOf(0x00.toByte()).ByteArrayToHex(),
        "p2sh" to byteArrayOf(0x05.toByte()).ByteArrayToHex(),
        "bech32" to "bc",
        "xprv" to byteArrayOf(0x04.toByte(), 0x88.toByte(), 0xad.toByte(), 0xe4.toByte()).ByteArrayToHex(),
        "xpub" to byteArrayOf(0x04.toByte(), 0x88.toByte(), 0xb2.toByte(), 0x1e.toByte()).ByteArrayToHex(),
        "yprv" to byteArrayOf(0x04.toByte(), 0x9d.toByte(), 0x78.toByte(), 0x78.toByte()).ByteArrayToHex(),
        "zprv" to byteArrayOf(0x04.toByte(), 0xb2.toByte(), 0x43.toByte(), 0x0c.toByte()).ByteArrayToHex(),
        "Yprv" to byteArrayOf(0x02.toByte(), 0x95.toByte(), 0xb0.toByte(), 0x05.toByte()).ByteArrayToHex(),
        "Zprv" to byteArrayOf(0x02.toByte(), 0xaa.toByte(), 0x7a.toByte(), 0x99.toByte()).ByteArrayToHex(),
        "ypub" to byteArrayOf(0x04.toByte(), 0x9d.toByte(), 0x7c.toByte(), 0xb2.toByte()).ByteArrayToHex(),
        "zpub" to byteArrayOf(0x04.toByte(), 0xb2.toByte(), 0x47.toByte(), 0x46.toByte()).ByteArrayToHex(),
        "Ypub" to byteArrayOf(0x02.toByte(), 0x95.toByte(), 0xb4.toByte(), 0x3f.toByte()).ByteArrayToHex(),
        "Zpub" to byteArrayOf(0x02.toByte(), 0xaa.toByte(), 0x7e.toByte(), 0xd3.toByte()).ByteArrayToHex(),
        "bip32" to 0 // coin type for bip32 derivation
    )

    val TEST: Map<String, Any> = mapOf(
        "name" to "Testnet",
        "wif" to byteArrayOf(0xEF.toByte()).ByteArrayToHex(),
        "p2pkh" to byteArrayOf(0x6F.toByte()).ByteArrayToHex(),
        "p2sh" to byteArrayOf(0xC4.toByte()).ByteArrayToHex(),
        "bech32" to "tb",
        "xprv" to byteArrayOf(0x04.toByte(), 0x35.toByte(), 0x83.toByte(), 0x94.toByte()).ByteArrayToHex(),
        "xpub" to byteArrayOf(0x04.toByte(), 0x35.toByte(), 0x87.toByte(), 0xcf.toByte()).ByteArrayToHex(),
        "yprv" to byteArrayOf(0x04.toByte(), 0x4a.toByte(), 0x4e.toByte(), 0x28.toByte()).ByteArrayToHex(),
        "zprv" to byteArrayOf(0x04.toByte(), 0x5f.toByte(), 0x18.toByte(), 0xbc.toByte()).ByteArrayToHex(),
        "Yprv" to byteArrayOf(0x02.toByte(), 0x42.toByte(), 0x85.toByte(), 0xb5.toByte()).ByteArrayToHex(),
        "Zprv" to byteArrayOf(0x02.toByte(), 0x57.toByte(), 0x50.toByte(), 0x48.toByte()).ByteArrayToHex(),
        "ypub" to byteArrayOf(0x04.toByte(), 0x4a.toByte(), 0x52.toByte(), 0x62.toByte()).ByteArrayToHex(),
        "zpub" to byteArrayOf(0x04.toByte(), 0x5f.toByte(), 0x1c.toByte(), 0xf6.toByte()).ByteArrayToHex(),
        "Ypub" to byteArrayOf(0x02.toByte(), 0x42.toByte(), 0x89.toByte(), 0xef.toByte()).ByteArrayToHex(),
        "Zpub" to byteArrayOf(0x02.toByte(), 0x57.toByte(), 0x54.toByte(), 0x83.toByte()).ByteArrayToHex(),
        "bip32" to 1
    )

}