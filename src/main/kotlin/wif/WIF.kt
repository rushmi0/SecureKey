package wif

import util.NETWORKS
import util.ShiftTo.ByteArrayToHex
import util.ShiftTo.HexToByteArray
import util.ShiftTo.decodeBase58
import util.ShiftTo.encodeBase58
import java.security.MessageDigest

object WIF {

    private val CHAIN = NETWORKS

    private fun privateKeyToWIF_U(network: String, privateKeyHex: String): String {

        /*
         *
         *  ฟังก์ชั่น privateKeyToWIF_U
         *     ├──  รับค่า Hash sha256  ::  <- 9454a5235cf34e382d7e927eb5709dc4f4ed08eed177cb3f2d4ea359071962d7
         *          └──  ผลลัพธ์ WIF Key  ::  -> 5JwcVJQfQbzAfXnMYQXzLjzczGi22v8BvyyHkUBTmYwN7Z3Qswa
         *
         */

        // * แปลง Private Key จากเลขฐานสิบหกเป็นอาร์เรย์ไบต์
        val privateKeyBytes = privateKeyHex.HexToByteArray()

        // * เมื่อตรวจสอบค่า network และสร้าง WIF Key ตาม network นั้น
        val prefix: ByteArray = when (network) {
            "main" -> {

                // * ดึงคำนำหน้า WIF สำหรับเครือข่าย "main" -> 0x80
                CHAIN.MAIN["wif"].toString().HexToByteArray()
            }

            "test" -> {

                // * ดึงคำนำหน้า WIF สำหรับเครือข่าย "test" -> 0xEF
                CHAIN.TEST["wif"].toString().HexToByteArray()
            }

            else -> {

                // ! แจ้งเตือนข้อผิดพลาดในกรณีที่ network ไม่ถูกต้อง
                return throw IllegalArgumentException("Invalid network")
            }
        }

        // * รวมคำนำหน้าและไบต์ของคีย์ส่วนตัวเข้าด้วยกัน
        val extendedKey = prefix + privateKeyBytes

        // * คำนวณเช็คซัม
        val checksum = extendedKey.getChecksum()

        // * รวมคีย์ที่ถูกขยายและเช็คซัมเข้าด้วยกัน
        val wifBytes = extendedKey + checksum

        // * แปลงอาร์เรย์ของไบต์ที่รวมกันเป็นสตริงฐานสิบหกและเข้ารหัสใน Base58
        return wifBytes.ByteArrayToHex().encodeBase58()
    }


    private fun privateKeyToWIF_C(network: String, privateKeyHex: String): String {

        /*
         *
         *  ฟังก์ชั่น privateKeyToWIF_C
         *     ├──  รับค่า Hash sha256  ::  <- 9454a5235cf34e382d7e927eb5709dc4f4ed08eed177cb3f2d4ea359071962d7
         *          └──  ผลลัพธ์ WIF Key  ::  -> L2C3duqSXBRKf4sBfcsn68mKqnL3ZTUjFGTSvryB9dxxBche5CNY
         *
         */

        // * แปลง Private Key จากเลขฐานสิบหกเป็นอาร์เรย์ไบต์
        val privateKeyBytes = privateKeyHex.HexToByteArray()

        // * เมื่อตรวจสอบค่า network และสร้าง WIF Key ตาม network นั้น
        val prefix: ByteArray = when (network) {
            "main" -> {

                // * ดึงคำนำหน้า WIF สำหรับเครือข่าย "main" -> 0x80
                CHAIN.MAIN["wif"].toString().HexToByteArray()
            }

            "test" -> {

                // * ดึงคำนำหน้า WIF สำหรับเครือข่าย "test" -> 0xEF
                CHAIN.TEST["wif"].toString().HexToByteArray()
            }

            else -> {

                // ! แจ้งเตือนข้อผิดพลาดในกรณีที่ network ไม่ถูกต้อง
                return throw IllegalArgumentException("Invalid network")
            }
        }

        // * สร้างอาร์เรย์ของไบต์ที่แทนค่าเพิ่มเติมสำหรับการบีบอัด
        val compressed = byteArrayOf(0x01.toByte())

        // * รวมคำนำหน้า, ไบต์ของคีย์ส่วนตัว, และค่าเพิ่มเติมสำหรับการบีบอัดเข้าด้วยกัน
        val extendedKey = prefix + privateKeyBytes + compressed

        // * คำนวณเช็คซัม
        val checksum = extendedKey.getChecksum()

        // * รวมคีย์ที่ถูกขยายและเช็คซัมเข้าด้วยกัน
        val wifBytes = extendedKey + checksum

        // * แปลงอาร์เรย์ของไบต์ที่รวมกันเป็นสตริงฐานสิบหกและเข้ารหัสใน Base58
        return wifBytes.ByteArrayToHex().encodeBase58()
    }

    // ──────────────────────────────────────────────────────────────────────────────────────── \\

    // * แปลงเลขฐานสิบหก (Private Key) ให้อยู่ในรูป WIF
    fun String.toWIF(network: String, option: Boolean): String {
        return if (option) {
            privateKeyToWIF_C(network, this)
        } else {
            privateKeyToWIF_U(network, this)
        }
    }

    // * แกะ WIF Key และเก็บเอาเฉพาะค่าคีย์ (Private Key) ที่ค้องการ
    fun String.extractWIF(): String {
        val data = this.decodeBase58().HexToByteArray()
        return data.copyOfRange(1, 33).ByteArrayToHex()
    }

    // ทำการ Hash ข้อมูล 2ครั้ง ด้วย SHA-256
    fun ByteArray.getChecksum(): ByteArray {
        val sha256 = MessageDigest.getInstance("SHA-256")
        val firstSHA256 = sha256.digest(this)
        val secondSHA256 = sha256.digest(firstSHA256)
        return secondSHA256.sliceArray(0..< 4)
    }

}