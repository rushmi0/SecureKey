package elliptic.example

import elliptic.ECDHkey
import elliptic.ECPublicKey.compressed
import elliptic.ECPublicKey.toPublicKey
import java.math.BigInteger
import java.security.SecureRandom

fun main() {

    // * ตัวอย่างการใช้งาน ECDH (Elliptic Curve Diffie-Hellman)
    val privateKeyA = BigInteger(256, SecureRandom()) // BigInteger("79625421569768853913552101372473036721620627201397836988747447632291648962205")
    val privateKeyB = BigInteger(256, SecureRandom()) // BigInteger("67914844877053552625417144116446677376217396135678097020919636085202412362945")

    println("\nPrivate Key A: $privateKeyA")
    println("Private Key B: $privateKeyB")

    // * สร้าง Public Key จาก Private Key โดยผลลัพธ์ที่ได้จะเป็นพิกัดจุดบนเส้นโค้งวงรี
    val publicKeyA = privateKeyA.toPublicKey().compressed()
    val publicKeyB = privateKeyB.toPublicKey().compressed()

    println("\nPublic Key A: $publicKeyA")
    println("Public Key B: $publicKeyB")

    // * สร้าง Shared Key ระหว่าง 2 ฝ่าย

    // นี้คือทางฝั่ง A ที่จะสร้าง Shared Key ขึ้นมา โดยใช้ Public Key ของ B และ Private Key ของ A
    val sharedKeyA = ECDHkey.sharedSecret(
        publicKeyB,
        privateKeyA
    )

    // นี้คือทางฝั่ง B ที่จะสร้าง Shared Key ขึ้นมา โดยใช้ Public Key ของ A และ Private Key ของ B
    val sharedKeyB = ECDHkey.sharedSecret(
        publicKeyA,
        privateKeyB
    )

    println("\nShared Key A: $sharedKeyA")
    println("Shared Key B: $sharedKeyB")

    // * ตรวจสอบ Shared Key ของทั้ง 2 ฝ่ายว่าเป็นค่าเดียวกันหรือไม่
    val check = sharedKeyA == sharedKeyB
    println("\nShared Key A == Shared Key B: $check")

}