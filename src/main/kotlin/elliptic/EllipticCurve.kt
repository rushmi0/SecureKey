package elliptic


import java.math.BigInteger
/*
* อ้างอิงจาก
* https://github.com/wobine/blackboard101/blob/master/EllipticCurvesPart5-TheMagic-SigningAndVerifying.py
* https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc
*
* < Elliptic Curve Cryptography >
* */

object EllipticCurve {

    // * กำหนดค่าพื้นฐานของเส้นโค้งวงรี โดยใส่ชื่อเส้นโค้งวงรีที่ต้องการใช้งาน
    val curve = CurveDomain("secp256k1").params

    // * ค่า A, B, P, G ที่ใช้ในการคำนวณ
    val A: BigInteger = curve.A
    val B: BigInteger = curve.B
    val P: BigInteger = curve.P
    val G: PointField = curve.G


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\

    /*
    * `isPointOnCurve` Metd นี้ใช้เพื่อตรวจสอบว่าจุดที่รับเข้ามานั้นอยู่บนเส้นโค้งวงรีหรือไม่
    * โดยการรับค่า point เพื่อนำไปคำนวณตามสมการเส้นโค้งวงรี และตรวจสอบว่าสมการที่ได้มีค่าเท่ากันหรือไม่ และจะคืนค่าเป็น true หากสมการมีค่าเท่ากัน
    * */
    fun isPointOnCurve(point: PointField?): Boolean {
        val (x, y) = point
        // ! ถ้าค่า point ที่รับเข้ามาเป็น null ให้ส่งค่า Exception กลับไป
            ?: throw IllegalArgumentException("`isPointOnCurve` Method Point is null")

        // * ตรวจสอบว่าจุดนั้นเป็นไปตามสมการเส้นโค้งวงรี หรือไม่: y^2 = x^3 + Ax + B (mod P)
        val leftSide = (y * y) % P // leftSide เป็นค่า y^2 และรนำไป mod P
        val rightSide = (x.pow(3) + A * x + B) % P // rightSide เป็นค่า x^3 + Ax + B และรนำไป mod P

        return leftSide == rightSide
    }

    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\

    /*
    * Function สำหรับคำนวณ modular inverse
    * https://www.dcode.fr/modular-inverse
    * */
    fun modinv(A: BigInteger, N: BigInteger = P) = A.modInverse(N)


    fun doublePoint(point: PointField?): PointField {

        // * ทำการแยกพิกัด x และ y ออกมาจาก `point` ลักษณะข้อมูลของ พิกัด x และ y จะเป็นค่า BigInteger เลขฐาน 10 เพื่อใช้ในการคำนวณต่อไป
        val (x, y) = point
        // ! ถ้าค่า point ที่รับเข้ามาเป็น null ให้ส่งค่า Exception กลับไป
            ?: throw IllegalArgumentException("`doublePoint` Method Point is null")

        // * คำนวณค่า slope ด้วยสูตร (3 * x^2 + A) * (2 * y)^-1 mod P
        val slope = (BigInteger.valueOf(3) * x * x + A) % P

        // *  คำนวณค่า lam_denom = (2 * y) mod P
        val lam_denom = (BigInteger.valueOf(2) * y) % P

        // * คำนวณค่า lam = slope * (lam_denom)^-1 mod P
        val lam = (slope * modinv(lam_denom)) % P

        // * คำนวณค่า xR = (lam^2 - 2 * x) mod P
        val xR = (lam * lam - BigInteger.valueOf(2) * x) % P


        /*
        * < จุดใหม่ที่ได้หลังจากการคูณด้วย 2 บนเส้นโค้งวงรี >
        *  คำนวณค่า yR = (lam * (x - xR) - y) mod P เป็นส่วนที่คำนวณหาค่า y  ของจุดใหม่หลังจากการคูณด้วย 2 บนเส้นโค้งวงรี
        *
        *  lam   คือค่าเอียงของเส้นที่ผ่านจุดเดิมและจุดใหม่หลังจากการคูณด้วย 2 บนเส้นโค้งวงรี
        *  x      คือค่า x ของจุดเดิม
        *  xR    คือค่า x ของจุดใหม่หลังจากการคูณด้วย 2 บนเส้นโค้งวงรี
        *  y     คือค่า y ของจุดเดิม
        *
        * นำค่าเหล่านี้มาใช้เพื่อหาค่า yR ใหม่ที่ถูกปรับเพิ่มหรือลดจากค่า y ของจุดเดิม โดยการคูณ lam กับผลต่างระหว่าง x และ xR
        * */
        val yR = (lam * (x - xR) - y) % P

        return PointField(xR, (yR + P) % P)
    }


    fun addPoint(
        point1: PointField, point2: PointField
    ): PointField {
        if (point1 == point2) {
            return doublePoint(point1)
        }

        // * ทำการแยกพิกัด x และ y ออกมาจาก `point1, point2` ลักษณะข้อมูลของ พิกัด x และ y จะเป็นค่า BigInteger เลขฐาน 10 เพื่อใช้ในการคำนวณต่อไป
        val (x1, y1) = point1
        val (x2, y2) = point2

        // * คำนวณค่า slope ด้วยสูตร (y2 - y1) * (x2 - x1)^-1 mod P เพื่อใช้หาค่าความเอียงของเส้นที่ผ่านจุด point1 และ point2
        val slope = ((y2 - y1) * modinv(x2 - x1)) % P

        // * คำนวณหาค่า `x` ซึ้งมาจากสมการ `slope^2 - x1 - x2 mod P` โดยค่า `x` นั้นจะเป็นค่าที่เป็นจำนวนเต็มเท่านั้น
        val x = (slope * slope - x1 - x2) % P

        // * คำนวณหาค่า `y` ซึ้งมาจากสมการ `slope * (x1 - x) - y1 mod P` โดยค่า `y` นั้นจะเป็นค่าที่เป็นจำนวนเต็มเท่านั้น
        val y = (slope * (x1 - x) - y1) % P

        // ! จัดการพิกัด Y ที่เป็นค่าลบ
        val yResult = if (y < A) y + P else y // * เงื่อนไขแรก ถ้า y น้อยกว่า A ให้บวก P เข้าไปเพื่อให้ค่า y เป็นบวก

        return PointField(x, yResult)
    }


    /**
     * `multiplyPoint` Method ใช้สำหรับคำนวณค่าจุดหลังการคูณด้วยจำนวนเต็มบนเส้นโค้งวงรี
     * หรือก็คือเป็นการสร้าง Public Key จาก Private Key
     * */
    fun multiplyPoint(
        k: BigInteger,
        point: PointField? = null
    ): PointField {

        try {
            // * ตัวแปร current ถูกกำหนดให้เป็น point ที่รับเข้ามา หากไม่มีการระบุ point ค่าเริ่มต้นจะเป็นจุด G ที่ใช้ในการคูณเช่นกับ private key
            val current: PointField = point ?: G

            // * แปลงจำนวนเต็ม k เป็นเลขฐานสอง
            val binary = k.toString(2)

            // * เริ่มต้นด้วยจุดเริ่มต้นปัจจุบัน
            var currentPoint = current

            // * วนลูปตามจำนวน binary digits ของ k
            for (i in 1 until binary.length) {
                currentPoint = doublePoint(currentPoint)

                // * ถ้า binary digit ที่ตำแหน่ง i เป็น '1'  ให้บวกจุดเริ่มต้น (current) เข้ากับจุดปัจจุบัน (currentPoint)
                if (binary[i] == '1') {
                    currentPoint = addPoint(currentPoint, current)
                }
            }
            // * ส่งคืนจุดที่คำนวณได้
            return currentPoint
        } catch (e: Exception) {
            e.printStackTrace()
            // ในกรณีที่เกิด Exception ให้ส่งคืนค่าที่เหมาะสม เช่น null หรือ PointField ว่าง
            return null!!
        }

    }


    // �� ──────────────────────────────────────────────────────────────────────────────────────── �� \\


}