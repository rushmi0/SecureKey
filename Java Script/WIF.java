import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;


public class WIF {

    public static String Private_to_WIF(String privateKeyHex) throws Exception {

        /*
         *
         *  ฟังก์ชั่น Private_to_WIF_compressed
         *     ├──  รับค่า Hash sha256  ::  <- 9454a5235cf34e382d7e927eb5709dc4f4ed08eed177cb3f2d4ea359071962d7
         *          └──  ผลลัพธ์ WIF Key  ::  -> 5JwcVJQfQbzAfXnMYQXzLjzczGi22v8BvyyHkUBTmYwN7Z3Qswa
         *
         */

        byte[] privateKeyBytes = hexString_To_ByteArray(privateKeyHex);
        byte[] prefix = new byte[] { (byte) 0x80 };

        byte[] extendedKey = concat_2item(prefix, privateKeyBytes);
        byte[] sha256 = hash_sha256(extendedKey);
        byte[] checksum = Arrays.copyOfRange(sha256, 0, 4);

        byte[] wifBytes = concat_2item(extendedKey, checksum);
        String WIF_KEY = Base58.encode(wifBytes);
        return  WIF_KEY;
    }





    public static String Private_To_WIF_Compressed(String privateKeyHex) throws Exception {

        /*
         *
         *  ฟังก์ชั่น Private_to_WIF_compressed
         *     ├──  รับค่า Hash sha256  ::  <- 9454a5235cf34e382d7e927eb5709dc4f4ed08eed177cb3f2d4ea359071962d7
         *          └──  ผลลัพธ์ WIF Key  ::  -> L2C3duqSXBRKf4sBfcsn68mKqnL3ZTUjFGTSvryB9dxxBche5CNY
         *
         */

        byte[] privateKeyBytes = hexString_To_ByteArray(privateKeyHex);
        byte[] prefix = new byte[] { (byte) 0x80 };
        byte[] compressed = new byte[] { (byte) 0x01 };

        byte[] extendedKey = concat_2item(prefix, privateKeyBytes);
        byte[] sha256 = hash_sha256(extendedKey);
        byte[] checksum = Arrays.copyOfRange(sha256, 0, 4);

        byte[] wifBytes = concat_3item(extendedKey, compressed , checksum);
        String WIF_KEY = Base58.encode(wifBytes);
        return  WIF_KEY;
    }


    public static String byteArray_To_HexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }


    private static byte[] hexString_To_ByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }


    private static byte[] hash_sha256(byte[] item) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] firstHash = digest.digest(item);
        return digest.digest(firstHash);
    }


    private static byte[] concat_2item(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);

        return result;
    }


    private static byte[] concat_3item(byte[] a, byte[] b, byte[] c) {
        byte[] result = new byte[a.length + b.length + c.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        System.arraycopy(c, 0, result, a.length + b.length, c.length);

        return result;
    }


    public static String random_key() {
        final int ENTROPY_LENGTH = 64;           // ปรับแก้จำนวน Bytes ตามต้องการ
        final int LIMIT = 62000000;              // 12วินาที

        try {
            byte[] byteValue = new byte[ENTROPY_LENGTH];
            new Random().nextBytes(byteValue);

            int intValue = new java.math.BigInteger(1, byteValue).intValue();
            String strValue = Integer.toString(intValue);
            byte[] strBytes = strValue.getBytes("UTF-8");

            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = strBytes;
            for (int i = 0; i < LIMIT; i++) {
                hash = messageDigest.digest(hash);
            }

            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();

        } catch (NoSuchAlgorithmException e) {
            System.out.println("SHA-256 algorithm not found");
            return null;
        } catch (java.io.UnsupportedEncodingException e) {
            System.out.println("UTF-8 encoding not supported");
            return null;
        }
    }


    public static void main(String[] args) {
        try {
            String privateKeyHex = random_key();
            String private_key = privateKeyHex;
            //String private_key = "9454a5235cf34e382d7e927eb5709dc4f4ed08eed177cb3f2d4ea359071962d7";
            System.out.println("Pritvate Key: "+ private_key.length() +" length\n\t└── " + private_key +"\n");
            String wif = WIF.Private_to_WIF(private_key);

            System.out.println("WIF Key:"+ wif.length() +" length\n\t└── " + wif +"\n");

            String wif2 = Private_To_WIF_Compressed(private_key);
            System.out.println("WIF Key [Compress]:"+ wif2.length() +" length\n\t└── " + wif2 +"\n");

            byte[] decoded = Base58.decode(wif);
            //System.out.println(Arrays.toString(decoded));
            byte[] Original_Key = Arrays.copyOfRange(decoded, 1, 33);

            String hexString = byteArray_To_HexString(Original_Key);
            System.out.println(new String("Original Key: "+ hexString.length() +" length\n\t└── " + hexString));
        } catch (Exception e) {
            System.out.println("An error occurred while generating the WIF key: " + e.getMessage());
        }

    }
}
