import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class GenerateRawKey {

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    public static String Bytes_To_Hex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = HEX_ARRAY[v >>> 4];
            hexChars[i * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }


    public static String KeyGan() {
        final int ENTROPY_LENGTH = 512;            // ปรับแก้จำนวนตามต้องการ
        final int LIMIT = 137000000;                     // 36วินาที Intel I5 Gen10. OC เต็มกำลัง

        try {
            byte[] byteValue = new byte[ENTROPY_LENGTH];

            new Random().nextBytes(byteValue);

            String randomHex = Bytes_To_Hex(byteValue);
            BigInteger randomBase10 = new BigInteger(randomHex, 16);

            String randomString = randomBase10.toString();
            byte[] randomBytes2 = new BigInteger(randomString).toByteArray();

            System.out.println(randomString);
            System.out.println(Bytes_To_Hex(randomBytes2));

            int intValue = new java.math.BigInteger(1, byteValue).intValue();
            String strValue = Integer.toString(intValue);

            byte[] strBytes = strValue.getBytes("UTF-8");

            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = strBytes;

            for (int i = 0; i < 1; i++) {
                hash = messageDigest.digest(hash);
            }

            StringBuilder sb = new StringBuilder();

            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();

        }

        catch (NoSuchAlgorithmException e) {
            System.out.println("SHA-256 algorithm not found");
            return null;
        }

        catch (java.io.UnsupportedEncodingException e) {
            System.out.println("UTF-8 encoding not supported");
            return null;
        }
    }

    // Test
    public static void main(String[] args) {
        String hashResult = KeyGan();
        System.out.println("Private Key: " + hashResult);
    }
}