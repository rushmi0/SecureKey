import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;

public class GenerateRawKey {
    
    public static String KeyGan() {
        final int ENTROPY_LENGTH = 214748364;            // ปรับแก้จำนวนตามต้องการ
        final int LIMIT = 137000000;                     // 36วินาที Intel I5 Gen10. OC เต็มกำลัง

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
