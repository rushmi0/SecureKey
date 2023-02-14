import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Random;


public class WIF {

    // input a02534a21ebb47b7f155f845d91eca8b35ea88128f3c54175804dbf7171106dc <- Hash sha256
    // output 5K2pH9GpdHMBrXzFuCwRto5ke6PQU1t8XLp7BATBtHU3KMnv85D <- WIF Key
    public static String Private_to_WIF(String privateKeyHex) throws Exception {
        byte[] privateKeyBytes = hexStringToByteArray(privateKeyHex);
        byte[] prefix = new byte[] { (byte) 0x80 };
        //System.out.println(prefix);

        byte[] extendedKey = concat_item(prefix, privateKeyBytes);
        byte[] sha256 = hash_sha256(extendedKey);
        byte[] checksum = Arrays.copyOfRange(sha256, 0, 4);

        byte[] wifBytes = concat_item(extendedKey, checksum);
        //System.out.println(wifBytes);
        String WIF_KEY = Base58.encode(wifBytes);
        return  WIF_KEY;
    }


    private static byte[] hexStringToByteArray(String s) {
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


    private static byte[] concat_item(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);

        return result;
    }



    public static String random_privatekey() {
        try {
            Random random = new Random();
            int number = random.nextInt();
            String str = Integer.toString(number);

            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            byte[] hash = messageDigest.digest(str.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            System.out.println("SHA-256 algorithm not found");
            return null;
        }
    }


    public static void main(String[] args) {
        try {
            String privateKeyHex = random_privatekey();
            String private_key = "9454a5235cf34e382d7e927eb5709dc4f4ed08eed177cb3f2d4ea359071962d7";
            System.out.println("Pritvate Key: " + private_key);
            String wif = WIF.Private_to_WIF(private_key);
            System.out.println("WIF Key: " + wif);

            byte[] decoded = Base58.decode_3(wif);

            System.out.println("wif decoded: " + decoded);
            System.out.println(Arrays.toString(decoded));

            byte[] ITEM = Arrays.copyOfRange(decoded, 1, 36);

            String output = new String(ITEM, StandardCharsets.UTF_8);

            System.out.println(new String("Decoded: " + output));
        } catch (Exception e) {
            System.out.println("An error occurred while generating the WIF key: " + e.getMessage());
        }

    }
}
