import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;


public class Base58 {
    private static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".toCharArray();
    private static final BigInteger BASE = BigInteger.valueOf(58);

    public static String encode(byte[] input) {
        BigInteger num = new BigInteger(1, input);
        StringBuilder sb = new StringBuilder();
        while (num.compareTo(BASE) >= 0) {
            BigInteger[] result = num.divideAndRemainder(BASE);
            sb.append(ALPHABET[result[1].intValue()]);
            num = result[0];
        }
        sb.append(ALPHABET[num.intValue()]);

        for (byte b : input) {
            if (b == 0x00) {
                sb.append(ALPHABET[0]);
            } else {
                break;
            }
        }
        return sb.reverse().toString();
    }


    public static byte[] decode_1(String input) {
        BigInteger num = BigInteger.valueOf(0);
        for (char c : input.toCharArray()) {
            int index = Arrays.binarySearch(ALPHABET, c);
            if (index < 0) {
                throw new IllegalArgumentException("Illegal character: " + c);
            }
            num = num.multiply(BASE).add(BigInteger.valueOf(index));
        }
        byte[] bytes = num.toByteArray();
        // Remove the leading zeros.
        int zeros = 0;
        for (; zeros < bytes.length - 1 && bytes[zeros] == 0x00; zeros++);
        return Arrays.copyOfRange(bytes, zeros, bytes.length);
    }


    public static String toBase16(byte[] input) {
        StringBuilder sb = new StringBuilder();
        for (byte b : input) {
            sb.append(String.format("%02X", b & 0xff));
        }
        return sb.toString();
    }


    public static byte[] decode_2(String input) {
        BigInteger num = BigInteger.valueOf(0);
        for (char c : input.toCharArray()) {
            num = num.multiply(BASE);
            int index = Arrays.binarySearch(ALPHABET, c);
            num = num.add(BigInteger.valueOf(index));
        }
        byte[] decoded = num.toByteArray();
        // Remove the sign byte.
        if (decoded[0] == 0x00) {
            byte[] tmp = new byte[decoded.length - 1];
            System.arraycopy(decoded, 1, tmp, 0, tmp.length);
            decoded = tmp;
        }
        // Add leading zeros.
        for (int i = 0; i < input.length() && input.charAt(i) == ALPHABET[0]; i++) {
            decoded = concat(new byte[] { 0x00 }, decoded);
        }
        return decoded;
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    public static String toHexString(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            String hex = Integer.toHexString(0xff & bytes[i]);
            if (hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }




    public static byte[] decode_3(String input) {
        BigInteger num = BigInteger.ZERO;
        for (char c : input.toCharArray()) {
            int digit = getIndex(c);
            if (digit == -1) {
                throw new IllegalArgumentException("Invalid character in input: " + c);
            }
            num = num.multiply(BASE).add(BigInteger.valueOf(digit));
        }
        return num.toByteArray();
    }


    private static int getIndex(char c) {
        for (int i = 0; i < ALPHABET.length; i++) {
            if (c == ALPHABET[i]) {
                return i;
            }
        }
        return -1;
    }



    public static void main(String[] args) {
        String data = "11449b2c636ddfd5bae53e856365e4dd9371aa4ee5870f2d6d3aefaa3eede850";
        byte[] input = data.getBytes();
        String encoded = Base58.encode(input);
        System.out.println("Original Data: " + data);
        //System.out.println("Encoded Data: " + encoded);

        byte[] decoded = Base58.decode_1(encoded);

        System.out.println(decoded);
        String output = new String(decoded, StandardCharsets.UTF_8);
        System.out.println(new String("Decoded: " + output));

        /*********************************************************************************/

        // 5JBQqvc5B2NgF3MrQ6NGkWLRyPbibhEw5USg6dqb5qYW4ZuXsb4
        String encodedData = "5JBQqvc5B2NgF3MrQ6NGkWLRyPbibhEw5USg6dqb5qYW4ZuXsb4";
        byte[] decodedData = Base58.decode_1(encodedData);
        System.out.println(decodedData);

        String output1 = new String(decodedData, StandardCharsets.UTF_8);
        System.out.println(new String("Decoded: " + output1));
    }
}
