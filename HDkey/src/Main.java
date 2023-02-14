import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Base64;

public class Main {

    private static final byte WIF_PRIVATE_KEY_PREFIX = (byte) 0x80;
    private static final byte WIF_PRIVATE_KEY_COMPRESSED = (byte) 0x01;

    public static String createWIFPrivateKey(byte[] privateKeyBytes) {
        ByteBuffer byteBuffer = ByteBuffer.allocate(privateKeyBytes.length + 2);
        byteBuffer.order(ByteOrder.BIG_ENDIAN);
        byteBuffer.put(WIF_PRIVATE_KEY_PREFIX);
        byteBuffer.put(privateKeyBytes);
        byteBuffer.put(WIF_PRIVATE_KEY_COMPRESSED);

        return Base64.getEncoder().encodeToString(byteBuffer.array());
    }

    public static void main(String[] args) {
        byte[] privateKeyBytes = {(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04};
        String wifPrivateKey = Main.createWIFPrivateKey(privateKeyBytes);
        System.out.println("WIF Private Key: " + wifPrivateKey);
    }

}
