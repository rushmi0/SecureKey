import java.util.Base64;

public class test {
    public static void main(String[] args) {
        byte[] input = new byte[] {1, 2, 3, 4, 5};
        String output = Base64.getEncoder().encodeToString(input);
        System.out.println("Base64 string representation: " + output);
    }
}