import twofish.Twofish;
import twofish.IntermediateUtilityMethods;

import java.io.IOException;

/**
 * In this class a real world application of Twofish is presented.
 * The algorithm is used to encrypt and decrypt a txt file.
 */
public class Main {





    public static void main(String[] args) throws Exception {
        try {
            // String encryptionKey192bit = "3a5ccc6bce05d8c165f6756801a46f3a6f47003359785b33f8ddfe98875bae0b";

            // byte[] fileCiphertext = Twofish.twofishECBEncrypt(
            //         Files.readAllBytes(Paths.get("examples/plaintext.txt")),
            //         encryptionKey192bit);

            // File encryptedFile = new File("examples/ciphertext.txt");
            // Files.write(encryptedFile.toPath(), fileCiphertext);

            // byte[] filePlaintext = Twofish.twofishECBDecrypt(
            //         Files.readAllBytes(Paths.get("examples/ciphertext.txt")),
            //         encryptionKey192bit);
            // File decryptedFile = new File("examples/decrypted.txt");
            // Files.write(decryptedFile.toPath(), filePlaintext);

            // Ask user for input on the mode of encryption or decryption that is whether in console or file

            // System.out.println("Enter the mode of operation: ");
            // System.out.println("1. Console");
            // System.out.println("2. File");
            // int mode = Integer.parseInt(System.console().readLine());

            // If user chooses console mode

            
            System.out.println("Enter the mode of operation: ");
            System.out.println("1. Encryption");
            System.out.println("2. Decryption");
            int modeOfOperation = Integer.parseInt(System.console().readLine());

                // If user chooses encryption mode1


            if (modeOfOperation == 1) {
                System.out.println("Enter the plaintext: ");
                String plaintext = System.console().readLine();
                // Convert the plaintext to byte array
                byte[] plaintextBytes = IntermediateUtilityMethods.stringToByteArray(plaintext);
                System.out.println("Enter the key: ");
                String key = System.console().readLine();
                // No need to convert the key
                byte[] ciphertext = Twofish.twofishECBEncrypt(plaintextBytes, key);
                // Convert the ciphertext to hex string
                System.out.println("Ciphertext: " + IntermediateUtilityMethods.byteArrayToHexString(ciphertext));
            }

            // If user chooses decryption mode

            else if (modeOfOperation == 2) {
                System.out.println("Enter the ciphertext: ");
                String ciphertext = System.console().readLine();
                // Convert the ciphertext to byte array
                byte[] ciphertextBytes = IntermediateUtilityMethods.decodeHexString(ciphertext);
                System.out.println("Enter the key: ");
                String key = System.console().readLine();
                // No need to convert the key
                byte[] plaintext = Twofish.twofishECBDecrypt(ciphertextBytes, key);
                // Convert the hex string to string
                System.out.println("Plaintext: " + new String(plaintext));
            }

            // Other than 1 or 2

            else {
                System.out.println("Invalid mode of operation");
            }

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

