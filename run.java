import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.util.*;

public static byte[] decrypt(byte[] input, String password) throws Exception {
    // Read the salt and IV from the encrypted data
    byte[] salt = new byte[16];
    byte[] iv = new byte[16];
    System.arraycopy(input, 0, salt, 0, 16);
    System.arraycopy(input, 16, iv, 0, 16);

    // Derive a key from the password and salt
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1000, 32 * 8);
    SecretKey tmp = factory.generateSecret(spec);
    SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

    // Decrypt the data
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
    return cipher.doFinal(input, 32, input.length - 32);
}



public static byte[] encrypt(byte[] input, String password) throws Exception {
    // Generate a random salt
    byte[] salt = new byte[16];
    SecureRandom rng = new SecureRandom();
    rng.nextBytes(salt);

    // Derive a key from the password and salt
    byte[] key;
    SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
    KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, 1000, 256);
    SecretKey tmp = factory.generateSecret(spec);
    key = tmp.getEncoded();

    // Encrypt the data using AES
    Cipher aes = Cipher.getInstance("AES/CBC/PKCS5Padding");
    SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
    aes.init(Cipher.ENCRYPT_MODE, keySpec);
    byte[] iv = aes.getIV();

    byte[] encryptedData;
    try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
        outputStream.write(salt);
        outputStream.write(iv);
        try (CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, aes)) {
            cipherOutputStream.write(input);
        }
        encryptedData = outputStream.toByteArray();
    }

    return encryptedData;
}
