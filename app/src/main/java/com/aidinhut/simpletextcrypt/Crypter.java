package com.aidinhut.simpletextcrypt;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/*
 * Provides methods for encrypting and decrypting data.
 */
public class Crypter {

    public static String encrypt(String password, String input)
            throws UnsupportedEncodingException,
            GeneralSecurityException {

        // Nonce (Initialization Vector) generates randomly, and sends along with the message.
        // For GCM mode, nonce *must* be unique for each message and is typically 12 bytes.
        // See: https://crypto.stackexchange.com/questions/39201/what-is-the-recommended-nonce-size-for-aes-gcm

        String nonce = getRandomNonce();
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce.getBytes("UTF-8")); // 128-bit authentication tag

        SecretKey secretKey = deriveKey(password, nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);

        byte[] encrypted = cipher.doFinal(input.getBytes());

        return nonce + Base64.encodeToString(encrypted, Base64.DEFAULT);
    }

    public static String decrypt(String password, String input)
            throws UnsupportedEncodingException,
            GeneralSecurityException {
        // First 12 chars is the random nonce.
        String nonce = input.substring(0, 12);
        String encryptedMessage = input.substring(12);

        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce.getBytes("UTF-8")); // 128-bit authentication tag

        SecretKey secretKey = deriveKey(password, nonce);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);

        byte[] original = cipher.doFinal(Base64.decode(encryptedMessage, Base64.DEFAULT));

        return new String(original);
    }

    /*
     * Returns a random string of length 12 chars for GCM nonce.
     */
    private static String getRandomNonce() {
        Random random = new Random();
        StringBuilder builder = new StringBuilder();

        for (int i = 0; i < 12; ++i) {
            builder.append((char)(random.nextInt(96) + 32));
        }

        return builder.toString();
    }

    /*
     * Derives a key from the specified password.
     */
    private static SecretKey deriveKey(String password, String salt)
        throws NoSuchAlgorithmException, InvalidKeySpecException
    {
        char[] passwordChars = new char[password.length()];
        password.getChars(0, password.length(), passwordChars, 0);

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(passwordChars, salt.getBytes(), 2000, 256);

        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }
}
