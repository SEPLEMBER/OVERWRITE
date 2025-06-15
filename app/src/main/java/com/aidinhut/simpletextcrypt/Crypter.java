package com.aidinhut.simpletextcrypt;

import android.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public class Crypter {
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int TAG_LENGTH_BIT = 128;
    private static final int IV_LENGTH_BYTE = 12;
    private static final int NONCE_BASE64_LENGTH = 16;
    private static final Cipher cipher;
    private static final SecretKeyFactory factory;

    static {
        try {
            cipher = Cipher.getInstance(TRANSFORMATION);
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize crypto objects", e);
        }
    }

    public static String encrypt(char[] password, String input) throws Exception {
        if (input == null || input.isEmpty() || password == null || password.length == 0) {
            throw new IllegalArgumentException("Input or password cannot be null or empty");
        }

        byte[] nonce = getRandomNonce();
        String nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP);
        SecretKey secretKey = deriveKey(password, nonceBase64);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, nonce));
        byte[] encrypted = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));

        return nonceBase64 + Base64.encodeToString(encrypted, Base64.NO_WRAP);
    }

    public static String decrypt(char[] password, String input) throws Exception {
        if (input == null || input.length() < NONCE_BASE64_LENGTH + 4) {
            throw new IllegalArgumentException("Invalid input format: too short");
        }

        String nonceBase64 = input.substring(0, NONCE_BASE64_LENGTH);
        String encryptedMessage = input.substring(NONCE_BASE64_LENGTH);

        byte[] nonce;
        byte[] encrypted;
        try {
            nonce = Base64.decode(nonceBase64, Base64.DEFAULT);
            encrypted = Base64.decode(encryptedMessage, Base64.DEFAULT);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid Base64 format");
        }

        if (nonce.length != IV_LENGTH_BYTE) {
            throw new IllegalArgumentException("Invalid nonce length");
        }
        if (encrypted.length < 16) {
            throw new IllegalArgumentException("Encrypted data too short for tag");
        }

        SecretKey secretKey = deriveKey(password, nonceBase64);
        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(TAG_LENGTH_BIT, nonce));
            byte[] decrypted = cipher.doFinal(encrypted);
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IllegalArgumentException("Decryption failed: invalid key or data");
        }
    }

    private static byte[] getRandomNonce() {
        byte[] nonce = new byte[IV_LENGTH_BYTE];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private static SecretKey deriveKey(char[] password, String salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt.getBytes(StandardCharsets.UTF_8), 100000, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }
}
