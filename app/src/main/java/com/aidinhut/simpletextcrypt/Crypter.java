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
import java.util.Arrays;

public class Crypter {
    private static Crypter instance;
    private Cipher cipher;
    private SecretKeyFactory factory;

    private Crypter() {
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static Crypter getInstance() {
        if (instance == null) {
            instance = new Crypter();
        }
        return instance;
    }

    public String encrypt(char[] password, String input) throws Exception {
        if (input == null || input.isEmpty() || password == null || password.length == 0) {
            throw new IllegalArgumentException("Input or password cannot be null or empty");
        }

        byte[] nonce = getRandomNonce();
        String nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP);
        SecretKey secretKey = deriveKey(password, nonceBase64);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, nonce));
        byte[] encrypted = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));

        Arrays.fill(password, '\0');
        return nonceBase64 + Base64.encodeToString(encrypted, Base64.NO_WRAP);
    }

    public String decrypt(char[] password, String input) throws Exception {
        if (input == null || input.length() < 20) {
            throw new IllegalArgumentException("Invalid input format: too short");
        }

        String nonceBase64 = input.substring(0, 16);
        String encryptedMessage = input.substring(16);

        byte[] nonce = Base64.decode(nonceBase64, Base64.DEFAULT);
        byte[] encrypted = Base64.decode(encryptedMessage, Base64.DEFAULT);

        if (nonce.length != 12) {
            throw new IllegalArgumentException("Invalid nonce length");
        }
        if (encrypted.length < 16) {
            throw new IllegalArgumentException("Encrypted data too short for tag");
        }

        SecretKey secretKey = deriveKey(password, nonceBase64);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, nonce));
        byte[] decrypted = cipher.doFinal(encrypted);
        Arrays.fill(password, '\0');
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    private byte[] getRandomNonce() {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private SecretKey deriveKey(char[] password, String salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(password, salt.getBytes(StandardCharsets.UTF_8), 50000, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }

    public void clearCache() {
        cipher = null;
        factory = null;
    }
}
