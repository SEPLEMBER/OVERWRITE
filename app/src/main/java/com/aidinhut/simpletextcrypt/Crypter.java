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
    private SecretKeyFactory factory;

    private Crypter() {
        try {
            factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        } catch (Exception e) {
            throw new RuntimeException("Failed to initialize Crypter", e);
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
            throw new IllegalArgumentException("Invalid input or password");
        }

        try {
            byte[] nonce = getRandomNonce();
            byte[] salt = getRandomSalt();
            String nonceBase64 = Base64.encodeToString(nonce, Base64.NO_WRAP);
            String saltBase64 = Base64.encodeToString(salt, Base64.NO_WRAP);

            SecretKey secretKey = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, new GCMParameterSpec(128, nonce));
            byte[] encrypted = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));

            Arrays.fill(password, '\0');
            return nonceBase64 + ":" + saltBase64 + ":" + Base64.encodeToString(encrypted, Base64.NO_WRAP);
        } catch (Exception e) {
            Arrays.fill(password, '\0');
            throw new Exception("Encryption failed", e);
        }
    }

    public String decrypt(char[] password, String input) throws Exception {
        if (input == null || input.length() < 34) { // Минимальная длина: nonce(16) + ":" + salt(24) + ":" + tag(16)
            throw new IllegalArgumentException("Invalid input format");
        }

        try {
            String[] parts = input.split(":");
            if (parts.length != 3) {
                throw new IllegalArgumentException("Invalid input format");
            }

            byte[] nonce = Base64.decode(parts[0], Base64.DEFAULT);
            byte[] salt = Base64.decode(parts[1], Base64.DEFAULT);
            byte[] encrypted = Base64.decode(parts[2], Base64.DEFAULT);

            if (nonce.length != 12 || salt.length != 16 || encrypted.length < 16) {
                throw new IllegalArgumentException("Invalid data format");
            }

            SecretKey secretKey = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(128, nonce));
            byte[] decrypted = cipher.doFinal(encrypted);

            Arrays.fill(password, '\0');
            return new String(decrypted, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Arrays.fill(password, '\0');
            throw new Exception("Decryption failed", e);
        }
    }

    private byte[] getRandomNonce() {
        byte[] nonce = new byte[12];
        new SecureRandom().nextBytes(nonce);
        return nonce;
    }

    private byte[] getRandomSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    private SecretKey deriveKey(char[] password, byte[] salt) throws Exception {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, 35000, 256);
            SecretKey key = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
            return key;
        } catch (Exception e) {
            throw new Exception("Key derivation failed", e);
        }
    }

    public void clearCache() {
        factory = null;
        instance = null;
        System.gc(); // Запросить сборку мусора для очистки буферов
    }
}
