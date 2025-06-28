package com.aidinhut.simpletextcrypt;

import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypter {

    private static final int SALT_LENGTH_BYTES    = 32;
    private static final int IV_LENGTH_BYTES      = 12;
    private static final int TAG_LENGTH_BITS      = 128;
    private static final int PBKDF2_ITERATIONS    = 75000;
    private static final int KEY_LENGTH_BITS      = 256;
    private static final String PBKDF2_ALGORITHM  = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_ALGORITHM  = "AES/GCM/NoPadding";
    private static final String FORMAT_VERSION    = "v1";

    // === Перегрузка: удобный интерфейс для String паролей ===
    public static String encrypt(String password, String plaintext)
            throws GeneralSecurityException {
        return encrypt(password != null ? password.toCharArray() : null, plaintext);
    }

    public static String decrypt(String password, String input)
            throws GeneralSecurityException {
        return decrypt(password != null ? password.toCharArray() : null, input);
    }

    // === Основные безопасные методы с char[] ===
    public static String encrypt(char[] password, String plaintext)
            throws GeneralSecurityException {

        if (password == null || plaintext == null || plaintext.isEmpty()) {
            throw new IllegalArgumentException("Password and plaintext must be non-null and non-empty");
        }

        SecureRandom rnd = new SecureRandom();

        byte[] salt = new byte[SALT_LENGTH_BYTES];
        rnd.nextBytes(salt);

        byte[] iv = new byte[IV_LENGTH_BYTES];
        rnd.nextBytes(iv);

        byte[] key = null;
        try {
            key = deriveKey(password, salt);
            SecretKey secretKey = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

            cipher.updateAAD(FORMAT_VERSION.getBytes(StandardCharsets.UTF_8));
            cipher.updateAAD(salt);
            cipher.updateAAD(iv);

            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            return FORMAT_VERSION + ":" +
                   Base64.encodeToString(salt, Base64.NO_WRAP) + ":" +
                   Base64.encodeToString(iv, Base64.NO_WRAP) + ":" +
                   Base64.encodeToString(ciphertext, Base64.NO_WRAP);

        } finally {
            if (key != null) java.util.Arrays.fill(key, (byte) 0);
            java.util.Arrays.fill(password, '\0');
        }
    }

    public static String decrypt(char[] password, String input)
            throws GeneralSecurityException {

        if (password == null || input == null) {
            throw new IllegalArgumentException("Password and input must be non-null");
        }

        String[] parts = input.split(":", 4);
        if (parts.length != 4 || !parts[0].equals(FORMAT_VERSION)) {
            throw new IllegalArgumentException("Invalid input format or version");
        }

        byte[] salt = Base64.decode(parts[1], Base64.NO_WRAP);
        byte[] iv = Base64.decode(parts[2], Base64.NO_WRAP);
        byte[] ciphertext = Base64.decode(parts[3], Base64.NO_WRAP);

        if (salt.length != SALT_LENGTH_BYTES || iv.length != IV_LENGTH_BYTES) {
            throw new IllegalArgumentException("Invalid salt or IV length");
        }

        byte[] key = null;
        try {
            key = deriveKey(password, salt);
            SecretKey secretKey = new SecretKeySpec(key, "AES");

            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

            cipher.updateAAD(FORMAT_VERSION.getBytes(StandardCharsets.UTF_8));
            cipher.updateAAD(salt);
            cipher.updateAAD(iv);

            byte[] plainBytes = cipher.doFinal(ciphertext);
            return new String(plainBytes, StandardCharsets.UTF_8);

        } finally {
            if (key != null) java.util.Arrays.fill(key, (byte) 0);
            java.util.Arrays.fill(password, '\0');
        }
    }

    private static byte[] deriveKey(char[] password, byte[] salt)
            throws InvalidKeySpecException, GeneralSecurityException {

        PBEKeySpec spec = new PBEKeySpec(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
        SecretKeyFactory factory = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
        return factory.generateSecret(spec).getEncoded();  // ← Была ошибка здесь
    }
}
