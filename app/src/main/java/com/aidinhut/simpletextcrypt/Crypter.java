package com.aidinhut.simpletextcrypt;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
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

    // Параметры алгоритмов (БЕЗ ИЗМЕНЕНИЙ)
    private static final int SALT_LENGTH_BYTES    = 16;       // 128-битная соль
    private static final int IV_LENGTH_BYTES      = 12;       // 96-битный IV для GCM
    private static final int TAG_LENGTH_BITS      = 128;      // 128-битный тег аутентичности
    private static final int PBKDF2_ITERATIONS    = 45000;    // Настраиваемое число итераций
    private static final int KEY_LENGTH_BITS      = 256;      // AES-256
    private static final String PBKDF2_ALGORITHM  = "PBKDF2WithHmacSHA256";
    private static final String CIPHER_ALGORITHM  = "AES/GCM/NoPadding";
    private static final String FORMAT_VERSION    = "v1";     // Версионирование формата

    /**
     * Шифрует строку.
     * Формат: v1:Base64(salt):Base64(iv):Base64(ciphertext)
     */
    public static String encrypt(String password, String plaintext)
            throws GeneralSecurityException {

        // ДОБАВЛЕНО: валидация входных параметров
        if (password == null || plaintext == null) {
            throw new IllegalArgumentException("Password and plaintext cannot be null");
        }
        if (plaintext.isEmpty()) {
            throw new IllegalArgumentException("Plaintext cannot be empty");
        }

        SecureRandom rnd = new SecureRandom();

        byte[] salt = new byte[SALT_LENGTH_BYTES];
        rnd.nextBytes(salt);

        byte[] ivBytes = new byte[IV_LENGTH_BYTES];
        rnd.nextBytes(ivBytes);

        byte[] keyBytes = deriveKeyBytes(password, salt);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

            // ИСПРАВЛЕНО: включен AAD для дополнительной защиты
            cipher.updateAAD(FORMAT_VERSION.getBytes(StandardCharsets.UTF_8));

            byte[] cipherBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            return FORMAT_VERSION + ":" +
                   Base64.encodeToString(salt, Base64.NO_WRAP) + ":" +
                   Base64.encodeToString(ivBytes, Base64.NO_WRAP) + ":" +
                   Base64.encodeToString(cipherBytes, Base64.NO_WRAP);

        } finally {
            java.util.Arrays.fill(keyBytes, (byte) 0);
        }
    }

    /**
     * Расшифровывает строку.
     * Ожидается формат: v1:salt:iv:ciphertext
     */
    public static String decrypt(String password, String input)
            throws GeneralSecurityException, UnsupportedEncodingException {

        // ДОБАВЛЕНО: валидация входных параметров
        if (password == null || input == null) {
            throw new IllegalArgumentException("Password and input cannot be null");
        }

        String[] parts = input.split(":", 4);
        if (parts.length != 4 || !parts[0].equals("v1")) {
            throw new IllegalArgumentException("Unsupported or invalid format");
        }

        byte[] salt    = Base64.decode(parts[1], Base64.NO_WRAP);
        byte[] ivBytes = Base64.decode(parts[2], Base64.NO_WRAP);
        byte[] cipherData = Base64.decode(parts[3], Base64.NO_WRAP);

        if (salt.length != SALT_LENGTH_BYTES || ivBytes.length != IV_LENGTH_BYTES) {
            throw new IllegalArgumentException("Invalid salt or IV length");
        }

        byte[] keyBytes = deriveKeyBytes(password, salt);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

            // ИСПРАВЛЕНО: включен AAD (должен совпадать с шифрованием)
            cipher.updateAAD(parts[0].getBytes(StandardCharsets.UTF_8));

            byte[] plainBytes = cipher.doFinal(cipherData);
            return new String(plainBytes, StandardCharsets.UTF_8);

        } finally {
            java.util.Arrays.fill(keyBytes, (byte) 0);
        }
    }

    // ДОБАВЛЕНО: методы для работы с byte arrays
    /**
     * Шифрует массив байт.
     * Возвращает: версия(1 байт) + соль + IV + зашифрованные данные
     */
    public static byte[] encryptBytes(String password, byte[] plaintext)
            throws GeneralSecurityException {

        if (password == null || plaintext == null) {
            throw new IllegalArgumentException("Password and plaintext cannot be null");
        }
        if (plaintext.length == 0) {
            throw new IllegalArgumentException("Plaintext cannot be empty");
        }

        SecureRandom rnd = new SecureRandom();

        byte[] salt = new byte[SALT_LENGTH_BYTES];
        rnd.nextBytes(salt);

        byte[] ivBytes = new byte[IV_LENGTH_BYTES];
        rnd.nextBytes(ivBytes);

        byte[] keyBytes = deriveKeyBytes(password, salt);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, ivBytes);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

            cipher.updateAAD(FORMAT_VERSION.getBytes(StandardCharsets.UTF_8));

            byte[] cipherBytes = cipher.doFinal(plaintext);

            // Формат: версия_байт + соль + IV + зашифрованные_данные
            byte[] result = new byte[1 + SALT_LENGTH_BYTES + IV_LENGTH_BYTES + cipherBytes.length];
            int pos = 0;
            result[pos++] = 1; // версия v1 как байт
            System.arraycopy(salt, 0, result, pos, SALT_LENGTH_BYTES);
            pos += SALT_LENGTH_BYTES;
            System.arraycopy(ivBytes, 0, result, pos, IV_LENGTH_BYTES);
            pos += IV_LENGTH_BYTES;
            System.arraycopy(cipherBytes, 0, result, pos, cipherBytes.length);

            return result;

        } finally {
            java.util.Arrays.fill(keyBytes, (byte) 0);
        }
    }

    /**
     * Расшифровывает массив байт.
     */
    public static byte[] decryptBytes(String password, byte[] input)
            throws GeneralSecurityException {

        if (password == null || input == null) {
            throw new IllegalArgumentException("Password and input cannot be null");
        }
        
        int minLength = 1 + SALT_LENGTH_BYTES + IV_LENGTH_BYTES + 16; // минимум для GCM тега
        if (input.length < minLength) {
            throw new IllegalArgumentException("Input too short");
        }

        int pos = 0;
        byte version = input[pos++];
        if (version != 1) {
            throw new IllegalArgumentException("Unsupported version: " + version);
        }

        byte[] salt = new byte[SALT_LENGTH_BYTES];
        System.arraycopy(input, pos, salt, 0, SALT_LENGTH_BYTES);
        pos += SALT_LENGTH_BYTES;

        byte[] ivBytes = new byte[IV_LENGTH_BYTES];
        System.arraycopy(input, pos, ivBytes, 0, IV_LENGTH_BYTES);
        pos += IV_LENGTH_BYTES;

        byte[] cipherData = new byte[input.length - pos];
        System.arraycopy(input, pos, cipherData, 0, cipherData.length);

        byte[] keyBytes = deriveKeyBytes(password, salt);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");

        try {
            Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
            GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, ivBytes);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

            cipher.updateAAD(FORMAT_VERSION.getBytes(StandardCharsets.UTF_8));

            return cipher.doFinal(cipherData);

        } finally {
            java.util.Arrays.fill(keyBytes, (byte) 0);
        }
    }

    /**
     * Генерация ключа через PBKDF2.
     */
    private static byte[] deriveKeyBytes(String password, byte[] salt)
            throws InvalidKeySpecException, GeneralSecurityException {
        char[] pwdChars = password.toCharArray();
        try {
            PBEKeySpec spec = new PBEKeySpec(pwdChars, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
            SecretKeyFactory f = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            return f.generateSecret(spec).getEncoded();
        } finally {
            java.util.Arrays.fill(pwdChars, '\0');
        }
    }
}
