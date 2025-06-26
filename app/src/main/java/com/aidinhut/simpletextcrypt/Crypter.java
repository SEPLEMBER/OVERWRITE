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
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypter {

    // Параметры
    private static final int SALT_LENGTH_BYTES       = 16;     // 128-бит соль
    private static final int IV_LENGTH_BYTES         = 16;     // 128-бит IV
    private static final int PBKDF2_ITERATIONS       = 27_000;
    private static final int KEY_LENGTH_BITS         = 256;    // длина AES-ключа
    private static final String PBKDF2_ALGORITHM     = "PBKDF2WithHmacSHA1";
    private static final String CIPHER_ALGORITHM     = "AES/CBC/PKCS5Padding";

    /**
     * Шифрует строку.
     * Возвращает строку в формате:
     * Base64(salt) : Base64(iv) : Base64(ciphertext)
     */
    public static String encrypt(String password, String plaintext)
            throws GeneralSecurityException {

        // 1) Генерим соль
        byte[] salt = new byte[SALT_LENGTH_BYTES];
        SecureRandom rnd = new SecureRandom();
        rnd.nextBytes(salt);

        // 2) Генерим IV
        byte[] ivBytes = new byte[IV_LENGTH_BYTES];
        rnd.nextBytes(ivBytes);
        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // 3) Деривация ключа
        byte[] keyBytes = deriveKeyBytes(password, salt);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        // Чистим keyBytes
        java.util.Arrays.fill(keyBytes, (byte) 0);

        // 4) Шифруем
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);
        byte[] cipherBytes = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // 5) Кодируем и пакуем
        String sSalt   = Base64.encodeToString(salt,     Base64.NO_WRAP);
        String sIv     = Base64.encodeToString(ivBytes,  Base64.NO_WRAP);
        String sCipher = Base64.encodeToString(cipherBytes, Base64.NO_WRAP);

        return sSalt + ":" + sIv + ":" + sCipher;
    }

    /**
     * Расшифровывает строку из формата salt:iv:cipher.
     */
    public static String decrypt(String password, String input)
            throws GeneralSecurityException, UnsupportedEncodingException {

        // 1) Разбираем на части
        String[] parts = input.split(":", 3);
        if (parts.length != 3) {
            throw new IllegalArgumentException("Invalid encrypted data format");
        }

        byte[] salt       = Base64.decode(parts[0], Base64.NO_WRAP);
        byte[] ivBytes    = Base64.decode(parts[1], Base64.NO_WRAP);
        byte[] cipherData = Base64.decode(parts[2], Base64.NO_WRAP);

        if (salt.length != SALT_LENGTH_BYTES || ivBytes.length != IV_LENGTH_BYTES) {
            throw new IllegalArgumentException("Invalid salt or IV length");
        }

        IvParameterSpec iv = new IvParameterSpec(ivBytes);

        // 2) Деривация ключа
        byte[] keyBytes = deriveKeyBytes(password, salt);
        SecretKey secretKey = new SecretKeySpec(keyBytes, "AES");
        java.util.Arrays.fill(keyBytes, (byte) 0);

        // 3) Расшифровка
        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        byte[] plainBytes = cipher.doFinal(cipherData);

        return new String(plainBytes, StandardCharsets.UTF_8);
    }

    /**
     * Возвращает «сырые» байты AES-ключа, полученные через PBKDF2.
     * После вызова нужно сразу затирать возвращённый массив.
     */
    private static byte[] deriveKeyBytes(String password, byte[] salt)
            throws InvalidKeySpecException, GeneralSecurityException {
        // Преобразуем пароль в char[]
        char[] pwdChars = password.toCharArray();
        try {
            PBEKeySpec spec = new PBEKeySpec(pwdChars, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BITS);
            SecretKeyFactory f = SecretKeyFactory.getInstance(PBKDF2_ALGORITHM);
            return f.generateSecret(spec).getEncoded();
        } finally {
            // Затираем пароль
            java.util.Arrays.fill(pwdChars, '\0');
        }
    }
}
