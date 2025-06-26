package com.aidinhut.simpletextcrypt;

import android.util.Base64;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypter {

    public static String encrypt(String password, String input)
            throws UnsupportedEncodingException,
            GeneralSecurityException {

        String ivKey = getRandomIV();
        IvParameterSpec iv = new IvParameterSpec(ivKey.getBytes("UTF-8"));

        SecretKey secretKey = deriveKey(password, ivKey);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv);

        byte[] encrypted = cipher.doFinal(input.getBytes());

        return ivKey + Base64.encodeToString(encrypted, Base64.DEFAULT);
    }

    public static String decrypt(String password, String input)
            throws UnsupportedEncodingException,
            GeneralSecurityException {

        String ivKey = input.substring(0, 16);
        String encryptedMessage = input.substring(16);

        IvParameterSpec iv = new IvParameterSpec(ivKey.getBytes("UTF-8"));

        SecretKey secretKey = deriveKey(password, ivKey);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);

        byte[] original = cipher.doFinal(Base64.decode(encryptedMessage, Base64.DEFAULT));

        return new String(original);
    }

    /*
     * Returns a cryptographically secure random string of 16 ASCII characters.
     */
    private static String getRandomIV() {
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder builder = new StringBuilder();

        for (int i = 0; i < 16; ++i) {
            builder.append((char) (secureRandom.nextInt(95) + 32)); // printable ASCII (32–126)
        }

        return builder.toString();
    }

    /*
     * Derives a key from the specified password using PBKDF2 with HMAC-SHA256.
     */
    private static SecretKey deriveKey(String password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {

        char[] passwordChars = password.toCharArray();

        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(passwordChars, salt.getBytes(), 110000, 256);

        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }
}
