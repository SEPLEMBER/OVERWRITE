```java
package com.aidinhut.simpletextcrypt;

import android.util.Base64;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class Crypter {

    public static String encrypt(char[] password, String input)
            throws UnsupportedEncodingException, GeneralSecurityException {
        String nonce = getRandomNonce();
        byte[] nonceBytes = Base64.decode(nonce, Base64.DEFAULT);
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonceBytes);
        SecretKey secretKey = deriveKey(password, nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmSpec);
        byte[] encrypted = cipher.doFinal(input.getBytes());
        return nonce + Base64.encodeToString(encrypted, Base64.DEFAULT);
    }

    public static String decrypt(char[] password, String input)
            throws UnsupportedEncodingException, GeneralSecurityException {
        String nonceOrIV = input.substring(0, input.length() >= 16 ? 16 : 12);
        String encryptedMessage = input.substring(input.length() >= 16 ? 16 : 12);
        SecretKey secretKey = deriveKey(password, nonceOrIV);

        if (nonceOrIV.length() == 16) {
            // Старый формат (CBC)
            IvParameterSpec iv = new IvParameterSpec(nonceOrIV.getBytes("UTF-8"));
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
            byte[] original = cipher.doFinal(Base64.decode(encryptedMessage, Base64.DEFAULT));
            return new String(original);
        } else {
            // Новый формат (GCM)
            byte[] nonceBytes = Base64.decode(nonceOrIV, Base64.DEFAULT);
            GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonceBytes);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, secretKey, gcmSpec);
            byte[] original = cipher.doFinal(Base64.decode(encryptedMessage, Base64.DEFAULT));
            return new String(original);
        }
    }

    private static String getRandomNonce() {
        SecureRandom random = new SecureRandom();
        byte[] nonce = new byte[12];
        random.nextBytes(nonce);
        return Base64.encodeToString(nonce, Base64.NO_WRAP);
    }

    private static SecretKey deriveKey(char[] password, String salt)
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        PBEKeySpec spec = new PBEKeySpec(password, salt.getBytes(), 100000, 256);
        return new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
    }
}
```
