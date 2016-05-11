package net.myrts.jce.utils;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

/**
 * @author <a href="mailto:vzhovtiuk@gmail.com">Vitaliy Zhovtyuk</a>
 *         Date: 5/4/16
 *         Time: 4:01 PM
 */
public class EncryptionUtil {

    public static final String AES256_ECB_CIPHER = "AES/ECB/PKCS5Padding";
    
    public static final String AES256_CBC_CIPHER = "AES/CBC/PKCS5Padding";
    
    public static final String AES256_CFB_CIPHER = "AES/CFB/PKCS5Padding";
    
    public static final String AES_KEY_TYPE = "AES";

    public static String encryptAES256ECB(char[] plaintext, char[] secretKey) throws DecoderException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException {
        SecretKeySpec secretSpec = new SecretKeySpec(Hex.decodeHex(secretKey), AES_KEY_TYPE);

        Cipher cipher = Cipher.getInstance(AES256_ECB_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, secretSpec);
        byte[] encryptedTextBytes = cipher.doFinal(String.valueOf(plaintext).getBytes(StandardCharsets.UTF_8.name()));

        return Base64.getEncoder().encodeToString(encryptedTextBytes);
    }

    public static EncryptionResult encryptAES256CBC(char[] plaintext, char[] secretKey) throws DecoderException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidParameterSpecException {
        SecretKeySpec secretSpec = new SecretKeySpec(Hex.decodeHex(secretKey), AES_KEY_TYPE);

        Cipher cipher = Cipher.getInstance(AES256_CBC_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, secretSpec);
        AlgorithmParameters params = cipher.getParameters();
        byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedTextBytes = cipher.doFinal(String.valueOf(plaintext).getBytes(StandardCharsets.UTF_8.name()));

        return new EncryptionResult(Base64.getEncoder().encodeToString(encryptedTextBytes), 
                Base64.getEncoder().encodeToString(ivBytes));
    }

  public static EncryptionResult encryptAES256CFB(char[] plaintext, char[] secretKey) throws DecoderException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidParameterSpecException {
        SecretKeySpec secretSpec = new SecretKeySpec(Hex.decodeHex(secretKey), AES_KEY_TYPE);

        Cipher cipher = Cipher.getInstance(AES256_CFB_CIPHER);
        cipher.init(Cipher.ENCRYPT_MODE, secretSpec);
        AlgorithmParameters params = cipher.getParameters();
        byte[] ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedTextBytes = cipher.doFinal(String.valueOf(plaintext).getBytes(StandardCharsets.UTF_8.name()));

        return new EncryptionResult(Base64.getEncoder().encodeToString(encryptedTextBytes), 
                Base64.getEncoder().encodeToString(ivBytes));
    }

    public static String decryptAES256ECB(char[] encryptedText, char[] secretKey) throws Exception {
        byte[] encryptedTextBytes = Base64.getDecoder().decode(new String(encryptedText));
        SecretKeySpec secretSpec = new SecretKeySpec(Hex.decodeHex(secretKey), AES_KEY_TYPE);

        Cipher cipher = Cipher.getInstance(AES256_ECB_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, secretSpec);

        byte[] decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        return new String(decryptedTextBytes);
    }
    
    public static String decryptAES256CBC(char[] encryptedText, char[] secretKey, String initVector) throws DecoderException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
        byte[] encryptedTextBytes = Base64.getDecoder().decode(new String(encryptedText));
        SecretKeySpec secretSpec = new SecretKeySpec(Hex.decodeHex(secretKey), AES_KEY_TYPE);

        Cipher cipher = Cipher.getInstance(AES256_CBC_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, secretSpec, new IvParameterSpec(Base64.getDecoder().decode(initVector)));

        byte[] decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        return new String(decryptedTextBytes);
    }

    
    public static char[] generateSecretKey(char[] keyText, String salt) throws InvalidKeySpecException, NoSuchAlgorithmException, DecoderException, UnsupportedEncodingException {
        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        int iterations = 65536;
        int keySize = 256;
        PBEKeySpec spec = new PBEKeySpec(keyText, salt.getBytes(StandardCharsets.UTF_8.name()), iterations, keySize);
        SecretKey secretKey = skf.generateSecret(spec);
        return Hex.encodeHex(secretKey.getEncoded());
    }
    
    public static String decryptAES256CFB(char[] encryptedText, char[] secretKey, String initVector) throws DecoderException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, InvalidParameterSpecException, InvalidAlgorithmParameterException {
        byte[] encryptedTextBytes = Base64.getDecoder().decode(new String(encryptedText));
        SecretKeySpec secretSpec = new SecretKeySpec(Hex.decodeHex(secretKey), AES_KEY_TYPE);

        Cipher cipher = Cipher.getInstance(AES256_CFB_CIPHER);
        cipher.init(Cipher.DECRYPT_MODE, secretSpec, new IvParameterSpec(Base64.getDecoder().decode(initVector)));

        byte[] decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        return new String(decryptedTextBytes);
    }
    
    public static String getSalt() throws NoSuchAlgorithmException {
        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[20];
        sr.nextBytes(salt);
        return new String(salt);
    }


    public static String encryptSha1(String content) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        if (md != null) {
            return Hex.encodeHexString(md.digest(content.getBytes(StandardCharsets.UTF_8.name())));
        }
        return null;
    }
    
}
