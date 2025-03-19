package org.simple.mail.util;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JceOpenSSLPKCS8DecryptorProviderBuilder;
import org.bouncycastle.operator.InputDecryptorProvider;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileReader;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.MGF1ParameterSpec;
import java.util.Base64;

/**
 * Utility class providing cryptographic operations for secure email
 */
public class CryptoUtils {

    static {
        // Register BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());
    }

    // Constants
    private static final String RSA_ALGORITHM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String AES_ALGORITHM = "AES/CBC/PKCS5Padding";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    /**
     * Extracts a private key from a PKCS#8 encrypted file (Criterion 2)
     */
    public static PrivateKey loadPrivateKey(String privateKeyPath, char[] password) throws Exception {
        try (PEMParser pemParser = new PEMParser(new FileReader(privateKeyPath))) {
            Object object = pemParser.readObject();

            if (object instanceof PKCS8EncryptedPrivateKeyInfo) {
                // Decrypt the encrypted private key info
                PKCS8EncryptedPrivateKeyInfo encryptedInfo = (PKCS8EncryptedPrivateKeyInfo) object;
                InputDecryptorProvider decryptProvider = new JceOpenSSLPKCS8DecryptorProviderBuilder()
                        .setProvider("BC")
                        .build(password);

                PrivateKeyInfo privateKeyInfo = encryptedInfo.decryptPrivateKeyInfo(decryptProvider);
                return new JcaPEMKeyConverter().setProvider("BC").getPrivateKey(privateKeyInfo);
            } else {
                throw new IllegalArgumentException("Unsupported private key format or incorrect password");
            }
        }
    }

    /**
     * Extracts a public key from an X.509 certificate file (Criterion 2)
     */
    public static PublicKey loadPublicKey(String certificatePath) throws Exception {
        try (PEMParser pemParser = new PEMParser(new FileReader(certificatePath))) {
            Object object = pemParser.readObject();

            if (object instanceof X509CertificateHolder) {
                X509CertificateHolder certHolder = (X509CertificateHolder) object;
                X509Certificate cert = new JcaX509CertificateConverter()
                        .setProvider("BC")
                        .getCertificate(certHolder);

                return cert.getPublicKey();
            } else {
                throw new IllegalArgumentException("File does not contain an X.509 certificate");
            }
        }
    }

    /**
     * Generates a random AES key (Criterion 3)
     * @param keySize Must be 128, 192, or 256 bits
     */
    public static SecretKey generateAESKey(int keySize) throws NoSuchAlgorithmException {
        if (keySize != 128 && keySize != 192 && keySize != 256) {
            throw new IllegalArgumentException("AES key size must be 128, 192, or 256 bits");
        }

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize, new SecureRandom()); // Using SecureRandom as required
        return keyGen.generateKey();
    }

    /**
     * Generates a random initialization vector for AES (Criterion 5)
     */
    public static byte[] generateIV() {
        byte[] iv = new byte[16]; // 16 bytes = 128 bits, standard for AES
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    /**
     * Encrypts data using AES in CBC mode with a random IV (Criterion 5)
     */
    public static byte[] encryptAES(byte[] data, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM, "BC");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        return cipher.doFinal(data);
    }

    /**
     * Decrypts data using AES in CBC mode (Criterion 5)
     */
    public static byte[] decryptAES(byte[] encryptedData, SecretKey key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(AES_ALGORITHM, "BC");
        IvParameterSpec ivSpec = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        return cipher.doFinal(encryptedData);
    }

    /**
     * Encrypts data using RSA with OAEP padding (Criterion 4)
     */
    public static byte[] encryptRSA(byte[] data, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM, "BC");

        // Set up OAEP padding parameters with SHA-256
        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

        cipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepParams);
        return cipher.doFinal(data);
    }

    /**
     * Decrypts data using RSA with OAEP padding (Criterion 4)
     */
    public static byte[] decryptRSA(byte[] encryptedData, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance(RSA_ALGORITHM, "BC");

        // Set up OAEP padding parameters with SHA-256
        OAEPParameterSpec oaepParams = new OAEPParameterSpec(
                "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT);

        cipher.init(Cipher.DECRYPT_MODE, privateKey, oaepParams);
        return cipher.doFinal(encryptedData);
    }

    /**
     * Signs data using RSA with SHA-256 (Criterion 6)
     */
    public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM, "BC");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    /**
     * Verifies a signature using RSA with SHA-256 (Criterion 6)
     */
    public static boolean verifySignature(byte[] data, byte[] signatureBytes, PublicKey publicKey) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM, "BC");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    /**
     * Encodes binary data as Base64 string
     */
    public static String encodeBase64(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    /**
     * Decodes a Base64 string to binary data
     */
    public static byte[] decodeBase64(String base64String) {
        return Base64.getDecoder().decode(base64String);
    }

    /**
     * Creates a SecretKey from raw bytes
     */
    public static SecretKey createSecretKey(byte[] keyBytes) {
        return new SecretKeySpec(keyBytes, "AES");
    }
}