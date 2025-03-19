package org.simple.mail.util;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.bouncycastle.pkcs.jcajce.JcaPKCS8EncryptedPrivateKeyInfoBuilder;
import org.bouncycastle.pkcs.jcajce.JcePKCSPBEOutputEncryptorBuilder;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Scanner;

/**
 * Command-line tool for generating RSA key pairs with PKCS#8 encrypted private keys
 * and X.509 certificates.
 */
public class KeyGenerator {

    static {
        // Register BouncyCastle provider
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final Scanner scanner = new Scanner(System.in);

    public static void main(String[] args) {
        System.out.println("======================================================");
        System.out.println("         RSA Key Pair Generator for Secure Email      ");
        System.out.println("======================================================");

        try {
            // Get user information
            String username = promptForInput("Enter username: ");
            String organization = promptForInput("Enter organization name: ");
            String country = promptForInput("Enter country code (2 letters, e.g., VN): ");
            String email = promptForInput("Enter email address: ");

            // Get key size (minimum 2048)
            int keySize = promptForKeySize();

            // Get validity period in days
            int validityDays = promptForInt("Enter certificate validity period in days (e.g., 365): ");

            // Get password for private key
            char[] password = promptForPassword("Enter password for private key encryption: ");

            // Create output directory
            String outputDir = "keys/" + username;
            createDirectory(outputDir);

            System.out.println("\nGenerating RSA key pair...");

            // Generate key pair
            KeyPair keyPair = generateRSAKeyPair(keySize);

            // Save private key in PKCS#8 format with password protection
            String privateKeyPath = outputDir + "/private_key.pem";
            saveEncryptedPrivateKey(keyPair.getPrivate(), password, privateKeyPath);

            // Generate and save X.509 certificate
            String certPath = outputDir + "/certificate.pem";
            generateAndSaveCertificate(keyPair, username, organization, country, email, validityDays, certPath);

            System.out.println("\nKey generation completed successfully!");
            System.out.println("Private key (PKCS#8) saved to: " + privateKeyPath);
            System.out.println("Certificate (X.509) saved to: " + certPath);

        } catch (Exception e) {
            System.err.println("Error generating keys: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * Generates an RSA key pair with the specified key size
     */
    private static KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(keySize, new SecureRandom());
        return keyPairGenerator.generateKeyPair();
    }

    /**
     * Saves a private key in PKCS#8 encrypted format
     */
    private static void saveEncryptedPrivateKey(PrivateKey privateKey, char[] password, String filePath)
            throws IOException, OperatorCreationException {

        // Create PKCS#8 encrypted private key info
        JcePKCSPBEOutputEncryptorBuilder encryptorBuilder =
                new JcePKCSPBEOutputEncryptorBuilder(org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC)
                        .setProvider("BC");

        PKCS8EncryptedPrivateKeyInfo encryptedInfo =
                new JcaPKCS8EncryptedPrivateKeyInfoBuilder(privateKey)
                        .build(encryptorBuilder.build(password));

        // Write to PEM file
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(filePath))) {
            pemWriter.writeObject(encryptedInfo);
            pemWriter.flush();
        }
    }

    /**
     * Generates a self-signed X.509 certificate and saves it to a file
     */
    private static void generateAndSaveCertificate(KeyPair keyPair, String username, String organization,
                                                   String country, String email, int validityDays, String filePath)
            throws OperatorCreationException, IOException {

        // Create certificate validity period
        Calendar calendar = Calendar.getInstance();
        Date startDate = calendar.getTime();

        calendar.add(Calendar.DAY_OF_YEAR, validityDays);
        Date endDate = calendar.getTime();

        // Create certificate subject name
        String subjectDN = String.format("CN=%s,O=%s,C=%s,E=%s",
                username, organization, country, email);
        X500Name subject = new X500Name(subjectDN);

        // Generate random serial number
        BigInteger serialNumber = new BigInteger(64, new SecureRandom());

        // Create certificate builder
        SubjectPublicKeyInfo subjectPublicKeyInfo =
                SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());

        X509v3CertificateBuilder certBuilder = new X509v3CertificateBuilder(
                subject,             // Issuer = subject for self-signed
                serialNumber,        // Serial number
                startDate,           // Start date
                endDate,             // End date
                subject,             // Subject
                subjectPublicKeyInfo // Public key
        );

        // Sign the certificate with the private key
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider("BC")
                .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);

        // Convert to X509Certificate
        try {
            X509Certificate cert = new JcaX509CertificateConverter()
                    .setProvider("BC")
                    .getCertificate(certHolder);

            // Write to PEM file
            try (JcaPEMWriter pemWriter = new JcaPEMWriter(new FileWriter(filePath))) {
                pemWriter.writeObject(cert);
                pemWriter.flush();
            }

        } catch (Exception e) {
            throw new IOException("Error converting certificate: " + e.getMessage(), e);
        }
    }

    /**
     * Prompts the user for input with the given prompt text
     */
    private static String promptForInput(String prompt) {
        System.out.print(prompt);
        return scanner.nextLine().trim();
    }

    /**
     * Prompts the user for a password
     */
    private static char[] promptForPassword(String prompt) {
        System.out.print(prompt);
        return scanner.nextLine().toCharArray();
    }

    /**
     * Prompts the user for the RSA key size (minimum 2048)
     */
    private static int promptForKeySize() {
        while (true) {
            try {
                String input = promptForInput("Enter RSA key size (minimum 2048 bits): ");
                int keySize = Integer.parseInt(input);
                if (keySize < 2048) {
                    System.out.println("Key size must be at least 2048 bits. Please try again.");
                } else {
                    return keySize;
                }
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Please enter a number.");
            }
        }
    }

    /**
     * Prompts the user for an integer
     */
    private static int promptForInt(String prompt) {
        while (true) {
            try {
                String input = promptForInput(prompt);
                return Integer.parseInt(input);
            } catch (NumberFormatException e) {
                System.out.println("Invalid input. Please enter a number.");
            }
        }
    }

    /**
     * Creates a directory if it doesn't exist
     */
    private static void createDirectory(String path) {
        File directory = new File(path);
        if (!directory.exists()) {
            if (directory.mkdirs()) {
                System.out.println("Created directory: " + path);
            } else {
                System.out.println("Failed to create directory: " + path);
            }
        }
    }
}