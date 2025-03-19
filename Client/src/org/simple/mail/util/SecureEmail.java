package org.simple.mail.util;

/**
 * Represents a secure email with encrypted contents
 * Used to format and parse secure emails
 */
public class SecureEmail {
    private String base64Signature;
    private String base64IV;
    private String base64EncryptedKey;
    private String base64EncryptedContent;

    /**
     * Creates a new secure email with the given components
     */
    public SecureEmail(String base64Signature, String base64IV,
                       String base64EncryptedKey, String base64EncryptedContent) {
        this.base64Signature = base64Signature;
        this.base64IV = base64IV;
        this.base64EncryptedKey = base64EncryptedKey;
        this.base64EncryptedContent = base64EncryptedContent;
    }

    /**
     * Parses a secure email from raw text
     */
    public static SecureEmail parseFromString(String rawEmail) {
        String base64Signature = null;
        String base64IV = null;
        String base64EncryptedKey = null;
        String base64EncryptedContent = null;

        String[] lines = rawEmail.split("\n");
        for (String line : lines) {
            if (line.startsWith("SIG: ")) {
                base64Signature = line.substring(5).trim();
            } else if (line.startsWith("IV: ")) {
                base64IV = line.substring(4).trim();
            } else if (line.startsWith("KEY: ")) {
                base64EncryptedKey = line.substring(5).trim();
            } else if (line.startsWith("BODY: ")) {
                base64EncryptedContent = line.substring(6).trim();
            }
        }

        if (base64Signature == null || base64IV == null ||
                base64EncryptedKey == null || base64EncryptedContent == null) {
            throw new IllegalArgumentException("Invalid secure email format: missing required fields");
        }

        return new SecureEmail(base64Signature, base64IV, base64EncryptedKey, base64EncryptedContent);
    }

    /**
     * Determines if a raw email is in secure format
     */
    public static boolean isSecureEmail(String rawEmail) {
        return rawEmail.contains("SIG:") &&
                rawEmail.contains("IV:") &&
                rawEmail.contains("KEY:") &&
                rawEmail.contains("BODY:");
    }

    /**
     * Formats the secure email as a string
     */
    @Override
    public String toString() {
        StringBuilder builder = new StringBuilder();
        builder.append("SIG: ").append(base64Signature).append("\n");
        builder.append("IV: ").append(base64IV).append("\n");
        builder.append("KEY: ").append(base64EncryptedKey).append("\n");
        builder.append("BODY: ").append(base64EncryptedContent).append("\n");
        return builder.toString();
    }

    // Getters
    public String getBase64Signature() {
        return base64Signature;
    }

    public String getBase64IV() {
        return base64IV;
    }

    public String getBase64EncryptedKey() {
        return base64EncryptedKey;
    }

    public String getBase64EncryptedContent() {
        return base64EncryptedContent;
    }
}