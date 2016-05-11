package net.myrts.jce.utils;

/**
 * Encrption container.
 *
 * @author <a href="mailto:vzhovtiuk@gmail.com">Vitaliy Zhovtyuk</a>
 *         Date: 5/9/16
 *         Time: 1:36 PM
 */
public class EncryptionResult {
    /**
     * Encrypted string.
     */
    private final String encryptedString;
    /**
     * Init vector.
     */
    private final String initVector;

    public EncryptionResult(String encryptedString, String initVector) {
        this.encryptedString = encryptedString;
        this.initVector = initVector;
    }

    public String getEncryptedString() {
        return encryptedString;
    }

    public String getInitVector() {
        return initVector;
    }
}
