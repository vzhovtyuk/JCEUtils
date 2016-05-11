package net.myrts.jce.utils;

import org.junit.Test;
import static net.myrts.jce.utils.EncryptionUtil.decryptAES256CFB;
import static net.myrts.jce.utils.EncryptionUtil.encryptAES256CFB;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Created by IntelliJ IDEA.
 *
 * @author <a href="mailto:vzhovtiuk@gmail.com">Vitaliy Zhovtyuk</a>
 *         Date: 5/4/16
 *         Time: 4:10 PM
 */
public class EncryptionUtilCFBTest {
    @Test
    public void shouldEncryptString() throws Exception {
        // given
        String encodedSecureKey = "77ffdeeb7fd6ac8bcf415479ba2e400c471ea2b1f22fc84abe620f2dc25cb101";
        String text = "PasswordToEncrypt";

        // when
        EncryptionResult encryptedContent = encryptAES256CFB(text.toCharArray(), encodedSecureKey.toCharArray());

        // then
        assertNotNull("Encrypted string does not provided ", encryptedContent.getEncryptedString());
        assertNotNull("Encrypted init vector does not provided ", encryptedContent.getInitVector());
    }

 @Test
    public void shouldEncryptStringGenerateKey() throws Exception {
        // given
     String text = "PasswordToEncrypt";
     char[] encodedSecureKey = EncryptionUtil.generateSecretKey(text.toCharArray(), EncryptionUtil.getSalt());

        // when
        EncryptionResult encryptedContent = encryptAES256CFB(text.toCharArray(), encodedSecureKey);

        // then
        assertNotNull("Encrypted string does not provided ", encryptedContent.getEncryptedString());
        assertNotNull("Encrypted init vector does not provided ", encryptedContent.getInitVector());
    }

    @Test
    public void shouldDecryptString() throws Exception {
        // given
        String encodedSecureKey = "77ffdeeb7fd6ac8bcf415479ba2e400c471ea2b1f22fc84abe620f2dc25cb101";
        String text = "n3/8kpixYzkkQvksa8UYDhTwowoPQrU262I+hgbmJkw=";
        String iv = "3NxCHqCpzJ3C4fLaFs0cJg==";

        // when

        String decryptedContent = decryptAES256CFB(text.toCharArray(), encodedSecureKey.toCharArray(),
                iv);

        // then
        assertEquals("Decrypted string does not match for " + text, "PasswordToEncrypt", decryptedContent);
    }
}
