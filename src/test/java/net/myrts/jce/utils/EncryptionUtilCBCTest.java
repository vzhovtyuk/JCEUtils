package net.myrts.jce.utils;

import org.junit.Test;
import static net.myrts.jce.utils.EncryptionUtil.decryptAES256CBC;
import static net.myrts.jce.utils.EncryptionUtil.encryptAES256CBC;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Created by IntelliJ IDEA.
 *
 * @author <a href="mailto:vzhovtiuk@gmail.com">Vitaliy Zhovtyuk</a>
 *         Date: 5/4/16
 *         Time: 4:10 PM
 */
public class EncryptionUtilCBCTest {
    @Test
    public void shouldEncryptString() throws Exception {
        // given
        String encodedSecureKey = "77ffdeeb7fd6ac8bcf415479ba2e400c471ea2b1f22fc84abe620f2dc25cb101";
        String text = "PasswordToEncrypt";

        // when
        EncryptionResult encryptedContent = encryptAES256CBC(text.toCharArray(), encodedSecureKey.toCharArray());

        // then
        assertNotNull("Encrypted string does not provided ", encryptedContent.getEncryptedString());
        assertNotNull("Encrypted init vector does not provided ", encryptedContent.getInitVector());
    }

    @Test
    public void shouldDecryptString() throws Exception {
        // given
        String encodedSecureKey = "77ffdeeb7fd6ac8bcf415479ba2e400c471ea2b1f22fc84abe620f2dc25cb101";
        String text = "FtE0ImplJTE9q5oCjvab3IwG++Nk8yzuGyWxD9f1+Mk=";
        String iv = "IqrAbiMO2AzN1BgEZljVmw==";

        // when

        String decryptedContent = decryptAES256CBC(text.toCharArray(), encodedSecureKey.toCharArray(), 
                iv);

        // then
        assertEquals("Decrypted string does not match for " + text, "PasswordToEncrypt", decryptedContent);
    }
}
