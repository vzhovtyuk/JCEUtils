package net.myrts.jce.utils;

import org.junit.Test;

import static net.myrts.jce.utils.EncryptionUtil.decryptAES256ECB;
import static net.myrts.jce.utils.EncryptionUtil.encryptAES256ECB;
import static org.junit.Assert.assertEquals;

/**
 * Created by IntelliJ IDEA.
 *
 * @author <a href="mailto:vzhovtiuk@gmail.com">Vitaliy Zhovtyuk</a>
 *         Date: 5/4/16
 *         Time: 4:10 PM
 */
public class EncryptionUtilECBTest {
    @Test
    public void shouldEncryptString() throws Exception {
        // given
        String encodedSecureKey = "77ffdeeb7fd6ac8bcf415479ba2e400c471ea2b1f22fc84abe620f2dc25cb101";
        String text = "PasswordToEncrypt";

        // when
        String encryptedContent = encryptAES256ECB(text.toCharArray(), encodedSecureKey.toCharArray());

        // then
        assertEquals("Encrypted string does not match for " + text, "Hz2w1/jiJm5DdONWYiAVhD88Rg6byZIVGAuoubVT5hQ=", encryptedContent);
    }

    @Test
    public void shouldDecryptString() throws Exception {
        // given
        String encodedSecureKey = "77ffdeeb7fd6ac8bcf415479ba2e400c471ea2b1f22fc84abe620f2dc25cb101";
        String text = "Hz2w1/jiJm5DdONWYiAVhD88Rg6byZIVGAuoubVT5hQ=";

        // when

        String decryptedContent = decryptAES256ECB(text.toCharArray(), encodedSecureKey.toCharArray());

        // then
        assertEquals("Decrypted string does not match for " + text, "PasswordToEncrypt", decryptedContent);
    }
}
