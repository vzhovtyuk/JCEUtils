package net.myrts.jce.utils;

import org.junit.Test;
import static net.myrts.jce.utils.EncryptionUtil.generateSecretKey;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 * Created by IntelliJ IDEA.
 *
 * @author <a href="mailto:vzhovtiuk@gmail.com">Vitaliy Zhovtyuk</a>
 *         Date: 5/4/16
 *         Time: 4:10 PM
 */
public class EncryptionUtilTest {
    @Test
    public void shouldGenerateSecretKey() throws Exception {
        // given
        String salt = "efbfbdefbfbdcda3efbfbd7eefbfbdefbfbdefbfbd423cefbfbdefbfbd7310efbfbdefbfbd465131";
        String text = "PasswordToEncrypt";

        // when

        char[] encryptedContent = generateSecretKey(text.toCharArray(), salt);

        // then
        assertEquals("Decrypted string does not match for " + text, 
                "77ffdeeb7fd6ac8bcf415479ba2e400c471ea2b1f22fc84abe620f2dc25cb101", String.valueOf(encryptedContent));
    }

   @Test
    public void shouldGenerateSalt() throws Exception {
        // given
        // when
        String generatedSalt = EncryptionUtil.getSalt();

        // then
       assertNotNull("Salt was not generated", generatedSalt);
    }

}
