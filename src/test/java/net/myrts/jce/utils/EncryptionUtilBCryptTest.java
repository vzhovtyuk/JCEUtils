package net.myrts.jce.utils;

import org.junit.Test;

import static net.myrts.jce.utils.EncryptionUtil.encryptBCrypt;
import static net.myrts.jce.utils.EncryptionUtil.generateBCryptSalt;
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
public class EncryptionUtilBCryptTest {
    @Test
    public void shouldGenerateSalt() throws Exception {
        // given
        // when
        String encryptedContent = generateBCryptSalt(10);
        // then
        assertNotNull("Generated salt does not match for " + encryptedContent, 
                String.valueOf(encryptedContent));
    }
    
    
    @Test
    public void shouldHashPass() throws Exception {
        // given
        String content = "sfjdkhfjdsk";
        String salt = "$2a$10$Sjez/As/DVV0msM1RfsOKu";
        
        // when

        String encryptedContent = encryptBCrypt(content, salt);

        // then
        assertEquals("Decrypted string does not match for " + content, 
                "$2a$10$Sjez/As/DVV0msM1RfsOKuEs6Vnpsg67yANCJDiZUTWA8cTCrRDvy", String.valueOf(encryptedContent));
    }
}
