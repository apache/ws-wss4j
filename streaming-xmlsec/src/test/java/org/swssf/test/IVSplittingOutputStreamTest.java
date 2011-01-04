/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.test;

import org.swssf.impl.util.IVSplittingOutputStream;
import org.swssf.impl.util.ReplaceableOuputStream;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class IVSplittingOutputStreamTest {

    private final String testString = "Within this class we test if the IVSplittingOutputStream works correctly under different conditions";

    @Test
    public void testWriteBytes() throws Exception {

        int ivSize = 16;

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, cipher, secretKey);
        ReplaceableOuputStream replaceableOuputStream = new ReplaceableOuputStream(ivSplittingOutputStream);
        ivSplittingOutputStream.setParentOutputStream(replaceableOuputStream);
        byte[] testBytes = testString.getBytes();
        for (int i = 0; i < testBytes.length; i++) {
            replaceableOuputStream.write(testBytes[i]);
        }
        replaceableOuputStream.close();

        Assert.assertEquals(new String(ivSplittingOutputStream.getIv()), testString.substring(0, ivSize));
        Assert.assertEquals(new String(byteArrayOutputStream.toByteArray()), testString.substring(ivSize));
        Assert.assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), testString);
        Assert.assertTrue(ivSplittingOutputStream.isIVComplete());
    }

    @Test
    public void testWriteBytesArray() throws Exception {

        int ivSize = 16;

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, cipher, secretKey);
        ReplaceableOuputStream replaceableOuputStream = new ReplaceableOuputStream(ivSplittingOutputStream);
        ivSplittingOutputStream.setParentOutputStream(replaceableOuputStream);
        replaceableOuputStream.write(testString.getBytes());
        replaceableOuputStream.close();

        Assert.assertEquals(new String(ivSplittingOutputStream.getIv()), testString.substring(0, ivSize));
        Assert.assertEquals(new String(byteArrayOutputStream.toByteArray()), testString.substring(ivSize));
        Assert.assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), testString);
        Assert.assertTrue(ivSplittingOutputStream.isIVComplete());
    }

    @Test
    public void testWriteBytesArrayWithOffset() throws Exception {

        int ivSize = 16;

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance("AES/CBC/ISO10126Padding");

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, cipher, secretKey);
        ReplaceableOuputStream replaceableOuputStream = new ReplaceableOuputStream(ivSplittingOutputStream);
        ivSplittingOutputStream.setParentOutputStream(replaceableOuputStream);

        byte[] testBytes = testString.getBytes();
        for (int i = 0; i < testBytes.length - 4; i += 4) {
            replaceableOuputStream.write(testBytes, i, 4);
        }
        //write last part
        replaceableOuputStream.write(testBytes, testBytes.length - testBytes.length % 4, testBytes.length % 4);
        replaceableOuputStream.close();

        Assert.assertEquals(new String(ivSplittingOutputStream.getIv()), testString.substring(0, ivSize));
        Assert.assertEquals(new String(byteArrayOutputStream.toByteArray()), testString.substring(ivSize));
        Assert.assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), testString);
        Assert.assertTrue(ivSplittingOutputStream.isIVComplete());
    }
}
