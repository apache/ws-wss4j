package ch.gigerstyle.xmlsec.test;

import ch.gigerstyle.xmlsec.impl.util.IVSplittingOutputStream;
import ch.gigerstyle.xmlsec.impl.util.ReplaceableOuputStream;
import org.testng.Assert;
import org.testng.annotations.Test;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.ByteArrayOutputStream;

/**
 * User: giger
 * Date: Jul 11, 2010
 * Time: 11:01:54 AM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
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
