package ch.gigerstyle.xmlsec.test;

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
    /*
    private final String testString = "Within this class we test if the IVSplittingOutputStream works correctly under different conditions";

    @Test
    public void testWriteBytes() throws Exception {

        int ivSize = 16;

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, ivSize);
        byte[] testBytes = testString.getBytes();
        for (int i = 0; i < testBytes.length; i++) {
            ivSplittingOutputStream.write(testBytes[i]);            
        }
        ivSplittingOutputStream.close();

        Assert.assertEquals(new String(ivSplittingOutputStream.getIv()), testString.substring(0, ivSize));
        Assert.assertEquals(new String(byteArrayOutputStream.toByteArray()), testString.substring(ivSize));
        Assert.assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), testString);
        Assert.assertTrue(ivSplittingOutputStream.isIVComplete());
    }

    @Test
    public void testWriteBytesArray() throws Exception {

        int ivSize = 16;

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, ivSize);
        ivSplittingOutputStream.write(testString.getBytes());
        ivSplittingOutputStream.close();

        Assert.assertEquals(new String(ivSplittingOutputStream.getIv()), testString.substring(0, ivSize));
        Assert.assertEquals(new String(byteArrayOutputStream.toByteArray()), testString.substring(ivSize));
        Assert.assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), testString);
        Assert.assertTrue(ivSplittingOutputStream.isIVComplete());
    }

    @Test
    public void testWriteBytesArrayWithOffset() throws Exception {

        int ivSize = 16;

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(byteArrayOutputStream, ivSize);

        byte[] testBytes = testString.getBytes();
        for (int i = 0; i < testBytes.length - 4; i+=4) {
            ivSplittingOutputStream.write(testBytes, i, 4);            
        }
        //write last part
        ivSplittingOutputStream.write(testBytes, testBytes.length - testBytes.length % 4, testBytes.length % 4);
        ivSplittingOutputStream.close();

        Assert.assertEquals(new String(ivSplittingOutputStream.getIv()), testString.substring(0, ivSize));
        Assert.assertEquals(new String(byteArrayOutputStream.toByteArray()), testString.substring(ivSize));
        Assert.assertEquals(new String(ivSplittingOutputStream.getIv()) + new String(byteArrayOutputStream.toByteArray()), testString);
        Assert.assertTrue(ivSplittingOutputStream.isIVComplete());
    }
    */
}
