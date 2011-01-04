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
package org.swssf.impl.util;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;

/**
 * IV splitting from the first few bytes in the stream.
 * When the iv is completely received the cipher will be initialized
 * and this output stream will be removed from chain of output streams
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class IVSplittingOutputStream extends FilterOutputStream {

    private ReplaceableOuputStream replaceableOuputStream;

    private byte[] iv;
    private int ivLength;
    private int pos = 0;

    private Cipher cipher;
    private Key secretKey;

    public IVSplittingOutputStream(OutputStream out, Cipher cipher, Key secretKey) {
        super(out);
        ivLength = cipher.getBlockSize();
        iv = new byte[ivLength];
        this.cipher = cipher;
        this.secretKey = secretKey;
    }

    public byte[] getIv() {
        return iv;
    }

    public boolean isIVComplete() {
        return pos == iv.length;
    }

    private void initializeCipher() throws IOException {
        IvParameterSpec iv = new IvParameterSpec(this.getIv());
        try {
            cipher.init(Cipher.DECRYPT_MODE, secretKey, iv);
        } catch (InvalidKeyException e) {
            throw new IOException(e);
        } catch (InvalidAlgorithmParameterException e) {
            throw new IOException(e);
        }
    }

    @Override
    public void write(int b) throws IOException {
        if (pos >= ivLength) {
            initializeCipher();
            out.write(b);
            replaceableOuputStream.setNewOutputStream(out);
            return;
        }
        iv[pos++] = (byte) b;
    }

    @Override
    public void write(byte[] b) throws IOException {
        write(b, 0, b.length);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        int missingBytes = ivLength - pos;
        if (missingBytes > len) {
            System.arraycopy(b, off, iv, pos, len);
            pos += len;
        } else {
            System.arraycopy(b, off, iv, pos, missingBytes);
            pos += missingBytes;
            initializeCipher();
            out.write(b, off + missingBytes, len - missingBytes);
            replaceableOuputStream.setNewOutputStream(out);
        }
    }

    public void setParentOutputStream(ReplaceableOuputStream replaceableOuputStream) {
        this.replaceableOuputStream = replaceableOuputStream;
    }
}
