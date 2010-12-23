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
package ch.gigerstyle.xmlsec.impl.util;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class TrimmerOutputStream extends FilterOutputStream {

    private byte[] buffer;
    private int bufferedCount;

    private int preTrimmed = 0;
    private int startTrimLength;
    private int endTrimLength;

    public TrimmerOutputStream(OutputStream out, int bufferSize, int startTrimLength, int endTrimLength) {
        super(out);
        if (bufferSize <= 0) {
            throw new IllegalArgumentException("bufferSize <= 0");
        }
        if (bufferSize < endTrimLength) {
            throw new IllegalArgumentException("bufferSize < endTrimLength");
        }
        this.buffer = new byte[bufferSize];
        this.startTrimLength = startTrimLength;
        this.endTrimLength = endTrimLength;
    }

    private void flushBuffer() throws IOException {
        if (bufferedCount >= endTrimLength) {
            //write all but the possible end (endTrimLength)
            out.write(buffer, 0, bufferedCount - endTrimLength);
            System.arraycopy(buffer, bufferedCount - endTrimLength, buffer, 0, endTrimLength);
            bufferedCount = endTrimLength;
        }
    }

    @Override
    public void write(int b) throws IOException {
        if (preTrimmed < startTrimLength) {
            //discard byte
            preTrimmed++;
            return;
        }
        if (bufferedCount >= buffer.length) {
            flushBuffer();
        }
        buffer[bufferedCount++] = (byte) b;
    }

    @Override
    public void write(byte[] b) throws IOException {
        write(b, 0, b.length);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (preTrimmed < startTrimLength) {
            int missingBytes = startTrimLength - preTrimmed;
            if (missingBytes >= len) {
                //discard bytes
                preTrimmed += len;
                return;
            }
            len -= missingBytes;
            off += missingBytes;
            preTrimmed += missingBytes;
        }

        if (len >= (buffer.length - bufferedCount)) {
            out.write(buffer, 0, bufferedCount);
            out.write(b, off, len - endTrimLength);
            System.arraycopy(b, (off + len) - endTrimLength, buffer, 0, endTrimLength);
            bufferedCount = endTrimLength;
            return;
        }

        System.arraycopy(b, off, buffer, bufferedCount, len);
        bufferedCount += len;
    }

    @Override
    public void flush() throws IOException {
        flushBuffer();
        out.flush();
    }
}
