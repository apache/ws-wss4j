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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.io.OutputStream;
import java.security.MessageDigest;

/**
 * A Streaming based message-digest implementation
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class DigestOutputStream extends OutputStream {

    protected static final transient Log log = LogFactory.getLog(DigestOutputStream.class);

    private MessageDigest messageDigest;

    private StringBuffer stringBuffer;

    public DigestOutputStream(MessageDigest messageDigest) {
        this.messageDigest = messageDigest;
        if (log.isDebugEnabled()) {
            stringBuffer = new StringBuffer();
        }
    }

    public void write(byte[] arg0) {
        write(arg0, 0, arg0.length);
    }

    public void write(int arg0) {
        messageDigest.update((byte) arg0);
        if (log.isDebugEnabled()) {
            stringBuffer.append(new String(new byte[]{(byte) arg0}));
        }
    }

    public void write(byte[] arg0, int arg1, int arg2) {
        messageDigest.update(arg0, arg1, arg2);
        if (log.isDebugEnabled()) {
            stringBuffer.append(new String(arg0, arg1, arg2));
        }
    }

    public byte[] getDigestValue() {
        if (log.isDebugEnabled()) {
            log.debug("Pre Digest: ");
            log.debug(stringBuffer.toString());
            log.debug("End pre Digest ");
            stringBuffer = new StringBuffer();
        }
        return messageDigest.digest();
    }
}
