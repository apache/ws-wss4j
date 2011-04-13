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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.swssf.ext.WSSecurityException;
import org.swssf.impl.algorithms.SignatureAlgorithm;

import java.io.OutputStream;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class SignerOutputStream extends OutputStream {

    protected static final transient Log log = LogFactory.getLog(SignerOutputStream.class);

    private final SignatureAlgorithm signatureAlgorithm;
    private StringBuffer stringBuffer;

    public SignerOutputStream(SignatureAlgorithm signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
        if (log.isDebugEnabled()) {
            stringBuffer = new StringBuffer();
        }
    }

    public void write(byte[] arg0) {
        write(arg0, 0, arg0.length);
    }

    public void write(int arg0) {
        try {
            signatureAlgorithm.engineUpdate((byte) arg0);
            if (log.isDebugEnabled()) {
                stringBuffer.append(new String(new byte[]{(byte) arg0}));
            }
        } catch (WSSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public void write(byte[] arg0, int arg1, int arg2) {
        try {
            signatureAlgorithm.engineUpdate(arg0, arg1, arg2);
            if (log.isDebugEnabled()) {
                stringBuffer.append(new String(arg0, arg1, arg2));
            }
        } catch (WSSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verify(byte[] signatureValue) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Pre Signed: ");
            log.debug(stringBuffer.toString());
            log.debug("End pre Signed ");
            stringBuffer = new StringBuffer();
        }
        return signatureAlgorithm.engineVerify(signatureValue);
    }

    public byte[] sign() throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Pre Signed: ");
            log.debug(stringBuffer.toString());
            log.debug("End pre Signed ");
            stringBuffer = new StringBuffer();
        }
        return signatureAlgorithm.engineSign();
    }
}