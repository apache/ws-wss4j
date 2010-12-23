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
import java.security.Signature;
import java.security.SignatureException;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SignerOutputStream extends OutputStream {

    protected static final transient Log log = LogFactory.getLog(SignerOutputStream.class);

    private final Signature signature;

    public SignerOutputStream(Signature signature) {
        this.signature = signature;
    }

    public void write(byte[] arg0) {
        write(arg0, 0, arg0.length);
    }

    public void write(int arg0) {
        try {
            signature.update((byte) arg0);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    public void write(byte[] arg0, int arg1, int arg2) {
        try {
            signature.update(arg0, arg1, arg2);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean verify(byte[] signatureValue) throws SignatureException {
        return signature.verify(signatureValue);
    }

    public byte[] sign() throws SignatureException {
        return signature.sign();
    }
}