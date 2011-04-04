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
package org.swssf.impl.securityToken;

import org.swssf.crypto.Crypto;
import org.swssf.ext.Constants;
import org.swssf.ext.WSSecurityException;

import javax.security.auth.callback.CallbackHandler;
import java.security.cert.X509Certificate;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public class X509PKIPathv1SecurityToken extends X509SecurityToken {
    private String alias = null;
    private X509Certificate x509Certificate;

    X509PKIPathv1SecurityToken(Crypto crypto, CallbackHandler callbackHandler, byte[] binaryContent) throws WSSecurityException {
        super(crypto, callbackHandler);
        X509Certificate[] x509Certificates = crypto.getX509Certificates(binaryContent, false);
        if (x509Certificates != null && x509Certificates.length > 0) {
            this.x509Certificate = x509Certificates[0];
        }
    }

    protected String getAlias() throws WSSecurityException {
        if (this.alias == null) {
            this.alias = getCrypto().getAliasForX509Cert(this.x509Certificate);
        }
        return this.alias;
    }

    @Override
    public X509Certificate getX509Certificate() throws WSSecurityException {
        return this.x509Certificate;
    }

    public Constants.KeyIdentifierType getKeyIdentifierType() {
        return Constants.KeyIdentifierType.BST_EMBEDDED;
    }
}
