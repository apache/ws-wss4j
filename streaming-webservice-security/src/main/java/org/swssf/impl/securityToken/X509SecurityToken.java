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
import org.swssf.ext.SecurityToken;
import org.swssf.ext.Utils;
import org.swssf.ext.WSPasswordCallback;
import org.swssf.ext.WSSecurityException;

import javax.security.auth.callback.CallbackHandler;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;

/**
 * @author $Author: $
 * @version $Revision: $ $Date: $
 */
public abstract class X509SecurityToken extends AbstractSecurityToken {
    private X509Certificate x509Certificate = null;

    X509SecurityToken(Crypto crypto, CallbackHandler callbackHandler) {
        super(crypto, callbackHandler);
    }

    public boolean isAsymmetric() {
        return true;
    }

    public Key getSecretKey(String algorithmURI) throws WSSecurityException {
        WSPasswordCallback pwCb = new WSPasswordCallback(getAlias(), WSPasswordCallback.DECRYPT);
        Utils.doCallback(getCallbackHandler(), pwCb);
        return getCrypto().getPrivateKey(getAlias(), pwCb.getPassword());
    }

    public PublicKey getPublicKey() throws WSSecurityException {
        X509Certificate x509Certificate = getX509Certificate();
        if (x509Certificate == null) {
            return null;
        }
        return x509Certificate.getPublicKey();
    }

    //todo testing:
    public void verify() throws WSSecurityException {
        try {
            X509Certificate x509Certificate = getX509Certificate();
            if (x509Certificate != null) {
                x509Certificate.checkValidity();
            }
            getCrypto().validateCert(x509Certificate);
        } catch (CertificateExpiredException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, e);
        } catch (CertificateNotYetValidException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, null, e);
        }
    }

    public SecurityToken getKeyWrappingToken() {
        return null;
    }

    public String getKeyWrappingTokenAlgorithm() {
        return null;
    }

    public X509Certificate getX509Certificate() throws WSSecurityException {
        if (this.x509Certificate == null) {
            X509Certificate[] x509Certificates = getCrypto().getCertificates(getAlias());
            if (x509Certificates.length == 0) {
                return null;
            }
            this.x509Certificate = x509Certificates[0];
        }
        return this.x509Certificate;
    }

    protected abstract String getAlias() throws WSSecurityException;
}
