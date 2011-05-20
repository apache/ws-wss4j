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

import org.opensaml.common.SAMLVersion;
import org.swssf.crypto.Crypto;
import org.swssf.ext.Constants;
import org.swssf.ext.SecurityToken;
import org.swssf.ext.WSSecurityException;
import org.swssf.impl.saml.SAMLKeyInfo;

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
public class SAMLSecurityToken extends AbstractSecurityToken {

    private SAMLVersion samlVersion;
    private SAMLKeyInfo samlKeyInfo;
    private X509Certificate[] x509Certificate;

    public SAMLSecurityToken(SAMLVersion samlVersion, SAMLKeyInfo samlKeyInfo, Crypto crypto, CallbackHandler callbackHandler, String id, Object processor) {
        super(crypto, callbackHandler, id, processor);
        this.samlVersion = samlVersion;
        this.samlKeyInfo = samlKeyInfo;
    }

    public boolean isAsymmetric() {
        return true;
    }

    public Key getSecretKey(String algorithmURI) throws WSSecurityException {
        return samlKeyInfo.getPrivateKey();
    }

    public PublicKey getPublicKey() throws WSSecurityException {
        PublicKey publicKey = samlKeyInfo.getPublicKey();
        if (publicKey == null) {
            publicKey = getX509Certificates()[0].getPublicKey();
        }
        return publicKey;
    }

    public X509Certificate[] getX509Certificates() throws WSSecurityException {
        if (this.x509Certificate == null) {
            this.x509Certificate = samlKeyInfo.getCerts();
        }
        return this.x509Certificate;
    }

    public void verify() throws WSSecurityException {
        try {
            X509Certificate[] x509Certificates = getX509Certificates();
            if (x509Certificates != null && x509Certificates.length > 0) {
                x509Certificates[0].checkValidity();
                getCrypto().verifyTrust(x509Certificates);
            }
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

    public Constants.KeyIdentifierType getKeyIdentifierType() {
        if (samlVersion == SAMLVersion.VERSION_10 || samlVersion == SAMLVersion.VERSION_11) {
            return Constants.KeyIdentifierType.SAML_10;
        }
        return Constants.KeyIdentifierType.SAML_20;
    }

    public SAMLKeyInfo getSamlKeyInfo() {
        return samlKeyInfo;
    }
}
