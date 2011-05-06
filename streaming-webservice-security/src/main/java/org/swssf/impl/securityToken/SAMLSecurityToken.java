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

import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.crypto.Crypto;
import org.swssf.ext.Constants;
import org.swssf.ext.SecurityToken;
import org.swssf.ext.WSSecurityException;
import org.swssf.impl.saml.SAMLKeyInfo;

import javax.crypto.spec.SecretKeySpec;
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

    private SAMLKeyInfo samlKeyInfo;
    private X509Certificate x509Certificate;

    public SAMLSecurityToken(SAMLKeyInfo samlKeyInfo, Crypto crypto, CallbackHandler callbackHandler) {
        super(crypto, callbackHandler);
        this.samlKeyInfo = samlKeyInfo;
    }

    public boolean isAsymmetric() {
        return true;
    }

    public Key getSecretKey(String algorithmURI) throws WSSecurityException {
        String algoFamily = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(algorithmURI);
        return new SecretKeySpec(samlKeyInfo.getSecret(), algoFamily);
    }

    public PublicKey getPublicKey() throws WSSecurityException {
        PublicKey publicKey = samlKeyInfo.getPublicKey();
        if (publicKey == null) {
            publicKey = getX509Certificate().getPublicKey();
        }
        return publicKey;
    }

    public void verify() throws WSSecurityException {
        try {
            X509Certificate x509Certificate = getX509Certificate();
            if (x509Certificate != null) {
                x509Certificate.checkValidity();
                getCrypto().validateCert(x509Certificate);
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
        return null;
    }

    public X509Certificate getX509Certificate() throws WSSecurityException {
        if (this.x509Certificate == null) {
            X509Certificate[] x509Certificates = samlKeyInfo.getCerts();
            if (x509Certificates == null || x509Certificates.length == 0) {
                return null;
            }
            this.x509Certificate = x509Certificates[0];
        }
        return this.x509Certificate;
    }
}
