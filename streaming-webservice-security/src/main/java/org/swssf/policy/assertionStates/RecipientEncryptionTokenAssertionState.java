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
package org.swssf.policy.assertionStates;

import org.swssf.ext.SecurityToken;
import org.swssf.ext.WSSecurityException;
import org.swssf.impl.securityToken.SecurityTokenFactory;
import org.swssf.impl.securityToken.X509SecurityToken;
import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.policy.secpolicy.model.*;
import org.swssf.securityEvent.InitiatorEncryptionTokenSecurityEvent;
import org.swssf.securityEvent.RecipientEncryptionTokenSecurityEvent;
import org.swssf.securityEvent.SecurityEvent;

import java.security.cert.X509Certificate;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */

//todo generify this class and rename it to TokenAssertionState ??
public class RecipientEncryptionTokenAssertionState extends AssertionState {

    public RecipientEncryptionTokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) {

        SecurityToken securityToken = null;

        switch (securityEvent.getSecurityEventType()) {
            //todo NPE's? Could it be that we don't have a wrapping token?
            //todo either generify this class or remove the InitiatorEncryptionToken case:
            case InitiatorEncryptionToken:
                InitiatorEncryptionTokenSecurityEvent initiatorEncryptionTokenSecurityEvent = (InitiatorEncryptionTokenSecurityEvent) securityEvent;
                securityToken = initiatorEncryptionTokenSecurityEvent.getSecurityToken().getKeyWrappingToken();
                break;
            case RecipientEncryptionToken:
                RecipientEncryptionTokenSecurityEvent recipientEncryptionTokenSecurityEvent = (RecipientEncryptionTokenSecurityEvent) securityEvent;
                securityToken = recipientEncryptionTokenSecurityEvent.getSecurityToken().getKeyWrappingToken();

                break;
        }

        //todo enumerate TokenTypes
        Token token = (Token) getAssertion();
        if (token instanceof HttpsToken) {
            assertHttpsToken((HttpsToken) token, securityToken);
        } else if (token instanceof IssuedToken) {
            assertIssuedToken((IssuedToken) token, securityToken);
        } else if (token instanceof SecureConversationToken) {
            assertSecureConversationToken((SecureConversationToken) token, securityToken);
        } else if (token instanceof UsernameToken) {
            assertUsernameToken((UsernameToken) token, securityToken);
        } else if (token instanceof X509Token) {
            assertX509Token((X509Token) token, securityToken);
        }

        return isAsserted();
    }

    private void assertHttpsToken(HttpsToken httpsToken, SecurityToken securityToken) {
    }

    private void assertIssuedToken(IssuedToken issuedToken, SecurityToken securityToken) {
    }

    private void assertSecureConversationToken(SecureConversationToken secureConversationToken, SecurityToken securityToken) {
    }

    private void assertUsernameToken(UsernameToken usernameToken, SecurityToken securityToken) {
    }

    private void assertX509Token(X509Token x509Token, SecurityToken securityToken) {
        if (!(securityToken instanceof X509SecurityToken)) {
            setAsserted(false);
            setErrorMessage("Expected a X509 Token");
        }
        X509SecurityToken x509SecurityToken = (X509SecurityToken) securityToken;

        setAsserted(true);

        try {
            X509Certificate x509Certificate = x509SecurityToken.getX509Certificate();
            if (x509Token.getIssuerName() != null) {
                final String certificateIssuerName = x509Certificate.getSubjectX500Principal().getName();
                if (!x509Token.getIssuerName().equals(certificateIssuerName)) {
                    setAsserted(false);
                    setErrorMessage("IssuerName in Policy (" + x509Token.getIssuerName() + ") didn't match with the one in the certificate (" + certificateIssuerName + ")");
                }
            }
            if (x509Token.getTokenVersionAndType() != null) {
                if ((x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_V3_TOKEN10) || x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_V3_TOKEN11)) && x509Certificate.getVersion() != 3) {
                    setAsserted(false);
                    setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " mismatch; Policy enforces " + x509Token.getTokenVersionAndType());
                } else if ((x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_V1_TOKEN10) || x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_V1_TOKEN11)) && x509Certificate.getVersion() != 1) {
                    setAsserted(false);
                    setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " mismatch; Policy enforces " + x509Token.getTokenVersionAndType());
                } else if (x509Certificate.getVersion() == 2) {
                    setAsserted(false);
                    setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " not supported");
                }
            }
        } catch (WSSecurityException e) {
            setAsserted(false);
            setErrorMessage(e.getMessage());
        }
    }
}
