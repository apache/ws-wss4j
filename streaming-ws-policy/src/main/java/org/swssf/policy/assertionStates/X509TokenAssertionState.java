/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.swssf.policy.assertionStates;

import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.secpolicy.model.AbstractSecurityAssertion;
import org.apache.ws.secpolicy.model.AbstractToken;
import org.apache.ws.secpolicy.model.X509Token;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.impl.securityToken.DelegatingSecurityToken;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.TokenSecurityEvent;
import org.swssf.wss.securityEvent.X509TokenSecurityEvent;
import org.swssf.xmlsec.ext.SecurityToken;
import org.swssf.xmlsec.ext.XMLSecurityConstants;
import org.swssf.xmlsec.ext.XMLSecurityException;

import java.security.cert.X509Certificate;

/**
 * @author $Author: giger $
 * @version $Revision: 1197077 $ $Date: 2011-11-03 13:17:40 +0100 (Don, 03. Nov 2011) $
 */

public class X509TokenAssertionState extends TokenAssertionState {

    public X509TokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public SecurityEvent.Event[] getSecurityEventType() {
        return new SecurityEvent.Event[]{
                SecurityEvent.Event.X509Token
        };
    }

    @Override
    public void assertToken(TokenSecurityEvent tokenSecurityEvent, AbstractToken abstractToken) throws WSSPolicyException {
        if (!(tokenSecurityEvent instanceof X509TokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a X509TokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }

        X509Token x509Token = (X509Token) abstractToken;
        SecurityToken securityToken = tokenSecurityEvent.getSecurityToken();
        XMLSecurityConstants.TokenType tokenType = securityToken.getTokenType();
        if (!(WSSConstants.X509V3Token.equals(tokenType)
                || WSSConstants.X509V1Token.equals(tokenType)
                || WSSConstants.X509Pkcs7Token.equals(tokenType)
                || WSSConstants.X509PkiPathV1Token.equals(tokenType))
                && !(securityToken instanceof DelegatingSecurityToken)) {
            throw new WSSPolicyException("Invalid Token for this assertion");
        }
        DelegatingSecurityToken delegatingSecurityToken = (DelegatingSecurityToken) securityToken;
        setAsserted(true);
        try {
            X509Certificate x509Certificate = delegatingSecurityToken.getX509Certificates()[0];
            if (x509Token.getIssuerName() != null) {
                final String certificateIssuerName = x509Certificate.getIssuerX500Principal().getName();
                if (!x509Token.getIssuerName().equals(certificateIssuerName)) {
                    setAsserted(false);
                    setErrorMessage("IssuerName in Policy (" + x509Token.getIssuerName() + ") didn't match with the one in the certificate (" + certificateIssuerName + ")");
                }
            }
            if (x509Token.isRequireKeyIdentifierReference() && delegatingSecurityToken.getKeyIdentifierType() != WSSConstants.KeyIdentifierType.X509_KEY_IDENTIFIER) {
                setAsserted(false);
                setErrorMessage("Policy enforces KeyIdentifierReference but we got " + delegatingSecurityToken.getTokenType());
            } else if (x509Token.isRequireIssuerSerialReference() && delegatingSecurityToken.getKeyIdentifierType() != WSSConstants.KeyIdentifierType.ISSUER_SERIAL) {
                setAsserted(false);
                setErrorMessage("Policy enforces IssuerSerialReference but we got " + delegatingSecurityToken.getTokenType());
            } else if (x509Token.isRequireEmbeddedTokenReference() && delegatingSecurityToken.getKeyIdentifierType() != WSSConstants.KeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE) {
                setAsserted(false);
                setErrorMessage("Policy enforces EmbeddedTokenReference but we got " + delegatingSecurityToken.getTokenType());
            } else if (x509Token.isRequireThumbprintReference() && delegatingSecurityToken.getKeyIdentifierType() != WSSConstants.KeyIdentifierType.THUMBPRINT_IDENTIFIER) {
                setAsserted(false);
                setErrorMessage("Policy enforces ThumbprintReference but we got " + delegatingSecurityToken.getTokenType());
            }
            if (x509Certificate.getVersion() == 2) {
                setAsserted(false);
                setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " not supported");
            }
            switch (x509Token.getTokenType()) {
                case WssX509V3Token10:
                case WssX509V3Token11:
                    if (WSSConstants.X509V3Token != delegatingSecurityToken.getTokenType() || x509Certificate.getVersion() != 3) {
                        setAsserted(false);
                        setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " mismatch; Policy enforces " + x509Token.getTokenType());
                    }
                    break;
                case WssX509V1Token11:
                    if (WSSConstants.X509V1Token != delegatingSecurityToken.getTokenType() || x509Certificate.getVersion() != 1) {
                        setAsserted(false);
                        setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " mismatch; Policy enforces " + x509Token.getTokenType());
                    }
                    break;
                case WssX509PkiPathV1Token10:
                case WssX509PkiPathV1Token11:
                    if (delegatingSecurityToken.getTokenType() != WSSConstants.X509PkiPathV1Token) {
                        setAsserted(false);
                        setErrorMessage("Policy enforces " + x509Token.getTokenType() + " but we got " + delegatingSecurityToken.getTokenType());
                    }
                    break;
                case WssX509Pkcs7Token10:
                case WssX509Pkcs7Token11:
                    setAsserted(false);
                    setErrorMessage("Unsupported token type: " + delegatingSecurityToken.getTokenType());
                    break;
            }
        } catch (XMLSecurityException e) {
            setAsserted(false);
            setErrorMessage(e.getMessage());
        }
    }
}
