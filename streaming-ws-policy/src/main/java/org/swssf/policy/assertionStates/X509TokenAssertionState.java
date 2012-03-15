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
import org.swssf.wss.impl.securityToken.AbstractSecurityToken;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.TokenSecurityEvent;
import org.swssf.wss.securityEvent.X509TokenSecurityEvent;
import org.swssf.xmlsec.ext.XMLSecurityConstants;
import org.swssf.xmlsec.ext.XMLSecurityException;

import java.security.cert.X509Certificate;

/**
 * WSP1.3, 5.4.3 X509Token Assertion
 *
 * @author $Author$
 * @version $Revision$ $Date$
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
    public boolean assertToken(TokenSecurityEvent tokenSecurityEvent, AbstractToken abstractToken) throws WSSPolicyException, XMLSecurityException {
        if (!(tokenSecurityEvent instanceof X509TokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a X509TokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }

        X509Token x509Token = (X509Token) abstractToken;

        AbstractSecurityToken securityToken = (AbstractSecurityToken) tokenSecurityEvent.getSecurityToken();
        XMLSecurityConstants.TokenType tokenType = securityToken.getTokenType();
        if (!(WSSConstants.X509V3Token.equals(tokenType)
                || WSSConstants.X509V1Token.equals(tokenType)
                || WSSConstants.X509Pkcs7Token.equals(tokenType)
                || WSSConstants.X509PkiPathV1Token.equals(tokenType))) {
            throw new WSSPolicyException("Invalid Token for this assertion");
        }
        setAsserted(true);
        try {
            X509Certificate x509Certificate = securityToken.getX509Certificates()[0];
            if (x509Token.getIssuerName() != null) {
                final String certificateIssuerName = x509Certificate.getIssuerX500Principal().getName();
                if (!x509Token.getIssuerName().equals(certificateIssuerName)) {
                    setAsserted(false);
                    setErrorMessage("IssuerName in Policy (" + x509Token.getIssuerName() + ") didn't match with the one in the certificate (" + certificateIssuerName + ")");
                }
            }
            if (x509Token.isRequireKeyIdentifierReference() && securityToken.getKeyIdentifierType() != WSSConstants.KeyIdentifierType.X509_KEY_IDENTIFIER) {
                setAsserted(false);
                setErrorMessage("Policy enforces KeyIdentifierReference but we got " + securityToken.getKeyIdentifierType());
            } else if (x509Token.isRequireIssuerSerialReference() && securityToken.getKeyIdentifierType() != WSSConstants.KeyIdentifierType.ISSUER_SERIAL) {
                setAsserted(false);
                setErrorMessage("Policy enforces IssuerSerialReference but we got " + securityToken.getKeyIdentifierType());
            } else if (x509Token.isRequireEmbeddedTokenReference() && securityToken.getKeyIdentifierType() != WSSConstants.KeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE) {
                setAsserted(false);
                setErrorMessage("Policy enforces EmbeddedTokenReference but we got " + securityToken.getKeyIdentifierType());
            } else if (x509Token.isRequireThumbprintReference() && securityToken.getKeyIdentifierType() != WSSConstants.KeyIdentifierType.THUMBPRINT_IDENTIFIER) {
                setAsserted(false);
                setErrorMessage("Policy enforces ThumbprintReference but we got " + securityToken.getKeyIdentifierType());
            }
            if (x509Certificate.getVersion() == 2) {
                setAsserted(false);
                setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " not supported");
            }
            if (x509Token.getTokenType() != null) {
                switch (x509Token.getTokenType()) {
                    case WssX509V3Token10:
                    case WssX509V3Token11:
                        if (WSSConstants.X509V3Token != securityToken.getTokenType() || x509Certificate.getVersion() != 3) {
                            setAsserted(false);
                            setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " mismatch; Policy enforces " + x509Token.getTokenType());
                        }
                        break;
                    case WssX509V1Token11:
                        if (WSSConstants.X509V1Token != securityToken.getTokenType() || x509Certificate.getVersion() != 1) {
                            setAsserted(false);
                            setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " mismatch; Policy enforces " + x509Token.getTokenType());
                        }
                        break;
                    case WssX509PkiPathV1Token10:
                    case WssX509PkiPathV1Token11:
                        if (securityToken.getTokenType() != WSSConstants.X509PkiPathV1Token) {
                            setAsserted(false);
                            setErrorMessage("Policy enforces " + x509Token.getTokenType() + " but we got " + securityToken.getTokenType());
                        }
                        break;
                    case WssX509Pkcs7Token10:
                    case WssX509Pkcs7Token11:
                        setAsserted(false);
                        setErrorMessage("Unsupported token type: " + securityToken.getTokenType());
                        break;
                }
            }
        } catch (XMLSecurityException e) {
            setAsserted(false);
            setErrorMessage(e.getMessage());
        }
        return isAsserted();
    }
}
