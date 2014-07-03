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
package org.apache.wss4j.policy.stax.assertionStates;

import org.apache.wss4j.common.WSSPolicyException;
import org.apache.wss4j.policy.SPConstants;
import org.apache.wss4j.policy.model.AbstractSecurityAssertion;
import org.apache.wss4j.policy.model.AbstractToken;
import org.apache.wss4j.policy.model.X509Token;
import org.apache.wss4j.policy.stax.PolicyAsserter;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.securityEvent.X509TokenSecurityEvent;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.SecurityToken;

import java.security.cert.X509Certificate;

import javax.xml.namespace.QName;

/**
 * WSP1.3, 5.4.3 X509Token Assertion
 */

public class X509TokenAssertionState extends TokenAssertionState {

    public X509TokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted, 
                                   PolicyAsserter policyAsserter, boolean initiator) {
        super(assertion, asserted, policyAsserter, initiator);
        
        if (asserted) {
            X509Token token = (X509Token) getAssertion();
            String namespace = token.getName().getNamespaceURI();
            if (token.isRequireKeyIdentifierReference()) {
                getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.REQUIRE_KEY_IDENTIFIER_REFERENCE));
            } else if (token.isRequireIssuerSerialReference()) {
                getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.REQUIRE_ISSUER_SERIAL_REFERENCE));
            } else if (token.isRequireEmbeddedTokenReference()) {
                getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.REQUIRE_EMBEDDED_TOKEN_REFERENCE));
            } else if (token.isRequireThumbprintReference()) {
                getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.REQUIRE_THUMBPRINT_REFERENCE));
            }
            if (token.getTokenType() != null) {
                getPolicyAsserter().assertPolicy(new QName(namespace, token.getTokenType().name()));
            }
        }
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                SecurityEventConstants.X509Token
        };
    }

    @Override
    public boolean assertToken(TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent,
                               AbstractToken abstractToken) throws WSSPolicyException, XMLSecurityException {
        if (!(tokenSecurityEvent instanceof X509TokenSecurityEvent)) {
            throw new WSSPolicyException("Expected a X509TokenSecurityEvent but got " + tokenSecurityEvent.getClass().getName());
        }

        X509Token x509Token = (X509Token) abstractToken;

        SecurityToken securityToken = tokenSecurityEvent.getSecurityToken();
        WSSecurityTokenConstants.TokenType tokenType = securityToken.getTokenType();
        if (!(WSSecurityTokenConstants.X509V3Token.equals(tokenType)
                || WSSecurityTokenConstants.X509V1Token.equals(tokenType)
                || WSSecurityTokenConstants.X509Pkcs7Token.equals(tokenType)
                || WSSecurityTokenConstants.X509PkiPathV1Token.equals(tokenType))) {
            throw new WSSPolicyException("Invalid Token for this assertion");
        }

        try {
            String namespace = getAssertion().getName().getNamespaceURI();
            
            X509Certificate x509Certificate = securityToken.getX509Certificates()[0];
            if (x509Token.getIssuerName() != null) {
                final String certificateIssuerName = x509Certificate.getIssuerX500Principal().getName();
                if (!x509Token.getIssuerName().equals(certificateIssuerName)) {
                    setErrorMessage("IssuerName in Policy (" + x509Token.getIssuerName() +
                            ") didn't match with the one in the certificate (" + certificateIssuerName + ")");
                    getPolicyAsserter().unassertPolicy(getAssertion(), getErrorMessage());
                    return false;
                }
            }
            if (x509Token.isRequireKeyIdentifierReference()) {
                if (!(WSSecurityTokenConstants.KeyIdentifier_X509KeyIdentifier.equals(securityToken.getKeyIdentifier())
                        || WSSecurityTokenConstants.KeyIdentifier_SkiKeyIdentifier.equals(securityToken.getKeyIdentifier()))) {
                    setErrorMessage("Policy enforces KeyIdentifierReference but we got " + securityToken.getKeyIdentifier());
                    getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.REQUIRE_KEY_IDENTIFIER_REFERENCE),
                                                       getErrorMessage());
                    return false;
                } else {
                    getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.REQUIRE_KEY_IDENTIFIER_REFERENCE));
                }
            } else if (x509Token.isRequireIssuerSerialReference()) {
                if (!WSSecurityTokenConstants.KeyIdentifier_IssuerSerial.equals(securityToken.getKeyIdentifier())) {
                    setErrorMessage("Policy enforces IssuerSerialReference but we got " + securityToken.getKeyIdentifier());
                    getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.REQUIRE_ISSUER_SERIAL_REFERENCE),
                                                     getErrorMessage());
                    return false;
                } else {
                    getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.REQUIRE_ISSUER_SERIAL_REFERENCE));
                }
            } else if (x509Token.isRequireEmbeddedTokenReference()) {
                if (!WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference.equals(securityToken.getKeyIdentifier())) {
                    setErrorMessage("Policy enforces EmbeddedTokenReference but we got " + securityToken.getKeyIdentifier());
                    getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.REQUIRE_EMBEDDED_TOKEN_REFERENCE),
                                                       getErrorMessage());
                    return false;
                } else {
                    getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.REQUIRE_EMBEDDED_TOKEN_REFERENCE));
                }
            } else if (x509Token.isRequireThumbprintReference()) {
                if (!WSSecurityTokenConstants.KeyIdentifier_ThumbprintIdentifier.equals(securityToken.getKeyIdentifier())) {
                    setErrorMessage("Policy enforces ThumbprintReference but we got " + securityToken.getKeyIdentifier());
                    getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.REQUIRE_THUMBPRINT_REFERENCE),
                                                       getErrorMessage());
                    return false;
                } else {
                    getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.REQUIRE_THUMBPRINT_REFERENCE));
                }
            }
            if (x509Certificate.getVersion() == 2) {
                setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " not supported");
                getPolicyAsserter().unassertPolicy(getAssertion(), getErrorMessage());
                return false;
            }
            if (x509Token.getTokenType() != null) {
                switch (x509Token.getTokenType()) {
                    case WssX509V3Token10:
                    case WssX509V3Token11:
                        if (!WSSecurityTokenConstants.X509V3Token.equals(securityToken.getTokenType()) ||
                                x509Certificate.getVersion() != 3) {
                            setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() +
                                    " mismatch; Policy enforces " + x509Token.getTokenType());
                            getPolicyAsserter().unassertPolicy(new QName(namespace, x509Token.getTokenType().name()),
                                                                         getErrorMessage());
                            return false;
                        }
                        getPolicyAsserter().assertPolicy(new QName(namespace, x509Token.getTokenType().name()));
                        break;
                    case WssX509V1Token11:
                        if (!WSSecurityTokenConstants.X509V1Token.equals(securityToken.getTokenType()) ||
                                x509Certificate.getVersion() != 1) {
                            setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() +
                                    " mismatch; Policy enforces " + x509Token.getTokenType());
                            getPolicyAsserter().unassertPolicy(new QName(namespace, SPConstants.WSS_X509_V1_TOKEN11),
                                                               getErrorMessage());
                            return false;
                        }
                        getPolicyAsserter().assertPolicy(new QName(namespace, SPConstants.WSS_X509_V1_TOKEN11));
                        break;
                    case WssX509PkiPathV1Token10:
                    case WssX509PkiPathV1Token11:
                        if (!WSSecurityTokenConstants.X509PkiPathV1Token.equals(securityToken.getTokenType())) {
                            setErrorMessage("Policy enforces " + x509Token.getTokenType() +
                                    " but we got " + securityToken.getTokenType());
                            getPolicyAsserter().unassertPolicy(new QName(namespace, x509Token.getTokenType().name()),
                                                               getErrorMessage());
                            return false;
                        }
                        getPolicyAsserter().assertPolicy(new QName(namespace, x509Token.getTokenType().name()));
                        break;
                    case WssX509Pkcs7Token10:
                    case WssX509Pkcs7Token11:
                        setErrorMessage("Unsupported token type: " + securityToken.getTokenType());
                        getPolicyAsserter().unassertPolicy(new QName(namespace, x509Token.getTokenType().name()),
                                                           getErrorMessage());
                        return false;
                }
            }
        } catch (XMLSecurityException e) {
            setErrorMessage(e.getMessage());
            getPolicyAsserter().unassertPolicy(getAssertion(), getErrorMessage());
            return false;
        }
        //always return true to prevent false alarm in case additional tokens with the same usage
        //appears in the message but do not fulfill the policy and are also not needed to fulfil the policy.
        getPolicyAsserter().assertPolicy(getAssertion());
        return true;
    }
}
