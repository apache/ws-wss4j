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

import org.opensaml.common.SAMLVersion;
import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.policy.secpolicy.model.*;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.impl.securityToken.DelegatingSecurityToken;
import org.swssf.wss.impl.securityToken.UsernameSecurityToken;
import org.swssf.wss.securityEvent.*;
import org.swssf.xmlsec.ext.SecurityToken;
import org.swssf.xmlsec.ext.XMLSecurityConstants;
import org.swssf.xmlsec.ext.XMLSecurityException;

import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */

public class TokenAssertionState extends AssertionState {

    public TokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) {

        TokenSecurityEvent tokenSecurityEvent = (TokenSecurityEvent) securityEvent;

        if (Arrays.binarySearch(getAssertion().getResponsibleAssertionEvents(), tokenSecurityEvent.getSecurityEventType()) < 0) {
            return false;
        }

        //todo enumerate TokenTypes
        Token token = (Token) getAssertion();
        if (token instanceof HttpsToken) {
            assertHttpsToken((HttpsToken) token, tokenSecurityEvent);
        } else if (token instanceof IssuedToken) {
            assertIssuedToken((IssuedToken) token, tokenSecurityEvent);
        } else if (token instanceof SecureConversationToken) {
            assertSecureConversationToken((SecureConversationToken) token, tokenSecurityEvent);
        } else if (token instanceof UsernameToken) {
            assertUsernameToken((UsernameToken) token, tokenSecurityEvent);
        } else if (token instanceof X509Token) {
            assertX509Token((X509Token) token, tokenSecurityEvent);
        } else if (token instanceof SecurityContextToken) {
            assertSecurityContextToken((SecurityContextToken) token, tokenSecurityEvent);
        } else if (token instanceof SamlToken) {
            assertSamlToken((SamlToken) token, tokenSecurityEvent);
        }

        return isAsserted();
    }

    //todo <sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>
    //todo claims

    private void assertSamlToken(SamlToken samlToken, TokenSecurityEvent securityEvent) {
        if (!(securityEvent instanceof SamlTokenSecurityEvent)) {
            setAsserted(false);
            setErrorMessage("Expected a SamlTokenSecurityEvent but got " + securityEvent.getClass().getName());
            return;
        }
        SamlTokenSecurityEvent samlTokenSecurityEvent = (SamlTokenSecurityEvent) securityEvent;

        setAsserted(true);
        if (samlToken.getIssuerName() != null && !samlToken.getIssuerName().equals(samlTokenSecurityEvent.getIssuerName())) {
            setAsserted(false);
            setErrorMessage("IssuerName in Policy (" + samlToken.getIssuerName() + ") didn't match with the one in the SamlToken (" + samlTokenSecurityEvent.getIssuerName() + ")");
        }
        if (samlToken.isRequireKeyIdentifierReference() && ((DelegatingSecurityToken) samlTokenSecurityEvent.getSecurityToken()).getKeyIdentifierType() != WSSConstants.KeyIdentifierType.X509_KEY_IDENTIFIER) {
            setAsserted(false);
            setErrorMessage("Policy enforces KeyIdentifierReference but we got " + samlTokenSecurityEvent.getSecurityToken().getTokenType());
        }
        if (samlToken.isUseSamlVersion11Profile10() && samlTokenSecurityEvent.getSamlVersion() != SAMLVersion.VERSION_10) {
            setAsserted(false);
            setErrorMessage("Policy enforces SamlVersion11Profile10 but we got " + samlTokenSecurityEvent.getSamlVersion());
        } else if (samlToken.isUseSamlVersion11Profile11() && samlTokenSecurityEvent.getSamlVersion() != SAMLVersion.VERSION_11) {
            setAsserted(false);
            setErrorMessage("Policy enforces SamlVersion11Profile11 but we got " + samlTokenSecurityEvent.getSamlVersion());
        } else if (samlToken.isUseSamlVersion20Profile11() && samlTokenSecurityEvent.getSamlVersion() != SAMLVersion.VERSION_20) {
            setAsserted(false);
            setErrorMessage("Policy enforces SamlVersion20Profile11 but we got " + samlTokenSecurityEvent.getSamlVersion());
        }
    }

    private void assertHttpsToken(HttpsToken httpsToken, TokenSecurityEvent securityEvent) {
        if (!(securityEvent instanceof HttpsTokenSecurityEvent)) {
            setAsserted(false);
            setErrorMessage("Expected a HttpsTokenSecurityEvent but got " + securityEvent.getClass().getName());
            return;
        }
        HttpsTokenSecurityEvent httpsTokenSecurityEvent = (HttpsTokenSecurityEvent) securityEvent;

        setAsserted(true);
        if (httpsToken.getIssuerName() != null && !httpsToken.getIssuerName().equals(httpsTokenSecurityEvent.getIssuerName())) {
            setAsserted(false);
            setErrorMessage("IssuerName in Policy (" + httpsToken.getIssuerName() + ") didn't match with the one in the HttpsToken (" + httpsTokenSecurityEvent.getIssuerName() + ")");
        }
        if (httpsToken.isHttpBasicAuthentication() && httpsTokenSecurityEvent.getAuthenticationType() != HttpsTokenSecurityEvent.AuthenticationType.HttpBasicAuthentication) {
            setAsserted(false);
            setErrorMessage("Policy enforces HttpBasicAuthentication but we got " + httpsTokenSecurityEvent.getAuthenticationType());
        } else if (httpsToken.isHttpDigestAuthentication() && httpsTokenSecurityEvent.getAuthenticationType() != HttpsTokenSecurityEvent.AuthenticationType.HttpDigestAuthentication) {
            setAsserted(false);
            setErrorMessage("Policy enforces HttpDigestAuthentication but we got " + httpsTokenSecurityEvent.getAuthenticationType());
        } else if (httpsToken.isRequireClientCertificate() && httpsTokenSecurityEvent.getAuthenticationType() != HttpsTokenSecurityEvent.AuthenticationType.HttpsClientCertificateAuthentication) {
            setAsserted(false);
            setErrorMessage("Policy enforces HttClientCertificateAuthentication but we got " + httpsTokenSecurityEvent.getAuthenticationType());
        }
    }

    private void assertIssuedToken(IssuedToken issuedToken, TokenSecurityEvent securityEvent) {
        if (!(securityEvent instanceof IssuedTokenSecurityEvent)) {
            setAsserted(false);
            setErrorMessage("Expected a IssuedSecurityTokenEvent but got " + securityEvent.getClass().getName());
            return;
        }
        IssuedTokenSecurityEvent issuedTokenSecurityEvent = (IssuedTokenSecurityEvent) securityEvent;

        setAsserted(true);
        if (issuedToken.getIssuerName() != null && !issuedToken.getIssuerName().equals(issuedTokenSecurityEvent.getIssuerName())) {
            setAsserted(false);
            setErrorMessage("IssuerName in Policy (" + issuedToken.getIssuerName() + ") didn't match with the one in the issuedSecurityToken (" + issuedTokenSecurityEvent.getIssuerName() + ")");
        }
        if (issuedToken.isRequireInternalReference() && !issuedTokenSecurityEvent.isInternalReference()) {
            setAsserted(false);
            setErrorMessage("Policy enforces internalUriRef but we didn't got one");
        }
        if (issuedToken.isRequireExternalReference() && issuedTokenSecurityEvent.isInternalReference()) {
            setAsserted(false);
            setErrorMessage("Policy enforces externalUriRef but we didn't got one");
        }
        //todo  <sp:RequestSecurityTokenTemplate TrustVersion="xs:anyURI"? >
    }

    private void assertSecureConversationToken(SecureConversationToken secureConversationToken, TokenSecurityEvent securityEvent) {
        if (!(securityEvent instanceof SecureConversationSecurityEvent)) {
            setAsserted(false);
            setErrorMessage("Expected a SecureConversationSecurityEvent but got " + securityEvent.getClass().getName());
            return;
        }
        SecureConversationSecurityEvent secureConversationSecurityEvent = (SecureConversationSecurityEvent) securityEvent;

        setAsserted(true);
        if (secureConversationToken.getIssuerName() != null && !secureConversationToken.getIssuerName().equals(secureConversationSecurityEvent.getIssuerName())) {
            setAsserted(false);
            setErrorMessage("IssuerName in Policy (" + secureConversationToken.getIssuerName() + ") didn't match with the one in the SecureConversationToken (" + secureConversationSecurityEvent.getIssuerName() + ")");
        }
        if (secureConversationToken.isRequireExternalUriRef() && !secureConversationSecurityEvent.isExternalUriRef()) {
            setAsserted(false);
            setErrorMessage("Policy enforces externalUriRef but we didn't got one");
        }
        //todo sp:SC13SecurityContextToken:
        //if (securityContextToken.isSc10SecurityContextToken() && )
        //todo MustNotSendCancel etc...
    }

    private void assertUsernameToken(UsernameToken usernameToken, TokenSecurityEvent securityEvent) {
        if (!(securityEvent instanceof UsernameTokenSecurityEvent)) {
            setAsserted(false);
            setErrorMessage("Expected a UsernameSecurityTokenEvent but got " + securityEvent.getClass().getName());
            return;
        }
        UsernameSecurityToken usernameSecurityToken = (UsernameSecurityToken) securityEvent.getSecurityToken();
        UsernameTokenSecurityEvent usernameTokenSecurityEvent = (UsernameTokenSecurityEvent) securityEvent;

        //todo how to verify the issuer of the UsernameToken??

        setAsserted(true);
        if (usernameToken.isNoPassword() && usernameTokenSecurityEvent.getUsernameTokenPasswordType() != WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE) {
            setAsserted(false);
            setErrorMessage("UsernameToken contains a password but the policy prohibits it");
        } else if (usernameToken.isHashPassword() && usernameTokenSecurityEvent.getUsernameTokenPasswordType() != WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST) {
            setAsserted(false);
            setErrorMessage("UsernameToken does not contain a hashed password");
        }
        if (usernameToken.isCreatedTimestamp() && (usernameSecurityToken.getCreated() == null || usernameTokenSecurityEvent.getUsernameTokenPasswordType() != WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT)) {
            setAsserted(false);
            setErrorMessage("UsernameToken does not contain a created timestamp or password is not plain text");
        }
        if (usernameToken.isNonce() && (usernameSecurityToken.getNonce() == null || usernameTokenSecurityEvent.getUsernameTokenPasswordType() != WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT)) {
            setAsserted(false);
            setErrorMessage("UsernameToken does not contain a nonce or password is not plain text");
        }
        //todo how does the profile 1.0 and 1.1 differ?? Both spec refer to the same namespace
        if (usernameToken.isUseUTProfile10() && !usernameTokenSecurityEvent.getUsernameTokenProfile().equals(WSSConstants.NS_USERNAMETOKEN_PROFILE11)) {
            setAsserted(false);
            setErrorMessage("Policy enforces UsernameToken profile 1.0 but we got 1.1");
        } else if (usernameToken.isUseUTProfile11() && !usernameTokenSecurityEvent.getUsernameTokenProfile().equals(WSSConstants.NS_USERNAMETOKEN_PROFILE11)) {
            setAsserted(false);
            setErrorMessage("Policy enforces UsernameToken profile 1.1 but we got 1.0");
        }
        //todo derived keys?
    }

    private void assertX509Token(X509Token x509Token, TokenSecurityEvent tokenSecurityEvent) {
        SecurityToken securityToken = tokenSecurityEvent.getSecurityToken();
        while (securityToken.getKeyWrappingToken() != null) {
            securityToken = securityToken.getKeyWrappingToken();
            XMLSecurityConstants.TokenType tokenType = securityToken.getTokenType();
            if (WSSConstants.X509V3Token.equals(tokenType)
                    || WSSConstants.X509V1Token.equals(tokenType)
                    || WSSConstants.X509Pkcs7Token.equals(tokenType)
                    || WSSConstants.X509PkiPathV1Token.equals(tokenType)) {
                break;
            }
        }
        if (!(securityToken instanceof DelegatingSecurityToken)) {
            return;
        }
        DelegatingSecurityToken delegatingSecurityToken = (DelegatingSecurityToken) securityToken;

        setAsserted(true);
        try {
            X509Certificate x509Certificate = delegatingSecurityToken.getX509Certificates()[0];
            if (x509Token.getIssuerName() != null) {
                final String certificateIssuerName = x509Certificate.getSubjectX500Principal().getName();
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
            if (x509Token.getTokenVersionAndType() != null) {
                if ((x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_V3_TOKEN10) || x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_V3_TOKEN11)) && !WSSConstants.X509V3Token.equals(delegatingSecurityToken.getTokenType()) && x509Certificate.getVersion() != 3) {
                    setAsserted(false);
                    setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " mismatch; Policy enforces " + x509Token.getTokenVersionAndType());
                } else if ((x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_V1_TOKEN10) || x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_V1_TOKEN11)) && !WSSConstants.X509V1Token.equals(delegatingSecurityToken.getTokenType()) && x509Certificate.getVersion() != 1) {
                    setAsserted(false);
                    setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " mismatch; Policy enforces " + x509Token.getTokenVersionAndType());
                } else if (x509Certificate.getVersion() == 2) {
                    setAsserted(false);
                    setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " not supported");
                } else if ((x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_PKI_PATH_V1_TOKEN10) || x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_PKI_PATH_V1_TOKEN11)) && delegatingSecurityToken.getTokenType() != WSSConstants.X509PkiPathV1Token) {
                    setAsserted(false);
                    setErrorMessage("Policy enforces " + x509Token.getTokenVersionAndType() + " but we got " + delegatingSecurityToken.getTokenType());
                } else if ((x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_PKCS7_TOKEN10) || x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_PKCS7_TOKEN11))) {
                    setAsserted(false);
                    setErrorMessage("Unsupported token type: " + delegatingSecurityToken.getTokenType());
                }
            }
        } catch (XMLSecurityException e) {
            setAsserted(false);
            setErrorMessage(e.getMessage());
        }
    }

    private void assertSecurityContextToken(SecurityContextToken securityContextToken, TokenSecurityEvent securityEvent) {
        if (!(securityEvent instanceof SecurityContextTokenSecurityEvent)) {
            setAsserted(false);
            setErrorMessage("Expected a SecurityContextTokenSecurityEvent but got " + securityEvent.getClass().getName());
            return;
        }
        SecurityContextTokenSecurityEvent securityContextTokenSecurityEvent = (SecurityContextTokenSecurityEvent) securityEvent;

        setAsserted(true);
        if (securityContextToken.getIssuerName() != null && !securityContextToken.getIssuerName().equals(securityContextTokenSecurityEvent.getIssuerName())) {
            setAsserted(false);
            setErrorMessage("IssuerName in Policy (" + securityContextToken.getIssuerName() + ") didn't match with the one in the SecurityContextToken (" + securityContextTokenSecurityEvent.getIssuerName() + ")");
        }
        if (securityContextToken.isRequireExternalUriRef() && !securityContextTokenSecurityEvent.isExternalUriRef()) {
            setAsserted(false);
            setErrorMessage("Policy enforces externalUriRef but we didn't got one");
        }
        //todo sp:SC13SecurityContextToken:
        //if (securityContextToken.isSc10SecurityContextToken() && )
    }
}
