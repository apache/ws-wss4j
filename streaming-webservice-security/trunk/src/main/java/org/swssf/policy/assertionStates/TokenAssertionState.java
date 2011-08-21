/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.policy.assertionStates;

import org.opensaml.common.SAMLVersion;
import org.swssf.ext.Constants;
import org.swssf.ext.SecurityToken;
import org.swssf.ext.WSSecurityException;
import org.swssf.impl.securityToken.DelegatingSecurityToken;
import org.swssf.impl.securityToken.UsernameSecurityToken;
import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.policy.secpolicy.model.*;
import org.swssf.securityEvent.*;

import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
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
        if (samlToken.isRequireKeyIdentifierReference() && ((DelegatingSecurityToken) samlTokenSecurityEvent.getSecurityToken()).getKeyIdentifierType() != Constants.KeyIdentifierType.X509_KEY_IDENTIFIER) {
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
        if (usernameToken.isNoPassword() && usernameTokenSecurityEvent.getUsernameTokenPasswordType() != Constants.UsernameTokenPasswordType.PASSWORD_NONE) {
            setAsserted(false);
            setErrorMessage("UsernameToken contains a password but the policy prohibits it");
        } else if (usernameToken.isHashPassword() && usernameTokenSecurityEvent.getUsernameTokenPasswordType() != Constants.UsernameTokenPasswordType.PASSWORD_DIGEST) {
            setAsserted(false);
            setErrorMessage("UsernameToken does not contain a hashed password");
        }
        if (usernameToken.isCreatedTimestamp() && (usernameSecurityToken.getCreated() == null || usernameTokenSecurityEvent.getUsernameTokenPasswordType() != Constants.UsernameTokenPasswordType.PASSWORD_TEXT)) {
            setAsserted(false);
            setErrorMessage("UsernameToken does not contain a created timestamp or password is not plain text");
        }
        if (usernameToken.isNonce() && (usernameSecurityToken.getNonce() == null || usernameTokenSecurityEvent.getUsernameTokenPasswordType() != Constants.UsernameTokenPasswordType.PASSWORD_TEXT)) {
            setAsserted(false);
            setErrorMessage("UsernameToken does not contain a nonce or password is not plain text");
        }
        //todo how does the profile 1.0 and 1.1 differ?? Both spec refer to the same namespace
        if (usernameToken.isUseUTProfile10() && !usernameTokenSecurityEvent.getUsernameTokenProfile().equals(Constants.NS_USERNAMETOKEN_PROFILE11)) {
            setAsserted(false);
            setErrorMessage("Policy enforces UsernameToken profile 1.0 but we got 1.1");
        } else if (usernameToken.isUseUTProfile11() && !usernameTokenSecurityEvent.getUsernameTokenProfile().equals(Constants.NS_USERNAMETOKEN_PROFILE11)) {
            setAsserted(false);
            setErrorMessage("Policy enforces UsernameToken profile 1.1 but we got 1.0");
        }
        //todo derived keys?
    }

    private void assertX509Token(X509Token x509Token, TokenSecurityEvent tokenSecurityEvent) {
        SecurityToken securityToken = tokenSecurityEvent.getSecurityToken();
        loop:
        while (securityToken.getKeyWrappingToken() != null) {
            securityToken = securityToken.getKeyWrappingToken();
            switch (securityToken.getTokenType()) {
                case X509V3Token:
                case X509V1Token:
                case X509Pkcs7Token:
                case X509PkiPathV1Token:
                    break loop;
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
            if (x509Token.isRequireKeyIdentifierReference() && delegatingSecurityToken.getKeyIdentifierType() != Constants.KeyIdentifierType.X509_KEY_IDENTIFIER) {
                setAsserted(false);
                setErrorMessage("Policy enforces KeyIdentifierReference but we got " + delegatingSecurityToken.getTokenType());
            } else if (x509Token.isRequireIssuerSerialReference() && delegatingSecurityToken.getKeyIdentifierType() != Constants.KeyIdentifierType.ISSUER_SERIAL) {
                setAsserted(false);
                setErrorMessage("Policy enforces IssuerSerialReference but we got " + delegatingSecurityToken.getTokenType());
            } else if (x509Token.isRequireEmbeddedTokenReference() && delegatingSecurityToken.getKeyIdentifierType() != Constants.KeyIdentifierType.BST_EMBEDDED) {
                setAsserted(false);
                setErrorMessage("Policy enforces EmbeddedTokenReference but we got " + delegatingSecurityToken.getTokenType());
            } else if (x509Token.isRequireThumbprintReference() && delegatingSecurityToken.getKeyIdentifierType() != Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER) {
                setAsserted(false);
                setErrorMessage("Policy enforces ThumbprintReference but we got " + delegatingSecurityToken.getTokenType());
            }
            if (x509Token.getTokenVersionAndType() != null) {
                if ((x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_V3_TOKEN10) || x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_V3_TOKEN11)) && delegatingSecurityToken.getTokenType() != Constants.TokenType.X509V3Token && x509Certificate.getVersion() != 3) {
                    setAsserted(false);
                    setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " mismatch; Policy enforces " + x509Token.getTokenVersionAndType());
                } else if ((x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_V1_TOKEN10) || x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_V1_TOKEN11)) && delegatingSecurityToken.getTokenType() != Constants.TokenType.X509V1Token && x509Certificate.getVersion() != 1) {
                    setAsserted(false);
                    setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " mismatch; Policy enforces " + x509Token.getTokenVersionAndType());
                } else if (x509Certificate.getVersion() == 2) {
                    setAsserted(false);
                    setErrorMessage("X509Certificate Version " + x509Certificate.getVersion() + " not supported");
                } else if ((x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_PKI_PATH_V1_TOKEN10) || x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_PKI_PATH_V1_TOKEN11)) && delegatingSecurityToken.getTokenType() != Constants.TokenType.X509PkiPathV1Token) {
                    setAsserted(false);
                    setErrorMessage("Policy enforces " + x509Token.getTokenVersionAndType() + " but we got " + delegatingSecurityToken.getTokenType());
                } else if ((x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_PKCS7_TOKEN10) || x509Token.getTokenVersionAndType().equals(SPConstants.WSS_X509_PKCS7_TOKEN11))) {
                    setAsserted(false);
                    setErrorMessage("Unsupported token type: " + delegatingSecurityToken.getTokenType());
                }
            }
        } catch (WSSecurityException e) {
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
