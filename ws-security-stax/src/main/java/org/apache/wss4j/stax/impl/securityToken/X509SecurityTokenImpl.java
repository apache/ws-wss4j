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
package org.apache.wss4j.stax.impl.securityToken;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.PublicKeyPrincipalImpl;
import org.apache.wss4j.stax.ext.*;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.securityToken.X509SecurityToken;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants.TokenType;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;

import java.security.Key;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public abstract class X509SecurityTokenImpl
        extends org.apache.xml.security.stax.impl.securityToken.X509SecurityToken implements X509SecurityToken {

    private static final transient org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(X509SecurityTokenImpl.class);
    
    private CallbackHandler callbackHandler;
    private Crypto crypto;
    private WSSSecurityProperties securityProperties;
    private Principal principal;

    protected X509SecurityTokenImpl(
            WSSecurityTokenConstants.TokenType tokenType, WSInboundSecurityContext wsInboundSecurityContext,
            Crypto crypto, CallbackHandler callbackHandler, String id,
            WSSecurityTokenConstants.KeyIdentifier keyIdentifier, WSSSecurityProperties securityProperties,
            boolean includedInMessage) {
        super(tokenType, wsInboundSecurityContext, id, keyIdentifier, includedInMessage);
        this.crypto = crypto;
        this.callbackHandler = callbackHandler;
        this.securityProperties = securityProperties;
    }

    protected Crypto getCrypto() {
        return crypto;
    }

    protected void setCrypto(Crypto crypto) {
        this.crypto = crypto;
    }

    public CallbackHandler getCallbackHandler() {
        return callbackHandler;
    }

    @Override
    public Key getKey(String algorithmURI, XMLSecurityConstants.AlgorithmUsage algorithmUsage,
                      String correlationID) throws XMLSecurityException {
        WSPasswordCallback pwCb = new WSPasswordCallback(getAlias(), WSPasswordCallback.DECRYPT);
        WSSUtils.doPasswordCallback(getCallbackHandler(), pwCb);
        try {
            return getCrypto().getPrivateKey(getAlias(), pwCb.getPassword());
        } catch (WSSecurityException ex) {
            // Check to see if we are decrypting rather than signature verification
            Crypto decCrypto = securityProperties.getDecryptionCrypto();
            if (decCrypto != null && decCrypto != getCrypto()) {
                return decCrypto.getPrivateKey(getAlias(), pwCb.getPassword());
            }
            throw ex;
        }
    }

    @Override
    public X509Certificate[] getX509Certificates() throws XMLSecurityException {
        if (super.getX509Certificates() == null) {
            String alias = getAlias();
            if (alias != null) {
                CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
                cryptoType.setAlias(alias);
                setX509Certificates(getCrypto().getX509Certificates(cryptoType));
            }
        }
        return super.getX509Certificates();
    }

    @Override
    public void verify() throws XMLSecurityException {
        //todo overall call verify on wrapping tokens for non top-level SecurityTokens!?
        X509Certificate[] x509Certificates = getX509Certificates();
        if (x509Certificates != null && x509Certificates.length > 0) {
            boolean enableRevocation = false;
            Collection<Pattern> subjectCertConstraints = null;
            if (securityProperties != null) {
                enableRevocation = securityProperties.isEnableRevocation();
                subjectCertConstraints = securityProperties.getSubjectCertConstraints();
            }
            getCrypto().verifyTrust(x509Certificates, enableRevocation, subjectCertConstraints);
        }
    }
    
    /**
     * @return      true if the certificate's SubjectDN matches the constraints defined in the
     *              subject DNConstraints; false, otherwise. The certificate subject DN only
     *              has to match ONE of the subject cert constraints (not all).
     */
    protected boolean
    matches(
        final X509Certificate cert, final Collection<Pattern> subjectDNPatterns
    ) {
        if (subjectDNPatterns.isEmpty()) {
            LOG.warn("No Subject DN Certificate Constraints were defined. This could be a security issue");
        }
        if (!subjectDNPatterns.isEmpty()) {
            if (cert == null) {
                LOG.debug("The certificate is null so no constraints matching was possible");
                return false;
            }
            String subjectName = cert.getSubjectX500Principal().getName();
            boolean subjectMatch = false;
            for (Pattern subjectDNPattern : subjectDNPatterns) {
                final Matcher matcher = subjectDNPattern.matcher(subjectName);
                if (matcher.matches()) {
                    LOG.debug("Subject DN " + subjectName + " matches with pattern " + subjectDNPattern);
                    subjectMatch = true;
                    break;
                }
            }
            if (!subjectMatch) {
                return false;
            }
        }
        
        return true;
    }
    
    protected abstract String getAlias() throws XMLSecurityException;

    @Override
    public Subject getSubject() throws WSSecurityException {
        return null;
    }

    @Override
    public Principal getPrincipal() throws WSSecurityException {
        if (this.principal == null) {
            try {
                X509Certificate[] certs = getX509Certificates();
                if (certs != null && certs.length > 0) {
                    return this.principal = certs[0].getSubjectX500Principal();
                }
                return this.principal = new PublicKeyPrincipalImpl(getPublicKey());
            } catch (XMLSecurityException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
            }
        }
        return this.principal;
    }
    
    @Override
    public TokenType getTokenType() {
        TokenType storedTokenType = super.getTokenType();
        // Just check to see whether the cert version is "1"
        if (WSSecurityTokenConstants.X509V3Token.equals(storedTokenType)) {
            try {
                X509Certificate[] certs = super.getX509Certificates();
                if (certs != null && certs.length > 0 && certs[0].getVersion() == 1) {
                    return WSSecurityTokenConstants.X509V1Token;
                }
            } catch (XMLSecurityException e) {
                return storedTokenType;
            }
        }
        
        return storedTokenType;
        
        
    }
}
