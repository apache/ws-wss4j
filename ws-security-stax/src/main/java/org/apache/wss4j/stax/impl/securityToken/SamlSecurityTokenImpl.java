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

import java.io.IOException;
import java.security.Key;
import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.w3c.dom.Element;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.SAMLTokenPrincipal;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.SamlSecurityToken;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.opensaml.common.SAMLVersion;

public class SamlSecurityTokenImpl extends AbstractInboundSecurityToken implements SamlSecurityToken {

    private final SamlAssertionWrapper samlAssertionWrapper;
    private InboundSecurityToken subjectSecurityToken;
    private Crypto crypto;
    private WSSSecurityProperties securityProperties;
    private Principal principal;
    private SAMLKeyInfo subjectKeyInfo;
    private byte[] secret;
    
    public SamlSecurityTokenImpl(WSInboundSecurityContext wsInboundSecurityContext, String id,
                                 WSSecurityTokenConstants.KeyIdentifier keyIdentifier,
                                 WSSSecurityProperties securityProperties) throws WSSecurityException {
        super(wsInboundSecurityContext, id, keyIdentifier, false);
        this.securityProperties = securityProperties;
        if (securityProperties.getCallbackHandler() != null) {
            // Try to get the Assertion from a CallbackHandler
            WSPasswordCallback pwcb = 
                new WSPasswordCallback(id, WSPasswordCallback.Usage.CUSTOM_TOKEN);
            try {
                securityProperties.getCallbackHandler().handle(new Callback[]{pwcb});
            } catch (IOException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noPassword", e);
            } catch (UnsupportedCallbackException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noPassword", e);
            }
            Element assertionElem = pwcb.getCustomToken();
            if (assertionElem == null) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "noToken", id
                );
            }
            
            if ("Assertion".equals(assertionElem.getLocalName())
                && (WSSConstants.NS_SAML.equals(assertionElem.getNamespaceURI())
                || WSSConstants.NS_SAML2.equals(assertionElem))) {
                this.samlAssertionWrapper = new SamlAssertionWrapper(assertionElem);
                
                subjectKeyInfo = 
                    SAMLUtil.getCredentialFromSubject(samlAssertionWrapper, null, 
                                                      securityProperties.getSignatureVerificationCrypto(),
                                                      securityProperties.getCallbackHandler());
            } else {
                // Possibly an Encrypted Assertion...just get the key
                this.samlAssertionWrapper = null;
                secret = pwcb.getKey();
            }
        } else {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "noToken", id
            );
        }
    }

    public SamlSecurityTokenImpl(SamlAssertionWrapper samlAssertionWrapper, InboundSecurityToken subjectSecurityToken,
                                 WSInboundSecurityContext wsInboundSecurityContext, Crypto crypto,
                                 WSSecurityTokenConstants.KeyIdentifier keyIdentifier,
                                 WSSSecurityProperties securityProperties) {
        super(wsInboundSecurityContext, samlAssertionWrapper.getId(), keyIdentifier, true);
        this.samlAssertionWrapper = samlAssertionWrapper;
        this.crypto = crypto;
        this.subjectSecurityToken = subjectSecurityToken;
        this.securityProperties = securityProperties;
    }

    @Override
    public boolean isAsymmetric() throws XMLSecurityException {
        if (this.subjectSecurityToken != null && this.subjectSecurityToken.isAsymmetric()) {
            return true;
        }
        return super.isAsymmetric();
    }

    @Override
    protected Key getKey(String algorithmURI, XMLSecurityConstants.AlgorithmUsage algorithmUsage, String correlationID) throws XMLSecurityException {
        if (secret != null) {
            return KeyUtils.prepareSecretKey(algorithmURI, secret);
        } else if (this.subjectSecurityToken != null) {
            return subjectSecurityToken.getSecretKey(algorithmURI, algorithmUsage, correlationID);
        } else if (subjectKeyInfo != null && subjectKeyInfo.getSecret() != null) {
            return KeyUtils.prepareSecretKey(algorithmURI, subjectKeyInfo.getSecret());
        }
        return super.getKey(algorithmURI, algorithmUsage, correlationID);
    }

    @Override
    protected PublicKey getPubKey(String algorithmURI, XMLSecurityConstants.AlgorithmUsage algorithmUsage, String correlationID) throws XMLSecurityException {
        if (this.subjectSecurityToken != null) {
            return subjectSecurityToken.getPublicKey(algorithmURI, algorithmUsage, correlationID);
        } else if (subjectKeyInfo != null && subjectKeyInfo.getPublicKey() != null) {
            return subjectKeyInfo.getPublicKey();
        }
        return super.getPubKey(algorithmURI, algorithmUsage, correlationID);
    }

    @Override
    public PublicKey getPublicKey() throws XMLSecurityException {
        if (this.subjectSecurityToken != null) {
            return subjectSecurityToken.getPublicKey();
        } else if (subjectKeyInfo != null && subjectKeyInfo.getPublicKey() != null) {
            return subjectKeyInfo.getPublicKey();
        }
        return super.getPublicKey();
    }

    @Override
    public X509Certificate[] getX509Certificates() throws XMLSecurityException {
        if (this.subjectSecurityToken != null) {
            return subjectSecurityToken.getX509Certificates();
        } else if (subjectKeyInfo != null && subjectKeyInfo.getCerts() != null) {
            return subjectKeyInfo.getCerts();
        }
        return super.getX509Certificates();
    }

    @Override
    public void verify() throws XMLSecurityException {
        //todo revisit verify for every security token incl. public-key
        //todo should we call verify implicit when accessing the keys?
        if (samlAssertionWrapper == null) {
            return;
        }
        try {
            String confirmMethod = null;
            List<String> methods = samlAssertionWrapper.getConfirmationMethods();
            if (methods != null && methods.size() > 0) {
                confirmMethod = methods.get(0);
            }
            // If HOK + Token is signed then we don't need to verify the subject cert, as we
            // indirectly trust it
            if (!OpenSAMLUtil.isMethodHolderOfKey(confirmMethod) && !samlAssertionWrapper.isSigned()) {
                X509Certificate[] x509Certificates = getX509Certificates();
                if (x509Certificates != null && x509Certificates.length > 0) {
                    //todo I don't think the checkValidity is necessary because the CertPathChecker
                    x509Certificates[0].checkValidity();
                    boolean enableRevocation = false;
                    if (securityProperties != null) {
                        enableRevocation = securityProperties.isEnableRevocation();
                    }
                    crypto.verifyTrust(x509Certificates, enableRevocation);
                }
                PublicKey publicKey = getPublicKey();
                if (publicKey != null) {
                    crypto.verifyTrust(publicKey);
                }
            }
        } catch (CertificateExpiredException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
        } catch (CertificateNotYetValidException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
        }
    }

    @Override
    public WSSecurityTokenConstants.TokenType getTokenType() {
        if (samlAssertionWrapper != null 
            && samlAssertionWrapper.getSamlVersion() == SAMLVersion.VERSION_10) {
            return WSSecurityTokenConstants.Saml10Token;
        } else if (samlAssertionWrapper != null 
            && samlAssertionWrapper.getSamlVersion() == SAMLVersion.VERSION_11) {
            return WSSecurityTokenConstants.Saml11Token;
        }
        return WSSecurityTokenConstants.Saml20Token;
    }

    @Override
    public Subject getSubject() throws WSSecurityException {
        return null;
    }

    @Override
    public Principal getPrincipal() throws WSSecurityException {
        if (this.principal == null) {
            this.principal = new SAMLTokenPrincipal() {
                @Override
                public SamlAssertionWrapper getToken() {
                    return samlAssertionWrapper;
                }

                @Override
                public String getName() {
                    return samlAssertionWrapper.getSubjectName();
                }

                @Override
                public String getId() {
                    return samlAssertionWrapper.getId();
                }
            };
        }
        return this.principal;
    }
}
