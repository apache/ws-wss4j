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
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;

import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.w3c.dom.Element;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.SAMLTokenPrincipal;
import org.apache.wss4j.dom.saml.OpenSAMLUtil;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.dom.saml.SAMLUtil;
import org.apache.wss4j.dom.saml.SamlAssertionWrapper;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.api.stax.ext.WSSConstants;
import org.apache.wss4j.api.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.api.stax.securityToken.SamlSecurityToken;
import org.apache.wss4j.api.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.opensaml.saml.common.SAMLVersion;

public class SamlSecurityTokenImpl extends AbstractInboundSecurityToken implements SamlSecurityToken {

    private final SamlAssertionWrapper samlAssertionWrapper;
    private InboundSecurityToken subjectSecurityToken;
    private Crypto crypto;
    private WSSSecurityProperties securityProperties;
    private Principal principal;
    private SAMLKeyInfo subjectKeyInfo;
    private byte[] secret;
    private Key key;

    public SamlSecurityTokenImpl(WSInboundSecurityContext wsInboundSecurityContext, String id,
                                 WSSecurityTokenConstants.KeyIdentifier keyIdentifier,
                                 WSSSecurityProperties securityProperties) throws WSSecurityException {
        super(wsInboundSecurityContext, id, keyIdentifier, false);
        this.securityProperties = securityProperties;
        if (securityProperties.getCallbackHandler() != null) {
            // Try to get the Assertion from a CallbackHandler
            WSPasswordCallback pwcb =
                new WSPasswordCallback(id, WSPasswordCallback.CUSTOM_TOKEN);
            try {
                securityProperties.getCallbackHandler().handle(new Callback[]{pwcb});
            } catch (IOException | UnsupportedCallbackException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e, "noPassword");
            }

            secret = pwcb.getKey();
            key = pwcb.getKeyObject();
            if (this.key instanceof PrivateKey) {
                super.setAsymmetric(true);
            }

            Element assertionElem = pwcb.getCustomToken();
            if (assertionElem != null && "Assertion".equals(assertionElem.getLocalName())
                && (WSSConstants.NS_SAML.equals(assertionElem.getNamespaceURI())
                || WSSConstants.NS_SAML2.equals(assertionElem.getNamespaceURI()))) {
                this.samlAssertionWrapper = new SamlAssertionWrapper(assertionElem);

                subjectKeyInfo =
                    SAMLUtil.getCredentialFromSubject(samlAssertionWrapper, null, null,
                                                      securityProperties.getSignatureVerificationCrypto());
            } else {
                // Possibly an Encrypted Assertion...we just need the key here
                this.samlAssertionWrapper = null;
            }

            if (this.samlAssertionWrapper == null && secret == null && key == null) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "noToken",
                    new Object[] {id}
                );
            }
        } else {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "noToken",
                new Object[] {id}
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
    protected Key getKey(String algorithmURI, XMLSecurityConstants.AlgorithmUsage algorithmUsage, String correlationID)
        throws XMLSecurityException {
        Key key = null;
        if (this.key != null) {
            key = this.key;
        } else if (secret != null) {
            String keyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(algorithmURI);
            key = new SecretKeySpec(secret, keyAlgorithm);
        } else if (this.subjectSecurityToken != null) {
            key = subjectSecurityToken.getSecretKey(algorithmURI, algorithmUsage, correlationID);
        } else if (subjectKeyInfo != null && subjectKeyInfo.getSecret() != null) {
            String keyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(algorithmURI);
            key = new SecretKeySpec(subjectKeyInfo.getSecret(), keyAlgorithm);
        }
        if (key != null) {
            super.setSecretKey(algorithmURI, key);
            return key;
        }
        return super.getKey(algorithmURI, algorithmUsage, correlationID);
    }

    @Override
    protected PublicKey getPubKey(String algorithmURI, XMLSecurityConstants.AlgorithmUsage algorithmUsage, String correlationID)
        throws XMLSecurityException {
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
        String confirmMethod = null;
        List<String> methods = samlAssertionWrapper.getConfirmationMethods();
        if (methods != null && !methods.isEmpty()) {
            confirmMethod = methods.get(0);
        }
        // If HOK + Token is signed then we don't need to verify the subject cert, as we
        // indirectly trust it
        if (!OpenSAMLUtil.isMethodHolderOfKey(confirmMethod) && !samlAssertionWrapper.isSigned()) {
            X509Certificate[] x509Certificates = getX509Certificates();
            if (x509Certificates != null && x509Certificates.length > 0) {
                boolean enableRevocation = false;
                Collection<Pattern> subjectCertConstraints = null;
                Collection<Pattern> issuerCertConstraints = null;
                if (securityProperties != null) {
                    enableRevocation = securityProperties.isEnableRevocation();
                    subjectCertConstraints = securityProperties.getSubjectCertConstraints();
                    issuerCertConstraints = securityProperties.getIssuerDNConstraints();

                }
                crypto.verifyTrust(x509Certificates, enableRevocation, subjectCertConstraints, issuerCertConstraints);
            }
            PublicKey publicKey = getPublicKey();
            if (publicKey != null) {
                crypto.verifyTrust(publicKey);
            }
        }
    }

    @Override
    public WSSecurityTokenConstants.TokenType getTokenType() {
        if (samlAssertionWrapper != null
            && samlAssertionWrapper.getSamlVersion() == SAMLVersion.VERSION_10) {
            return WSSecurityTokenConstants.SAML_10_TOKEN;
        } else if (samlAssertionWrapper != null
            && samlAssertionWrapper.getSamlVersion() == SAMLVersion.VERSION_11) {
            return WSSecurityTokenConstants.SAML_11_TOKEN;
        }
        return WSSecurityTokenConstants.SAML_20_TOKEN;
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

            };
        }
        return this.principal;
    }

    @Override
    public SamlAssertionWrapper getSamlAssertionWrapper() {
        return samlAssertionWrapper;
    }
}
