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
package org.apache.wss4j.stax.impl.processor.output;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenConstants.TokenType;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.XMLStreamException;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;

public class BinarySecurityTokenOutputProcessor extends AbstractOutputProcessor {

    public BinarySecurityTokenOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        try {
            final String bstId;
            final X509Certificate[] x509Certificates;
            String reference = null;
            Key key = null;
            TokenType tokenType = WSSecurityTokenConstants.X509V3Token;

            XMLSecurityConstants.Action action = getAction();
            if (WSSConstants.SIGNATURE.equals(action)
                    || WSSConstants.SAML_TOKEN_SIGNED.equals(action)
                    || WSSConstants.SIGNATURE_WITH_DERIVED_KEY.equals(action)) {
                // See if a Symmetric Key is already available
                String tokenId = 
                    outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE);
                SecurityTokenProvider<OutboundSecurityToken> signatureTokenProvider = null;
                GenericOutboundSecurityToken securityToken = null;
                if (tokenId != null && !WSSConstants.SIGNATURE_WITH_DERIVED_KEY.equals(getAction())) {
                    signatureTokenProvider = 
                        outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
                    if (signatureTokenProvider != null) {
                        securityToken = 
                            (GenericOutboundSecurityToken)signatureTokenProvider.getSecurityToken();
                        if (securityToken != null) {
                            key = securityToken.getSecretKey(getSecurityProperties().getSignatureAlgorithm());
                            reference = securityToken.getSha1Identifier();
                            tokenType = securityToken.getTokenType();
                        }
                    }
                }
                
                if (key == null) {
                    bstId = IDGenerator.generateID(null);
                    String alias = ((WSSSecurityProperties) getSecurityProperties()).getSignatureUser();
                    WSPasswordCallback pwCb = new WSPasswordCallback(alias, WSPasswordCallback.Usage.SIGNATURE);
                    WSSUtils.doPasswordCallback(((WSSSecurityProperties)getSecurityProperties()).getCallbackHandler(), pwCb);
                    String password = pwCb.getPassword();
                    byte[] secretKey = pwCb.getKey();
                    if (password == null && secretKey == null) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "noPassword", alias);
                    }
                    if (password != null) {
                        key = ((WSSSecurityProperties) getSecurityProperties()).getSignatureCrypto().getPrivateKey(alias, password);
                        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
                        cryptoType.setAlias(alias);
                        x509Certificates = ((WSSSecurityProperties) getSecurityProperties()).getSignatureCrypto().getX509Certificates(cryptoType);
                        if (x509Certificates == null || x509Certificates.length == 0) {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "noUserCertsFound", alias);
                        }
                    } else {
                        x509Certificates = null;
                        String algoFamily = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(getSecurityProperties().getSignatureAlgorithm());
                        key = new SecretKeySpec(secretKey, algoFamily);
                    }
                    tokenType = null;
                } else {
                    bstId = tokenId;
                    x509Certificates = null;
                }
            } else if (WSSConstants.ENCRYPT.equals(action) ||
                    WSSConstants.ENCRYPT_WITH_DERIVED_KEY.equals(action)) {
                X509Certificate x509Certificate = getReqSigCert(outputProcessorChain.getSecurityContext());
                if (((WSSSecurityProperties) getSecurityProperties()).isUseReqSigCertForEncryption()) {
                    if (x509Certificate == null) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, "noCert");
                    }
                    x509Certificates = new X509Certificate[1];
                    x509Certificates[0] = x509Certificate;
                } else if (getSecurityProperties().getEncryptionUseThisCertificate() != null) {
                    x509Certificate = getSecurityProperties().getEncryptionUseThisCertificate();
                    x509Certificates = new X509Certificate[1];
                    x509Certificates[0] = x509Certificate;
                } else {
                    CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
                    WSSSecurityProperties securityProperties = ((WSSSecurityProperties) getSecurityProperties());
                    cryptoType.setAlias(securityProperties.getEncryptionUser());
                    Crypto crypto = securityProperties.getEncryptionCrypto();
                    x509Certificates = crypto.getX509Certificates(cryptoType);
                    if (x509Certificates == null || x509Certificates.length == 0) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, "noUserCertsFound",
                                ((WSSSecurityProperties) getSecurityProperties()).getEncryptionUser());
                    }
                }
                
                // Check for Revocation
                WSSSecurityProperties securityProperties = ((WSSSecurityProperties) getSecurityProperties());
                if (securityProperties.isEnableRevocation()) {
                    Crypto crypto = securityProperties.getEncryptionCrypto();
                    crypto.verifyTrust(x509Certificates, true);
                }

                key = null;
                bstId = IDGenerator.generateID(null);
            } else {
                bstId = IDGenerator.generateID(null);
                x509Certificates = null;
                key = null;
            }

            final GenericOutboundSecurityToken binarySecurityToken =
                    new GenericOutboundSecurityToken(bstId, tokenType, key, x509Certificates);
            binarySecurityToken.setSha1Identifier(reference);
            final SecurityTokenProvider<OutboundSecurityToken> binarySecurityTokenProvider =
                    new SecurityTokenProvider<OutboundSecurityToken>() {

                @Override
                public OutboundSecurityToken getSecurityToken() throws WSSecurityException {
                    return binarySecurityToken;
                }

                @Override
                public String getId() {
                    return bstId;
                }
            };

            if (WSSConstants.SIGNATURE.equals(action)
                    || WSSConstants.SAML_TOKEN_SIGNED.equals(action)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, bstId);
                boolean includeSignatureToken = 
                    ((WSSSecurityProperties) getSecurityProperties()).isIncludeSignatureToken();
                if ((includeSignatureToken 
                    || WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference.equals(getSecurityProperties().getSignatureKeyIdentifier()))
                    && !WSSecurityTokenConstants.KerberosToken.equals(tokenType)) {
                    FinalBinarySecurityTokenOutputProcessor finalBinarySecurityTokenOutputProcessor = new FinalBinarySecurityTokenOutputProcessor(binarySecurityToken);
                    finalBinarySecurityTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                    finalBinarySecurityTokenOutputProcessor.setAction(getAction());
                    finalBinarySecurityTokenOutputProcessor.addBeforeProcessor(WSSSignatureOutputProcessor.class.getName());
                    finalBinarySecurityTokenOutputProcessor.init(outputProcessorChain);
                    binarySecurityToken.setProcessor(finalBinarySecurityTokenOutputProcessor);
                }
            } else if (WSSConstants.ENCRYPT.equals(action)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY, bstId);
                if (WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference.equals(((WSSSecurityProperties) getSecurityProperties()).getEncryptionKeyIdentifier())) {
                    FinalBinarySecurityTokenOutputProcessor finalBinarySecurityTokenOutputProcessor = new FinalBinarySecurityTokenOutputProcessor(binarySecurityToken);
                    finalBinarySecurityTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                    finalBinarySecurityTokenOutputProcessor.setAction(getAction());
                    finalBinarySecurityTokenOutputProcessor.addAfterProcessor(EncryptEndingOutputProcessor.class.getName());
                    finalBinarySecurityTokenOutputProcessor.init(outputProcessorChain);
                    binarySecurityToken.setProcessor(finalBinarySecurityTokenOutputProcessor);
                }
            } else if (WSSConstants.SIGNATURE_WITH_DERIVED_KEY.equals(action)
                    || WSSConstants.ENCRYPT_WITH_DERIVED_KEY.equals(action)) {

                WSSConstants.DerivedKeyTokenReference derivedKeyTokenReference = ((WSSSecurityProperties) getSecurityProperties()).getDerivedKeyTokenReference();
                switch (derivedKeyTokenReference) {

                    case DirectReference:
                        outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, bstId);
                        break;
                    case EncryptedKey:
                        outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY, bstId);
                        break;
                    case SecurityContextToken:
                        outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SECURITYCONTEXTTOKEN, bstId);
                        break;
                }
            }

            outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(bstId, binarySecurityTokenProvider);

        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }

    private X509Certificate getReqSigCert(SecurityContext securityContext) throws XMLSecurityException {
        List<SecurityEvent> securityEventList = securityContext.getAsList(SecurityEvent.class);
        if (securityEventList != null) {
            for (int i = 0; i < securityEventList.size(); i++) {
                SecurityEvent securityEvent = securityEventList.get(i);
                if (securityEvent instanceof TokenSecurityEvent) {
                    @SuppressWarnings("unchecked")
                    TokenSecurityEvent<? extends SecurityToken> tokenSecurityEvent 
                        = (TokenSecurityEvent<? extends SecurityToken>) securityEvent;
                    if (!tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(WSSecurityTokenConstants.TokenUsage_MainSignature)) {
                        continue;
                    }
                    X509Certificate[] x509Certificates = tokenSecurityEvent.getSecurityToken().getX509Certificates();
                    if (x509Certificates != null && x509Certificates.length > 0) {
                        return x509Certificates[0];
                    }
                }
            }
        }
        return null;
    }

    class FinalBinarySecurityTokenOutputProcessor extends AbstractOutputProcessor {

        private final OutboundSecurityToken securityToken;

        FinalBinarySecurityTokenOutputProcessor(OutboundSecurityToken securityToken) throws XMLSecurityException {
            super();
            this.addAfterProcessor(BinarySecurityTokenOutputProcessor.class.getName());
            this.securityToken = securityToken;
        }

        @Override
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain)
                throws XMLStreamException, XMLSecurityException {

            outputProcessorChain.processEvent(xmlSecEvent);

            if (WSSUtils.isSecurityHeaderElement(xmlSecEvent, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {

                WSSUtils.updateSecurityHeaderOrder(
                        outputProcessorChain, WSSConstants.TAG_wsse_BinarySecurityToken, getAction(), false);

                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                boolean useSingleCertificate = getSecurityProperties().isUseSingleCert();
                WSSUtils.createBinarySecurityTokenStructure(
                        this, subOutputProcessorChain, securityToken.getId(),
                        securityToken.getX509Certificates(), useSingleCertificate);

                outputProcessorChain.removeProcessor(this);
            }
        }        
    }
}
