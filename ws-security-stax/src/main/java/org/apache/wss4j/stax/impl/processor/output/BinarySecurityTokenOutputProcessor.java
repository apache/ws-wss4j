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
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;
import org.apache.xml.security.stax.impl.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;

import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class BinarySecurityTokenOutputProcessor extends AbstractOutputProcessor {

    public BinarySecurityTokenOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        try {
            final String bstId = IDGenerator.generateID(null);
            final X509Certificate[] x509Certificates;
            final Key key;

            XMLSecurityConstants.Action action = getAction();
            if (action.equals(WSSConstants.SIGNATURE)
                    || action.equals(WSSConstants.SAML_TOKEN_SIGNED)
                    || action.equals(WSSConstants.SIGNATURE_WITH_DERIVED_KEY)) {

                String alias = ((WSSSecurityProperties) getSecurityProperties()).getSignatureUser();
                WSPasswordCallback pwCb = new WSPasswordCallback(alias, WSPasswordCallback.Usage.SIGNATURE);
                WSSUtils.doPasswordCallback(((WSSSecurityProperties)getSecurityProperties()).getCallbackHandler(), pwCb);
                String password = pwCb.getPassword();
                if (password == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "noPassword", alias);
                }
                key = ((WSSSecurityProperties) getSecurityProperties()).getSignatureCrypto().getPrivateKey(alias, password);
                CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
                cryptoType.setAlias(alias);
                x509Certificates = ((WSSSecurityProperties) getSecurityProperties()).getSignatureCrypto().getX509Certificates(cryptoType);
                if (x509Certificates == null || x509Certificates.length == 0) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "noUserCertsFound", alias);
                }
            } else if (action.equals(WSSConstants.ENCRYPT) ||
                    action.equals(WSSConstants.ENCRYPT_WITH_DERIVED_KEY)) {
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
                    if (securityProperties.isEnableRevocation()) {
                        crypto.verifyTrust(x509Certificates, true);
                    }
                }
                
                // Check for Revocation
                if (x509Certificates != null) {
                    WSSSecurityProperties securityProperties = ((WSSSecurityProperties) getSecurityProperties());
                    if (securityProperties.isEnableRevocation()) {
                        Crypto crypto = securityProperties.getEncryptionCrypto();
                        crypto.verifyTrust(x509Certificates, true);
                    }
                }
                
                key = null;
            } else {
                x509Certificates = null;
                key = null;
            }

            final GenericOutboundSecurityToken binarySecurityToken =
                    new GenericOutboundSecurityToken(bstId, WSSConstants.X509V3Token, key, x509Certificates);
            final SecurityTokenProvider binarySecurityTokenProvider = new SecurityTokenProvider() {

                @SuppressWarnings("unchecked")
                @Override
                public OutboundSecurityToken getSecurityToken() throws WSSecurityException {
                    return binarySecurityToken;
                }

                @Override
                public String getId() {
                    return bstId;
                }
            };

            if (action.equals(WSSConstants.SIGNATURE)
                    || action.equals(WSSConstants.SAML_TOKEN_SIGNED)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, bstId);
                if (getSecurityProperties().getSignatureKeyIdentifierType() == WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE) {
                    outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_APPEND_SIGNATURE_ON_THIS_ID, bstId);
                    FinalBinarySecurityTokenOutputProcessor finalBinarySecurityTokenOutputProcessor = new FinalBinarySecurityTokenOutputProcessor(binarySecurityToken);
                    finalBinarySecurityTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                    finalBinarySecurityTokenOutputProcessor.setAction(getAction());
                    finalBinarySecurityTokenOutputProcessor.addBeforeProcessor(WSSSignatureOutputProcessor.class.getName());
                    finalBinarySecurityTokenOutputProcessor.init(outputProcessorChain);
                    binarySecurityToken.setProcessor(finalBinarySecurityTokenOutputProcessor);
                }
            } else if (action.equals(WSSConstants.ENCRYPT)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY, bstId);
                if (((WSSSecurityProperties) getSecurityProperties()).getEncryptionKeyIdentifierType() == WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE) {
                    FinalBinarySecurityTokenOutputProcessor finalBinarySecurityTokenOutputProcessor = new FinalBinarySecurityTokenOutputProcessor(binarySecurityToken);
                    finalBinarySecurityTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                    finalBinarySecurityTokenOutputProcessor.setAction(getAction());
                    finalBinarySecurityTokenOutputProcessor.addAfterProcessor(EncryptEndingOutputProcessor.class.getName());
                    finalBinarySecurityTokenOutputProcessor.init(outputProcessorChain);
                    binarySecurityToken.setProcessor(finalBinarySecurityTokenOutputProcessor);
                }
            } else if (action.equals(WSSConstants.SIGNATURE_WITH_DERIVED_KEY)
                    || action.equals(WSSConstants.ENCRYPT_WITH_DERIVED_KEY)) {

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
                    TokenSecurityEvent tokenSecurityEvent = (TokenSecurityEvent) securityEvent;
                    if (!tokenSecurityEvent.getSecurityToken().getTokenUsages().contains(SecurityToken.TokenUsage.MainSignature)) {
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
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            outputProcessorChain.processEvent(xmlSecEvent);
            if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
                XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
                if (xmlSecStartElement.getName().equals(WSSConstants.TAG_wsse_Security)
                        && WSSUtils.isInSecurityHeader(xmlSecStartElement, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                    boolean useSingleCertificate = getSecurityProperties().isUseSingleCert();
                    WSSUtils.createBinarySecurityTokenStructure(this, subOutputProcessorChain, securityToken.getId(), securityToken.getX509Certificates(), useSingleCertificate);

                    outputProcessorChain.removeProcessor(this);
                }
            }
        }
    }
}
