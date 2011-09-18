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
package org.swssf.impl.processor.output;

import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.securityToken.DelegatingSecurityToken;
import org.swssf.impl.securityToken.ProcessorInfoSecurityToken;
import org.swssf.impl.securityToken.X509SecurityToken;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.SignatureTokenSecurityEvent;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.Key;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class BinarySecurityTokenOutputProcessor extends AbstractOutputProcessor {

    public BinarySecurityTokenOutputProcessor(SecurityProperties securityProperties, Constants.Action action) throws WSSecurityException {
        super(securityProperties, action);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        try {
            final String bstId = "BST-" + UUID.randomUUID().toString();
            final X509Certificate[] x509Certificates;
            final Key key;

            switch (getAction()) {
                case SIGNATURE:
                case SAML_TOKEN_SIGNED:
                case SIGNATURE_WITH_DERIVED_KEY:
                    String alias = getSecurityProperties().getSignatureUser();
                    WSPasswordCallback pwCb = new WSPasswordCallback(alias, WSPasswordCallback.Usage.SIGNATURE);
                    Utils.doPasswordCallback(getSecurityProperties().getCallbackHandler(), pwCb);
                    String password = pwCb.getPassword();
                    if (password == null) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "noPassword", alias);
                    }
                    key = getSecurityProperties().getSignatureCrypto().getPrivateKey(alias, password);
                    x509Certificates = getSecurityProperties().getSignatureCrypto().getCertificates(getSecurityProperties().getSignatureUser());
                    if (x509Certificates == null || x509Certificates.length == 0) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_SIGNATURE, "noUserCertsFound", alias);
                    }
                    break;
                case ENCRYPT:
                case ENCRYPT_WITH_DERIVED_KEY:
                    X509Certificate x509Certificate = getReqSigCert(outputProcessorChain.getSecurityContext());
                    if (x509Certificate != null && getSecurityProperties().isUseReqSigCertForEncryption()) {
                        x509Certificates = new X509Certificate[1];
                        x509Certificates[0] = x509Certificate;
                    } else if (getSecurityProperties().getEncryptionUseThisCertificate() != null) {
                        x509Certificate = getSecurityProperties().getEncryptionUseThisCertificate();
                        x509Certificates = new X509Certificate[1];
                        x509Certificates[0] = x509Certificate;
                    } else {
                        x509Certificates = getSecurityProperties().getEncryptionCrypto().getCertificates(getSecurityProperties().getEncryptionUser());
                        if (x509Certificates == null || x509Certificates.length == 0) {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, "noUserCertsFound", getSecurityProperties().getEncryptionUser());
                        }
                    }
                    key = null;
                    break;
                default:
                    x509Certificates = null;
                    key = null;
                    break;
            }

            final ProcessorInfoSecurityToken binarySecurityToken = new ProcessorInfoSecurityToken() {

                private OutputProcessor outputProcessor;

                public String getId() {
                    return bstId;
                }

                public void setProcessor(OutputProcessor outputProcessor) {
                    this.outputProcessor = outputProcessor;
                }

                public Object getProcessor() {
                    return outputProcessor;
                }

                public boolean isAsymmetric() {
                    return true;
                }

                public Key getSecretKey(String algorithmURI, Constants.KeyUsage keyUsage) throws WSSecurityException {
                    return key;
                }

                public PublicKey getPublicKey(Constants.KeyUsage keyUsage) throws WSSecurityException {
                    return x509Certificates[0].getPublicKey();
                }

                public X509Certificate[] getX509Certificates() throws WSSecurityException {
                    return x509Certificates;
                }

                public void verify() throws WSSecurityException {
                }

                public SecurityToken getKeyWrappingToken() {
                    return null;
                }

                public String getKeyWrappingTokenAlgorithm() {
                    return null;
                }

                public Constants.TokenType getTokenType() {
                    return null;
                }
            };

            final SecurityTokenProvider binarySecurityTokenProvider = new SecurityTokenProvider() {
                public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                    return binarySecurityToken;
                }

                public String getId() {
                    return bstId;
                }
            };

            switch (getAction()) {
                case SIGNATURE:
                case SAML_TOKEN_SIGNED:
                    outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, bstId);
                    if (getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {
                        outputProcessorChain.getSecurityContext().put(Constants.PROP_APPEND_SIGNATURE_ON_THIS_ID, bstId);
                        FinalBinarySecurityTokenOutputProcessor finalBinarySecurityTokenOutputProcessor = new FinalBinarySecurityTokenOutputProcessor(getSecurityProperties(), getAction(), binarySecurityToken);
                        finalBinarySecurityTokenOutputProcessor.getBeforeProcessors().add(SignatureOutputProcessor.class.getName());
                        outputProcessorChain.addProcessor(finalBinarySecurityTokenOutputProcessor);
                        binarySecurityToken.setProcessor(finalBinarySecurityTokenOutputProcessor);
                    }
                    break;
                case ENCRYPT:
                    outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY, bstId);
                    if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {
                        FinalBinarySecurityTokenOutputProcessor finalBinarySecurityTokenOutputProcessor = new FinalBinarySecurityTokenOutputProcessor(getSecurityProperties(), getAction(), binarySecurityToken);
                        finalBinarySecurityTokenOutputProcessor.getAfterProcessors().add(EncryptEndingOutputProcessor.class.getName());
                        outputProcessorChain.addProcessor(finalBinarySecurityTokenOutputProcessor);
                        binarySecurityToken.setProcessor(finalBinarySecurityTokenOutputProcessor);
                    }
                    break;
                case SIGNATURE_WITH_DERIVED_KEY:
                case ENCRYPT_WITH_DERIVED_KEY:
                    switch (getSecurityProperties().getDerivedKeyTokenReference()) {

                        case DirectReference:
                            outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, bstId);
                            break;
                        case EncryptedKey:
                            outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY, bstId);
                            break;
                        case SecurityContextToken:
                            outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_SECURITYCONTEXTTOKEN, bstId);
                            break;
                    }
                    if ((getAction() == Constants.Action.ENCRYPT_WITH_DERIVED_KEY
                            && getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE)
                            || (getAction() == Constants.Action.SIGNATURE_WITH_DERIVED_KEY
                            && getSecurityProperties().getSignatureKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE)) {
                        FinalBinarySecurityTokenOutputProcessor finalBinarySecurityTokenOutputProcessor = new FinalBinarySecurityTokenOutputProcessor(getSecurityProperties(), getAction(), binarySecurityToken);
                        finalBinarySecurityTokenOutputProcessor.getAfterProcessors().add(EncryptEndingOutputProcessor.class.getName());
                        outputProcessorChain.addProcessor(finalBinarySecurityTokenOutputProcessor);
                        binarySecurityToken.setProcessor(finalBinarySecurityTokenOutputProcessor);
                    }
                    break;
            }

            outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(bstId, binarySecurityTokenProvider);

        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlEvent);
    }

    private X509Certificate getReqSigCert(SecurityContext securityContext) throws WSSecurityException {
        List<SecurityEvent> securityEventList = securityContext.getAsList(SecurityEvent.class);
        if (securityEventList != null) {
            for (int i = 0; i < securityEventList.size(); i++) {
                SecurityEvent securityEvent = securityEventList.get(i);
                //todo find correct message signature token...however...
                if (securityEvent.getSecurityEventType() == SecurityEvent.Event.SignatureToken) {
                    SignatureTokenSecurityEvent signatureTokenSecurityEvent = (SignatureTokenSecurityEvent) securityEvent;
                    SecurityToken securityToken = signatureTokenSecurityEvent.getSecurityToken();
                    if (securityToken instanceof DelegatingSecurityToken) {
                        securityToken = ((DelegatingSecurityToken) securityToken).getDelegatedSecurityToken();
                    }
                    if (securityToken instanceof X509SecurityToken) {
                        X509SecurityToken x509SecurityToken = (X509SecurityToken) securityToken;
                        return x509SecurityToken.getX509Certificates()[0];
                    }
                }
            }
        }
        return null;
    }

    class FinalBinarySecurityTokenOutputProcessor extends AbstractOutputProcessor {

        private SecurityToken securityToken;

        FinalBinarySecurityTokenOutputProcessor(SecurityProperties securityProperties, Constants.Action action, SecurityToken securityToken) throws WSSecurityException {
            super(securityProperties, action);
            this.getAfterProcessors().add(BinarySecurityTokenOutputProcessor.class.getName());
            this.securityToken = securityToken;
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
            outputProcessorChain.processEvent(xmlEvent);
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (outputProcessorChain.getDocumentContext().isInSecurityHeader() && startElement.getName().equals(Constants.TAG_wsse_Security)) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                    boolean useSingleCertificate = getSecurityProperties().isUseSingleCert();
                    createBinarySecurityTokenStructure(subOutputProcessorChain, securityToken.getId(), securityToken.getX509Certificates(), useSingleCertificate);

                    outputProcessorChain.removeProcessor(this);
                }
            }
        }
    }
}
