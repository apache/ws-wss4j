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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import org.apache.commons.codec.binary.Base64;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.utils.WSSUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.AbstractOutputProcessor;
import org.apache.xml.security.stax.ext.OutputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

public class EncryptedKeyOutputProcessor extends AbstractOutputProcessor {

    public EncryptedKeyOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) 
        throws XMLStreamException, XMLSecurityException {
        try {

            String tokenId = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY);
            if (tokenId == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }
            SecurityTokenProvider<OutboundSecurityToken> wrappingSecurityTokenProvider =
                    outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
            if (wrappingSecurityTokenProvider == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }
            final OutboundSecurityToken wrappingSecurityToken = wrappingSecurityTokenProvider.getSecurityToken();
            if (wrappingSecurityToken == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }

            SecurityTokenProvider<OutboundSecurityToken> encryptedKeySecurityTokenProvider = null;
            GenericOutboundSecurityToken encryptedKeySecurityToken = null;

            String sigTokenId =
                    outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE);
            // See if a Symmetric Key is already available
            String encTokenId =
                    outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION);
            if (encTokenId == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }

            encryptedKeySecurityTokenProvider =
                outputProcessorChain.getSecurityContext().getSecurityTokenProvider(encTokenId);
            if (encryptedKeySecurityTokenProvider == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }
            encryptedKeySecurityToken =
                    (GenericOutboundSecurityToken)encryptedKeySecurityTokenProvider.getSecurityToken();

            boolean sharedToken = encTokenId.equals(sigTokenId);

            FinalEncryptedKeyOutputProcessor finalEncryptedKeyOutputProcessor = 
                new FinalEncryptedKeyOutputProcessor(encryptedKeySecurityToken);
            finalEncryptedKeyOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
            finalEncryptedKeyOutputProcessor.setAction(getAction());
            XMLSecurityConstants.Action action = getAction();
            if (WSSConstants.ENCRYPT.equals(action)) {
                if (wrappingSecurityToken.getProcessor() != null) {
                    finalEncryptedKeyOutputProcessor.addBeforeProcessor(wrappingSecurityToken.getProcessor());
                    finalEncryptedKeyOutputProcessor.init(outputProcessorChain);
                } else if (sharedToken) {
                    finalEncryptedKeyOutputProcessor.addAfterProcessor(EncryptEndingOutputProcessor.class.getName());

                    //hint for the headerReordering processor where to place the EncryptedKey
                    if (getSecurityProperties().getActions().indexOf(WSSConstants.ENCRYPT) 
                        < getSecurityProperties().getActions().indexOf(WSSConstants.SIGNATURE)) {
                        finalEncryptedKeyOutputProcessor.addBeforeProcessor(WSSSignatureOutputProcessor.class.getName());
                        finalEncryptedKeyOutputProcessor.setAction(WSSConstants.SIGNATURE);
                    }
                    finalEncryptedKeyOutputProcessor.setOutputReferenceList(false);
                    finalEncryptedKeyOutputProcessor.init(outputProcessorChain);

                    ReferenceListOutputProcessor referenceListOutputProcessor = new ReferenceListOutputProcessor();
                    referenceListOutputProcessor.addBeforeProcessor(finalEncryptedKeyOutputProcessor);
                    referenceListOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                    referenceListOutputProcessor.setAction(getAction());
                    referenceListOutputProcessor.init(outputProcessorChain);
                } else {
                    finalEncryptedKeyOutputProcessor.addAfterProcessor(EncryptEndingOutputProcessor.class.getName());
                    finalEncryptedKeyOutputProcessor.init(outputProcessorChain);
                }
            } else if (WSSConstants.SIGNATURE_WITH_DERIVED_KEY.equals(action)) {
                if (wrappingSecurityToken.getProcessor() != null) {
                    finalEncryptedKeyOutputProcessor.addBeforeProcessor(wrappingSecurityToken.getProcessor());
                } else {
                    finalEncryptedKeyOutputProcessor.addBeforeProcessor(WSSSignatureOutputProcessor.class.getName());
                }
                finalEncryptedKeyOutputProcessor.init(outputProcessorChain);
            } else if (WSSConstants.ENCRYPT_WITH_DERIVED_KEY.equals(action)) {
                if (wrappingSecurityToken.getProcessor() != null) {
                    finalEncryptedKeyOutputProcessor.addBeforeProcessor(wrappingSecurityToken.getProcessor());
                    finalEncryptedKeyOutputProcessor.init(outputProcessorChain);
                } else if (sharedToken) {
                    finalEncryptedKeyOutputProcessor.addBeforeProcessor(WSSSignatureOutputProcessor.class.getName());
                    finalEncryptedKeyOutputProcessor.addAfterProcessor(EncryptEndingOutputProcessor.class.getName());

                    //hint for the headerReordering processor where to place the EncryptedKey
                    if (getSecurityProperties().getActions().indexOf(WSSConstants.ENCRYPT_WITH_DERIVED_KEY) 
                        < getSecurityProperties().getActions().indexOf(WSSConstants.SIGNATURE_WITH_DERIVED_KEY)) {
                        finalEncryptedKeyOutputProcessor.setAction(WSSConstants.SIGNATURE_WITH_DERIVED_KEY);
                    }
                    finalEncryptedKeyOutputProcessor.setOutputReferenceList(false);
                    finalEncryptedKeyOutputProcessor.init(outputProcessorChain);
                } else {
                    finalEncryptedKeyOutputProcessor.addAfterProcessor(EncryptEndingOutputProcessor.class.getName());
                    finalEncryptedKeyOutputProcessor.init(outputProcessorChain);
                }
                ReferenceListOutputProcessor referenceListOutputProcessor = new ReferenceListOutputProcessor();
                referenceListOutputProcessor.addBeforeProcessor(finalEncryptedKeyOutputProcessor);
                referenceListOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
                referenceListOutputProcessor.setAction(getAction());
                referenceListOutputProcessor.init(outputProcessorChain);
            } else {
                finalEncryptedKeyOutputProcessor.init(outputProcessorChain);
            }

            outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(
                    encryptedKeySecurityToken.getId(), encryptedKeySecurityTokenProvider);
            encryptedKeySecurityToken.setProcessor(finalEncryptedKeyOutputProcessor);
        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }

    class FinalEncryptedKeyOutputProcessor extends AbstractOutputProcessor {

        private final OutboundSecurityToken securityToken;
        private boolean outputReferenceList = true;

        FinalEncryptedKeyOutputProcessor(OutboundSecurityToken securityToken) throws XMLSecurityException {
            super();
            this.addAfterProcessor(FinalEncryptedKeyOutputProcessor.class.getName());
            this.securityToken = securityToken;
        }

        protected void setOutputReferenceList(boolean outputReferenceList) {
            this.outputReferenceList = outputReferenceList;
        }

        @Override
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain)
                throws XMLStreamException, XMLSecurityException {

            outputProcessorChain.processEvent(xmlSecEvent);

            if (WSSUtils.isSecurityHeaderElement(xmlSecEvent, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {

                final QName headerElementName = WSSConstants.TAG_xenc_EncryptedKey;
                OutputProcessorUtils.updateSecurityHeaderOrder(outputProcessorChain, headerElementName, getAction(), false);

                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                final X509Certificate x509Certificate = securityToken.getKeyWrappingToken().getX509Certificates()[0];
                final String encryptionKeyTransportAlgorithm = getSecurityProperties().getEncryptionKeyTransportAlgorithm();

                List<XMLSecAttribute> attributes = new ArrayList<>(1);
                attributes.add(createAttribute(WSSConstants.ATT_NULL_Id, securityToken.getId()));
                createStartElementAndOutputAsEvent(subOutputProcessorChain, headerElementName, true, attributes);

                attributes = new ArrayList<>(1);
                attributes.add(createAttribute(WSSConstants.ATT_NULL_Algorithm, encryptionKeyTransportAlgorithm));
                createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_EncryptionMethod, false, attributes);

                final String encryptionKeyTransportMGFAlgorithm = getSecurityProperties().getEncryptionKeyTransportMGFAlgorithm();

                if (XMLSecurityConstants.NS_XENC11_RSAOAEP.equals(encryptionKeyTransportAlgorithm) 
                    || XMLSecurityConstants.NS_XENC_RSAOAEPMGF1P.equals(encryptionKeyTransportAlgorithm)) {

                    byte[] oaepParams = getSecurityProperties().getEncryptionKeyTransportOAEPParams();
                    if (oaepParams != null) {
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_xenc_OAEPparams, 
                                                           false, null);
                        createCharactersAndOutputAsEvent(subOutputProcessorChain, Base64.encodeBase64String(oaepParams));
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_xenc_OAEPparams);
                    }

                    String encryptionKeyTransportDigestAlgorithm = getSecurityProperties().getEncryptionKeyTransportDigestAlgorithm();
                    if (encryptionKeyTransportDigestAlgorithm != null) {
                        attributes = new ArrayList<>(1);
                        attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm, encryptionKeyTransportDigestAlgorithm));
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_DigestMethod, 
                                                           true, attributes);
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_dsig_DigestMethod);
                    }

                    if (encryptionKeyTransportMGFAlgorithm != null) {
                        attributes = new ArrayList<>(1);
                        attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm, encryptionKeyTransportMGFAlgorithm));
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_xenc11_MGF, 
                                                           true, attributes);
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, XMLSecurityConstants.TAG_xenc11_MGF);
                    }
                }

                createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_EncryptionMethod);
                createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_KeyInfo, true, null);
                createSecurityTokenReferenceStructureForEncryptedKey(
                        subOutputProcessorChain, securityToken,
                        ((WSSSecurityProperties) getSecurityProperties()).getEncryptionKeyIdentifier(),
                        getSecurityProperties().isUseSingleCert()
                );
                createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_KeyInfo);
                createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_CipherData, false, null);
                createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_CipherValue, false, null);

                try {
                    //encrypt the symmetric session key with the public key from the receiver:
                    String jceid = JCEAlgorithmMapper.translateURItoJCEID(encryptionKeyTransportAlgorithm);
                    Cipher cipher = Cipher.getInstance(jceid);

                    AlgorithmParameterSpec algorithmParameterSpec = null;
                    if (XMLSecurityConstants.NS_XENC11_RSAOAEP.equals(encryptionKeyTransportAlgorithm) 
                        || XMLSecurityConstants.NS_XENC_RSAOAEPMGF1P.equals(encryptionKeyTransportAlgorithm)) {

                        String jceDigestAlgorithm = "SHA-1";
                        String encryptionKeyTransportDigestAlgorithm = 
                            getSecurityProperties().getEncryptionKeyTransportDigestAlgorithm();
                        if (encryptionKeyTransportDigestAlgorithm != null) {
                            jceDigestAlgorithm = JCEAlgorithmMapper.translateURItoJCEID(encryptionKeyTransportDigestAlgorithm);
                        }

                        PSource.PSpecified pSource = PSource.PSpecified.DEFAULT;
                        byte[] oaepParams = getSecurityProperties().getEncryptionKeyTransportOAEPParams();
                        if (oaepParams != null) {
                            pSource = new PSource.PSpecified(oaepParams);
                        }

                        MGF1ParameterSpec mgfParameterSpec = new MGF1ParameterSpec("SHA-1");
                        if (encryptionKeyTransportMGFAlgorithm != null) {
                            String jceMGFAlgorithm = JCEAlgorithmMapper.translateURItoJCEID(encryptionKeyTransportMGFAlgorithm);
                            mgfParameterSpec = new MGF1ParameterSpec(jceMGFAlgorithm);
                        }
                        algorithmParameterSpec = new OAEPParameterSpec(jceDigestAlgorithm, "MGF1", mgfParameterSpec, pSource);
                    }

                    cipher.init(Cipher.WRAP_MODE, x509Certificate.getPublicKey(), algorithmParameterSpec);

                    Key secretKey = securityToken.getSecretKey("");

                    int blockSize = cipher.getBlockSize();
                    if (blockSize > 0 && blockSize < secretKey.getEncoded().length) {
                        throw new WSSecurityException(
                                WSSecurityException.ErrorCode.FAILURE,
                                "unsupportedKeyTransp",
                                new Object[] {"public key algorithm too weak to encrypt symmetric key"}
                        );
                    }
                    byte[] encryptedEphemeralKey = cipher.wrap(secretKey);

                    if (((WSSSecurityProperties)getSecurityProperties()).getCallbackHandler() != null) {
                        // Store the Encrypted Key in the CallbackHandler for processing on the inbound side
                        WSPasswordCallback callback =
                            new WSPasswordCallback(securityToken.getId(), WSPasswordCallback.SECRET_KEY);
                        callback.setKey(encryptedEphemeralKey);
                        try {
                            ((WSSSecurityProperties)getSecurityProperties()).getCallbackHandler().handle(new Callback[]{callback});
                        } catch (IOException | UnsupportedCallbackException e) { // NOPMD
                            // Do nothing
                        }
                    }

                    createCharactersAndOutputAsEvent(subOutputProcessorChain, 
                                                     new Base64(76, new byte[]{'\n'}).encodeToString(encryptedEphemeralKey));

                } catch (NoSuchPaddingException | NoSuchAlgorithmException
                    | InvalidKeyException | IllegalBlockSizeException
                    | InvalidAlgorithmParameterException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
                }

                createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_CipherValue);
                createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_CipherData);

                if (outputReferenceList && WSSConstants.ENCRYPT.equals(getAction())) {
                    WSSUtils.createReferenceListStructureForEncryption(this, subOutputProcessorChain);
                }
                createEndElementAndOutputAsEvent(subOutputProcessorChain, headerElementName);
                outputProcessorChain.removeProcessor(this);
            }
        }

        protected void createSecurityTokenReferenceStructureForEncryptedKey(
                OutputProcessorChain outputProcessorChain,
                OutboundSecurityToken securityToken,
                WSSecurityTokenConstants.KeyIdentifier keyIdentifier,
                boolean useSingleCertificate)
                throws XMLStreamException, XMLSecurityException {

            if (securityToken.getCustomTokenReference() != null) {
                outputDOMElement(securityToken.getCustomTokenReference(), outputProcessorChain);
                return;
            }

            List<XMLSecAttribute> attributes = new ArrayList<>(2);
            attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, IDGenerator.generateID(null)));
            if (WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference.equals(keyIdentifier) && !useSingleCertificate) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_X509PKIPathv1));
            }
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference, false, attributes);

            X509Certificate[] x509Certificates = securityToken.getKeyWrappingToken().getX509Certificates();
            String tokenId = securityToken.getKeyWrappingToken().getId();

            if (WSSecurityTokenConstants.KeyIdentifier_IssuerSerial.equals(keyIdentifier)) {
                WSSUtils.createX509IssuerSerialStructure(this, outputProcessorChain, x509Certificates);
            } else if (WSSecurityTokenConstants.KeyIdentifier_SkiKeyIdentifier.equals(keyIdentifier)) {
                WSSUtils.createX509SubjectKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (WSSecurityTokenConstants.KeyIdentifier_X509KeyIdentifier.equals(keyIdentifier)) {
                WSSUtils.createX509KeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (WSSecurityTokenConstants.KeyIdentifier_ThumbprintIdentifier.equals(keyIdentifier)) {
                WSSUtils.createThumbprintKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (WSSecurityTokenConstants.KeyIdentifier_EncryptedKeySha1Identifier.equals(keyIdentifier)) {
                //not applicable, fallback to thumbprint...
                WSSUtils.createThumbprintKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (WSSecurityTokenConstants.KeyIdentifier_SecurityTokenDirectReference.equals(keyIdentifier)) {
                String valueType;
                if (useSingleCertificate) {
                    valueType = WSSConstants.NS_X509_V3_TYPE;
                } else {
                    valueType = WSSConstants.NS_X509PKIPathv1;
                }
                WSSUtils.createBSTReferenceStructure(this, outputProcessorChain, tokenId, valueType, true);
            } else {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "unsupportedSecurityToken");
            }
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference);
        }
    }
}
