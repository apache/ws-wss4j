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

import org.apache.commons.codec.binary.Base64;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.securityToken.GenericOutboundSecurityToken;
import org.apache.xml.security.stax.impl.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.ArrayList;
import java.util.List;

public class EncryptedKeyOutputProcessor extends AbstractOutputProcessor {

    public EncryptedKeyOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        try {

            String tokenId = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY);
            if (tokenId == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }
            SecurityTokenProvider wrappingSecurityTokenProvider = outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
            if (wrappingSecurityTokenProvider == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }
            final OutboundSecurityToken wrappingSecurityToken = wrappingSecurityTokenProvider.getSecurityToken();
            if (wrappingSecurityToken == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }

            //prepare the symmetric session key for all encryption parts
            String keyAlgorithm = JCEAlgorithmMapper.getJCERequiredKeyFromURI(securityProperties.getEncryptionSymAlgorithm());
            KeyGenerator keyGen;
            try {
                keyGen = KeyGenerator.getInstance(keyAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
            }
            //the sun JCE provider expects the real key size for 3DES (112 or 168 bit)
            //whereas bouncy castle expects the block size of 128 or 192 bits
            if (keyAlgorithm.contains("AES")) {
                int keyLength = JCEAlgorithmMapper.getKeyLengthFromURI(securityProperties.getEncryptionSymAlgorithm());
                keyGen.init(keyLength);
            }

            final Key symmetricKey = keyGen.generateKey();

            final String ekId = IDGenerator.generateID(null);

            final GenericOutboundSecurityToken encryptedKeySecurityToken = new GenericOutboundSecurityToken(ekId, WSSConstants.EncryptedKeyToken, symmetricKey);
            encryptedKeySecurityToken.setKeyWrappingToken(wrappingSecurityToken);
            wrappingSecurityToken.addWrappedToken(encryptedKeySecurityToken);

            final SecurityTokenProvider encryptedKeySecurityTokenProvider = new SecurityTokenProvider() {

                @SuppressWarnings("unchecked")
                @Override
                public OutboundSecurityToken getSecurityToken() throws XMLSecurityException {
                    return encryptedKeySecurityToken;
                }

                @Override
                public String getId() {
                    return ekId;
                }
            };

            FinalEncryptedKeyOutputProcessor finalEncryptedKeyOutputProcessor = new FinalEncryptedKeyOutputProcessor(encryptedKeySecurityToken);
            finalEncryptedKeyOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
            finalEncryptedKeyOutputProcessor.setAction(getAction());
            XMLSecurityConstants.Action action = getAction();
            if (action.equals(WSSConstants.ENCRYPT)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION, ekId);
                if (wrappingSecurityToken.getProcessor() != null) {
                    finalEncryptedKeyOutputProcessor.addBeforeProcessor(wrappingSecurityToken.getProcessor());
                } else {
                    finalEncryptedKeyOutputProcessor.addAfterProcessor(EncryptEndingOutputProcessor.class.getName());
                }
            } else if (action.equals(WSSConstants.SIGNATURE_WITH_DERIVED_KEY)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, ekId);
                if (wrappingSecurityToken.getProcessor() != null) {
                    finalEncryptedKeyOutputProcessor.addBeforeProcessor(wrappingSecurityToken.getProcessor());
                } else {
                    finalEncryptedKeyOutputProcessor.addBeforeProcessor(WSSSignatureOutputProcessor.class.getName());
                }
            } else if (action.equals(WSSConstants.ENCRYPT_WITH_DERIVED_KEY)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, ekId);
                if (wrappingSecurityToken.getProcessor() != null) {
                    finalEncryptedKeyOutputProcessor.addBeforeProcessor(wrappingSecurityToken.getProcessor());
                } else {
                    finalEncryptedKeyOutputProcessor.addAfterProcessor(EncryptEndingOutputProcessor.class.getName());
                }
            }
            finalEncryptedKeyOutputProcessor.init(outputProcessorChain);
            outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(ekId, encryptedKeySecurityTokenProvider);
            encryptedKeySecurityToken.setProcessor(finalEncryptedKeyOutputProcessor);
        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }

    class FinalEncryptedKeyOutputProcessor extends AbstractOutputProcessor {

        private final OutboundSecurityToken securityToken;

        FinalEncryptedKeyOutputProcessor(OutboundSecurityToken securityToken) throws XMLSecurityException {
            super();
            this.addAfterProcessor(FinalEncryptedKeyOutputProcessor.class.getName());
            this.securityToken = securityToken;
        }

        /*
       <xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="EncKeyId-1483925398">
           <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
           <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
               <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                   <wsse:KeyIdentifier EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary" ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier">
                       pHoiKNGY2YsLBKxwIV+jURt858M=
                   </wsse:KeyIdentifier>
               </wsse:SecurityTokenReference>
           </ds:KeyInfo>
           <xenc:CipherData>
               <xenc:CipherValue>
                   Khsa9SN3ALNXOgGDKOqihvfwGsXb9QN/q4Fpi9uuThgz+3D4oRSMkrGSPCqwG13vddvHywGAA/XNbWNT+5Xivz3lURCDCc2H/92YlXXo/crQNJnPlLrLZ81bGOzbNo7lnYQBLp/77K7b1bhldZAeV9ZfEW7DjbOMZ+k1dnDCu3A=
               </xenc:CipherValue>
           </xenc:CipherData>
           <xenc:ReferenceList>
               <xenc:DataReference URI="#EncDataId-1612925417" />
           </xenc:ReferenceList>
       </xenc:EncryptedKey>
        */

        @Override
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            outputProcessorChain.processEvent(xmlSecEvent);
            if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
                XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
                if (xmlSecStartElement.getName().equals(WSSConstants.TAG_wsse_Security)
                        && WSSUtils.isInSecurityHeader(xmlSecStartElement, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                    final X509Certificate x509Certificate = securityToken.getKeyWrappingToken().getX509Certificates()[0];
                    final String encryptionKeyTransportAlgorithm = getSecurityProperties().getEncryptionKeyTransportAlgorithm();

                    List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
                    attributes.add(createAttribute(WSSConstants.ATT_NULL_Id, securityToken.getId()));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_EncryptedKey, true, attributes);

                    attributes = new ArrayList<XMLSecAttribute>(1);
                    attributes.add(createAttribute(WSSConstants.ATT_NULL_Algorithm, encryptionKeyTransportAlgorithm));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_EncryptionMethod, false, attributes);

                    final String encryptionKeyTransportMGFAlgorithm = getSecurityProperties().getEncryptionKeyTransportMGFAlgorithm();

                    if (XMLSecurityConstants.NS_XENC11_RSAOAEP.equals(encryptionKeyTransportAlgorithm) ||
                            XMLSecurityConstants.NS_XENC_RSAOAEPMGF1P.equals(encryptionKeyTransportAlgorithm)) {

                        byte[] oaepParams = getSecurityProperties().getEncryptionKeyTransportOAEPParams();
                        if (oaepParams != null) {
                            createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_OAEPparams, false, null);
                            createCharactersAndOutputAsEvent(outputProcessorChain, Base64.encodeBase64String(oaepParams));
                            createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_OAEPparams);
                        }

                        String encryptionKeyTransportDigestAlgorithm = getSecurityProperties().getEncryptionKeyTransportDigestAlgorithm();
                        if (encryptionKeyTransportDigestAlgorithm != null) {
                            attributes = new ArrayList<XMLSecAttribute>(1);
                            attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm, encryptionKeyTransportDigestAlgorithm));
                            createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_DigestMethod, true, attributes);
                            createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_DigestMethod);
                        }

                        if (encryptionKeyTransportMGFAlgorithm != null) {
                            attributes = new ArrayList<XMLSecAttribute>(1);
                            attributes.add(createAttribute(XMLSecurityConstants.ATT_NULL_Algorithm, encryptionKeyTransportMGFAlgorithm));
                            createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc11_MGF, true, attributes);
                            createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc11_MGF);
                        }
                    }

                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_EncryptionMethod);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_KeyInfo, true, null);
                    createSecurityTokenReferenceStructureForEncryptedKey(
                            subOutputProcessorChain, securityToken,
                            ((WSSSecurityProperties) getSecurityProperties()).getEncryptionKeyIdentifierType(),
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
                        if (XMLSecurityConstants.NS_XENC11_RSAOAEP.equals(encryptionKeyTransportAlgorithm) ||
                                XMLSecurityConstants.NS_XENC_RSAOAEPMGF1P.equals(encryptionKeyTransportAlgorithm)) {

                            String jceDigestAlgorithm = "SHA-1";
                            String encryptionKeyTransportDigestAlgorithm = getSecurityProperties().getEncryptionKeyTransportDigestAlgorithm();
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
                                    "public key algorithm too weak to encrypt symmetric key"
                            );
                        }
                        byte[] encryptedEphemeralKey = cipher.wrap(secretKey);

                        createCharactersAndOutputAsEvent(subOutputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(encryptedEphemeralKey));

                    } catch (NoSuchPaddingException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
                    } catch (NoSuchAlgorithmException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
                    } catch (InvalidKeyException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
                    } catch (IllegalBlockSizeException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
                    } catch (InvalidAlgorithmParameterException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
                    }

                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_CipherValue);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_CipherData);

                    if (getAction() == WSSConstants.ENCRYPT) {
                        WSSUtils.createReferenceListStructureForEncryption(this, subOutputProcessorChain);
                    }
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_EncryptedKey);
                    outputProcessorChain.removeProcessor(this);
                }
            }
        }

        protected void createSecurityTokenReferenceStructureForEncryptedKey(
                OutputProcessorChain outputProcessorChain,
                OutboundSecurityToken securityToken,
                WSSConstants.KeyIdentifierType keyIdentifierType,
                boolean useSingleCertificate)
                throws XMLStreamException, XMLSecurityException {

            List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
            attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, IDGenerator.generateID(null)));
            if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE && !useSingleCertificate) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_X509PKIPathv1));
            }
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference, false, attributes);

            X509Certificate[] x509Certificates = securityToken.getKeyWrappingToken().getX509Certificates();
            String tokenId = securityToken.getKeyWrappingToken().getId();

            if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.ISSUER_SERIAL) {
                createX509IssuerSerialStructure(outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.SKI_KEY_IDENTIFIER) {
                WSSUtils.createX509SubjectKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.X509_KEY_IDENTIFIER) {
                WSSUtils.createX509KeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.THUMBPRINT_IDENTIFIER) {
                WSSUtils.createThumbprintKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE) {
                String valueType;
                if (useSingleCertificate) {
                    valueType = WSSConstants.NS_X509_V3_TYPE;
                } else {
                    valueType = WSSConstants.NS_X509PKIPathv1;
                }
                WSSUtils.createBSTReferenceStructure(this, outputProcessorChain, tokenId, valueType);
            } else {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "unsupportedSecurityToken");
            }
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference);
        }
    }
}
