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
package org.swssf.wss.impl.processor.output;

import org.apache.commons.codec.binary.Base64;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.ext.WSSUtils;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.impl.securityToken.AbstractSecurityToken;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.impl.util.IDGenerator;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class EncryptedKeyOutputProcessor extends AbstractOutputProcessor {

    public EncryptedKeyOutputProcessor() throws XMLSecurityException {
        super();
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        try {

            String tokenId = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY);
            if (tokenId == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION);
            }
            SecurityTokenProvider wrappingSecurityTokenProvider = outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
            if (wrappingSecurityTokenProvider == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION);
            }
            final SecurityToken wrappingSecurityToken = wrappingSecurityTokenProvider.getSecurityToken();
            if (wrappingSecurityToken == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION);
            }

            //prepare the symmetric session key for all encryption parts
            String keyAlgorithm = JCEAlgorithmMapper.getJCERequiredKeyFromURI(securityProperties.getEncryptionSymAlgorithm());
            KeyGenerator keyGen;
            try {
                keyGen = KeyGenerator.getInstance(keyAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
            }
            //the sun JCE provider expects the real key size for 3DES (112 or 168 bit)
            //whereas bouncy castle expects the block size of 128 or 192 bits
            if (keyAlgorithm.contains("AES")) {
                int keyLength = JCEAlgorithmMapper.getKeyLengthFromURI(securityProperties.getEncryptionSymAlgorithm());
                keyGen.init(keyLength);
            }

            final Key symmetricKey = keyGen.generateKey();

            final String ekId = IDGenerator.generateID(null);

            final AbstractSecurityToken encryptedKeySecurityToken = new AbstractSecurityToken(ekId) {

                public boolean isAsymmetric() {
                    return false;
                }

                public Key getKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
                    return symmetricKey;
                }

                public PublicKey getPubKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
                    return null;
                }

                public X509Certificate[] getX509Certificates() throws XMLSecurityException {
                    return null;
                }

                public SecurityToken getKeyWrappingToken() {
                    return wrappingSecurityToken;
                }

                public WSSConstants.TokenType getTokenType() {
                    return null;
                }
            };
            wrappingSecurityToken.addWrappedToken(encryptedKeySecurityToken);

            final SecurityTokenProvider encryptedKeySecurityTokenProvider = new SecurityTokenProvider() {

                @Override
                public SecurityToken getSecurityToken() throws XMLSecurityException {
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
                    finalEncryptedKeyOutputProcessor.addBeforeProcessor(SignatureOutputProcessor.class.getName());
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

        private final SecurityToken securityToken;

        FinalEncryptedKeyOutputProcessor(SecurityToken securityToken) throws XMLSecurityException {
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

                    X509Certificate x509Certificate = securityToken.getKeyWrappingToken().getX509Certificates()[0];

                    List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(1);
                    attributes.add(createAttribute(WSSConstants.ATT_NULL_Id, securityToken.getId()));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_EncryptedKey, true, attributes);

                    attributes = new ArrayList<XMLSecAttribute>(1);
                    attributes.add(createAttribute(WSSConstants.ATT_NULL_Algorithm, getSecurityProperties().getEncryptionKeyTransportAlgorithm()));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_EncryptionMethod, false, attributes);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_EncryptionMethod);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_KeyInfo, true, null);
                    createSecurityTokenReferenceStructureForEncryptedKey(subOutputProcessorChain, securityToken, ((WSSSecurityProperties) getSecurityProperties()).getEncryptionKeyIdentifierType(), getSecurityProperties().isUseSingleCert());
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_KeyInfo);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_CipherData, false, null);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_CipherValue, false, null);

                    try {
                        //encrypt the symmetric session key with the public key from the receiver:
                        String jceid = JCEAlgorithmMapper.translateURItoJCEID(getSecurityProperties().getEncryptionKeyTransportAlgorithm());
                        Cipher cipher = Cipher.getInstance(jceid);
                        cipher.init(Cipher.WRAP_MODE, x509Certificate);

                        Key secretKey = securityToken.getSecretKey(null, null);

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
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
                    } catch (NoSuchAlgorithmException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
                    } catch (InvalidKeyException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
                    } catch (IllegalBlockSizeException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
                    }

                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_CipherValue);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_CipherData);

                    if (getAction() == WSSConstants.ENCRYPT) {
                        createReferenceListStructure(subOutputProcessorChain);
                    }
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_EncryptedKey);
                    outputProcessorChain.removeProcessor(this);
                }
            }
        }

        protected void createSecurityTokenReferenceStructureForEncryptedKey(
                OutputProcessorChain outputProcessorChain,
                SecurityToken securityToken,
                WSSConstants.KeyIdentifierType keyIdentifierType,
                boolean useSingleCertificate)
                throws XMLStreamException, XMLSecurityException {

            List<XMLSecAttribute> attributes = new ArrayList<XMLSecAttribute>(2);
            attributes.add(createAttribute(WSSConstants.ATT_wsu_Id, IDGenerator.generateID(null)));
            if (keyIdentifierType == WSSConstants.KeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE && !useSingleCertificate) {
                attributes.add(createAttribute(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_X509PKIPathv1));
            }
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference, false, attributes);

            X509Certificate[] x509Certificates = securityToken.getKeyWrappingToken().getX509Certificates();
            String tokenId = securityToken.getKeyWrappingToken().getId();

            if (keyIdentifierType == WSSConstants.KeyIdentifierType.ISSUER_SERIAL) {
                createX509IssuerSerialStructure(outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.SKI_KEY_IDENTIFIER) {
                WSSUtils.createX509SubjectKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.X509_KEY_IDENTIFIER) {
                WSSUtils.createX509KeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.THUMBPRINT_IDENTIFIER) {
                WSSUtils.createThumbprintKeyIdentifierStructure(this, outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType == WSSConstants.KeyIdentifierType.SECURITY_TOKEN_DIRECT_REFERENCE) {
                String valueType;
                if (useSingleCertificate) {
                    valueType = WSSConstants.NS_X509_V3_TYPE;
                } else {
                    valueType = WSSConstants.NS_X509PKIPathv1;
                }
                WSSUtils.createBSTReferenceStructure(this, outputProcessorChain, tokenId, valueType);
            } else {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_ENCRYPTION, "unsupportedSecurityToken", keyIdentifierType.name());
            }
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference);
        }
    }
}
