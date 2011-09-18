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

import org.apache.commons.codec.binary.Base64;
import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.securityToken.ProcessorInfoSecurityToken;

import javax.crypto.*;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class EncryptedKeyOutputProcessor extends AbstractOutputProcessor {

    public EncryptedKeyOutputProcessor(SecurityProperties securityProperties, Constants.Action action) throws WSSecurityException {
        super(securityProperties, action);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
        try {

            String tokenId = outputProcessorChain.getSecurityContext().get(Constants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY);
            if (tokenId == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION);
            }
            SecurityTokenProvider wrappingSecurityTokenProvider = outputProcessorChain.getSecurityContext().getSecurityTokenProvider(tokenId);
            if (wrappingSecurityTokenProvider == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION);
            }
            final SecurityToken wrappingSecurityToken = wrappingSecurityTokenProvider.getSecurityToken(null);
            if (wrappingSecurityToken == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION);
            }

            //prepare the symmetric session key for all encryption parts
            String keyAlgorithm = JCEAlgorithmMapper.getJCERequiredKeyFromURI(securityProperties.getEncryptionSymAlgorithm());
            int keyLength = JCEAlgorithmMapper.getKeyLengthFromURI(securityProperties.getEncryptionSymAlgorithm());
            KeyGenerator keyGen = null;
            try {
                keyGen = KeyGenerator.getInstance(keyAlgorithm);
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
            }
            keyGen.init(keyLength);

            final Key symmetricKey = keyGen.generateKey();

            final String ekId = "EK-" + UUID.randomUUID().toString();

            final ProcessorInfoSecurityToken encryptedKeySecurityToken = new ProcessorInfoSecurityToken() {

                private OutputProcessor outputProcessor;

                public String getId() {
                    return ekId;
                }

                public void setProcessor(OutputProcessor outputProcessor) {
                    this.outputProcessor = outputProcessor;
                }

                public Object getProcessor() {
                    return outputProcessor;
                }

                public boolean isAsymmetric() {
                    return false;
                }

                public Key getSecretKey(String algorithmURI, Constants.KeyUsage keyUsage) throws WSSecurityException {
                    return symmetricKey;
                }

                public PublicKey getPublicKey(Constants.KeyUsage keyUsage) throws WSSecurityException {
                    return null;
                }

                public X509Certificate[] getX509Certificates() throws WSSecurityException {
                    return null;
                }

                public void verify() throws WSSecurityException {
                }

                public SecurityToken getKeyWrappingToken() {
                    return wrappingSecurityToken;
                }

                public String getKeyWrappingTokenAlgorithm() {
                    return null;
                }

                public Constants.TokenType getTokenType() {
                    return null;
                }
            };

            final SecurityTokenProvider encryptedKeySecurityTokenProvider = new SecurityTokenProvider() {
                public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                    return encryptedKeySecurityToken;
                }

                public String getId() {
                    return ekId;
                }
            };

            FinalEncryptedKeyOutputProcessor finalEncryptedKeyOutputProcessor = new FinalEncryptedKeyOutputProcessor(getSecurityProperties(), getAction(), encryptedKeySecurityToken);
            switch (getAction()) {
                case ENCRYPT:
                    outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION, ekId);
                    if (wrappingSecurityToken.getProcessor() != null) {
                        finalEncryptedKeyOutputProcessor.getBeforeProcessors().add(wrappingSecurityToken.getProcessor());
                    } else {
                        finalEncryptedKeyOutputProcessor.getAfterProcessors().add(EncryptEndingOutputProcessor.class.getName());
                    }
                    break;
                case SIGNATURE_WITH_DERIVED_KEY:
                    outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, ekId);
                    if (wrappingSecurityToken.getProcessor() != null) {
                        finalEncryptedKeyOutputProcessor.getBeforeProcessors().add(wrappingSecurityToken.getProcessor());
                    } else {
                        finalEncryptedKeyOutputProcessor.getBeforeProcessors().add(SignatureOutputProcessor.class.getName());
                    }
                    break;
                case ENCRYPT_WITH_DERIVED_KEY:
                    outputProcessorChain.getSecurityContext().put(Constants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, ekId);
                    if (wrappingSecurityToken.getProcessor() != null) {
                        finalEncryptedKeyOutputProcessor.getBeforeProcessors().add(wrappingSecurityToken.getProcessor());
                    } else {
                        finalEncryptedKeyOutputProcessor.getAfterProcessors().add(EncryptEndingOutputProcessor.class.getName());
                    }
                    break;
            }
            outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(ekId, encryptedKeySecurityTokenProvider);
            encryptedKeySecurityToken.setProcessor(finalEncryptedKeyOutputProcessor);
            outputProcessorChain.addProcessor(finalEncryptedKeyOutputProcessor);
        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlEvent);
    }

    class FinalEncryptedKeyOutputProcessor extends AbstractOutputProcessor {

        private SecurityToken securityToken;

        FinalEncryptedKeyOutputProcessor(SecurityProperties securityProperties, Constants.Action action, SecurityToken securityToken) throws WSSecurityException {
            super(securityProperties, action);
            this.getAfterProcessors().add(FinalEncryptedKeyOutputProcessor.class.getName());
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
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
            outputProcessorChain.processEvent(xmlEvent);
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (outputProcessorChain.getDocumentContext().isInSecurityHeader() && startElement.getName().equals(Constants.TAG_wsse_Security)) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                    X509Certificate x509Certificate = securityToken.getKeyWrappingToken().getX509Certificates()[0];

                    Map<QName, String> attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_Id, securityToken.getId());
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_EncryptedKey, attributes);

                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_Algorithm, getSecurityProperties().getEncryptionKeyTransportAlgorithm());
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_EncryptionMethod, attributes);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_EncryptionMethod);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_KeyInfo, null);
                    createSecurityTokenReferenceStructureForEncryptedKey(subOutputProcessorChain, securityToken, getSecurityProperties().getEncryptionKeyIdentifierType(), getSecurityProperties().isUseSingleCert());
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_dsig_KeyInfo);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_CipherData, null);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_CipherValue, null);

                    try {
                        //encrypt the symmetric session key with the public key from the receiver:
                        String jceid = JCEAlgorithmMapper.translateURItoJCEID(getSecurityProperties().getEncryptionKeyTransportAlgorithm());
                        Cipher cipher = Cipher.getInstance(jceid);
                        cipher.init(Cipher.ENCRYPT_MODE, x509Certificate);

                        byte[] ephemeralKey = securityToken.getSecretKey(null, null).getEncoded();

                        int blockSize = cipher.getBlockSize();
                        if (blockSize > 0 && blockSize < ephemeralKey.length) {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "unsupportedKeyTransp", "public key algorithm too weak to encrypt symmetric key"
                            );
                        }
                        byte[] encryptedEphemeralKey = cipher.doFinal(ephemeralKey);

                        createCharactersAndOutputAsEvent(subOutputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(encryptedEphemeralKey));

                    } catch (NoSuchPaddingException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
                    } catch (NoSuchAlgorithmException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
                    } catch (InvalidKeyException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
                    } catch (BadPaddingException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
                    } catch (IllegalBlockSizeException e) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_ENCRYPTION, e);
                    }

                    createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_CipherValue);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_CipherData);

                    if (getAction() == Constants.Action.ENCRYPT) {
                        createReferenceListStructure(subOutputProcessorChain);
                    }
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, Constants.TAG_xenc_EncryptedKey);
                    outputProcessorChain.removeProcessor(this);
                }
            }
        }
    }
}
