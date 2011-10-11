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
import org.swssf.wss.ext.WSSDocumentContext;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.impl.securityToken.ProcessorInfoSecurityToken;
import org.swssf.xmlsec.config.JCEAlgorithmMapper;
import org.swssf.xmlsec.crypto.Crypto;
import org.swssf.xmlsec.crypto.Merlin;
import org.swssf.xmlsec.ext.*;

import javax.crypto.*;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class EncryptedKeyOutputProcessor extends AbstractOutputProcessor {

    public EncryptedKeyOutputProcessor(XMLSecurityProperties securityProperties, XMLSecurityConstants.Action action) throws XMLSecurityException {
        super(securityProperties, action);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
        try {

            String tokenId = outputProcessorChain.getSecurityContext().get(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTED_KEY);
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

                public Key getSecretKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
                    return symmetricKey;
                }

                public PublicKey getPublicKey(XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
                    return null;
                }

                public X509Certificate[] getX509Certificates() throws XMLSecurityException {
                    return null;
                }

                public void verify() throws XMLSecurityException {
                }

                public SecurityToken getKeyWrappingToken() {
                    return wrappingSecurityToken;
                }

                public String getKeyWrappingTokenAlgorithm() {
                    return null;
                }

                public WSSConstants.TokenType getTokenType() {
                    return null;
                }
            };

            final SecurityTokenProvider encryptedKeySecurityTokenProvider = new SecurityTokenProvider() {
                public SecurityToken getSecurityToken(Crypto crypto) throws XMLSecurityException {
                    return encryptedKeySecurityToken;
                }

                public String getId() {
                    return ekId;
                }
            };

            FinalEncryptedKeyOutputProcessor finalEncryptedKeyOutputProcessor = new FinalEncryptedKeyOutputProcessor(getSecurityProperties(), getAction(), encryptedKeySecurityToken);
            XMLSecurityConstants.Action action = getAction();
            if (action.equals(WSSConstants.ENCRYPT)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_ENCRYPTION, ekId);
                if (wrappingSecurityToken.getProcessor() != null) {
                    finalEncryptedKeyOutputProcessor.getBeforeProcessors().add(wrappingSecurityToken.getProcessor());
                } else {
                    finalEncryptedKeyOutputProcessor.getAfterProcessors().add(org.swssf.wss.impl.processor.output.EncryptEndingOutputProcessor.class.getName());
                }
            } else if (action.equals(WSSConstants.SIGNATURE_WITH_DERIVED_KEY)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, ekId);
                if (wrappingSecurityToken.getProcessor() != null) {
                    finalEncryptedKeyOutputProcessor.getBeforeProcessors().add(wrappingSecurityToken.getProcessor());
                } else {
                    finalEncryptedKeyOutputProcessor.getBeforeProcessors().add(org.swssf.wss.impl.processor.output.SignatureOutputProcessor.class.getName());
                }
            } else if (action.equals(WSSConstants.ENCRYPT_WITH_DERIVED_KEY)) {
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_DERIVED_KEY, ekId);
                if (wrappingSecurityToken.getProcessor() != null) {
                    finalEncryptedKeyOutputProcessor.getBeforeProcessors().add(wrappingSecurityToken.getProcessor());
                } else {
                    finalEncryptedKeyOutputProcessor.getAfterProcessors().add(org.swssf.wss.impl.processor.output.EncryptEndingOutputProcessor.class.getName());
                }
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

        FinalEncryptedKeyOutputProcessor(XMLSecurityProperties securityProperties, XMLSecurityConstants.Action action, SecurityToken securityToken) throws XMLSecurityException {
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
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            outputProcessorChain.processEvent(xmlEvent);
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                if (((WSSDocumentContext) outputProcessorChain.getDocumentContext()).isInSecurityHeader() && startElement.getName().equals(WSSConstants.TAG_wsse_Security)) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                    X509Certificate x509Certificate = securityToken.getKeyWrappingToken().getX509Certificates()[0];

                    Map<QName, String> attributes = new HashMap<QName, String>();
                    attributes.put(WSSConstants.ATT_NULL_Id, securityToken.getId());
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_EncryptedKey, attributes);

                    attributes = new HashMap<QName, String>();
                    attributes.put(WSSConstants.ATT_NULL_Algorithm, getSecurityProperties().getEncryptionKeyTransportAlgorithm());
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_EncryptionMethod, attributes);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_EncryptionMethod);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_KeyInfo, null);
                    createSecurityTokenReferenceStructureForEncryptedKey(subOutputProcessorChain, securityToken, ((WSSSecurityProperties) getSecurityProperties()).getEncryptionKeyIdentifierType(), getSecurityProperties().isUseSingleCert());
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_dsig_KeyInfo);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_CipherData, null);
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_xenc_CipherValue, null);

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

            Map<QName, String> attributes = new HashMap<QName, String>();
            attributes.put(WSSConstants.ATT_wsu_Id, "STRId-" + UUID.randomUUID().toString());
            if ((keyIdentifierType.name().equals(WSSConstants.KeyIdentifierType.BST_DIRECT_REFERENCE.name())
                    || keyIdentifierType.name().equals(WSSConstants.KeyIdentifierType.BST_EMBEDDED.name()))
                    && !useSingleCertificate) {
                attributes.put(WSSConstants.ATT_wsse11_TokenType, WSSConstants.NS_X509PKIPathv1);
            }
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference, attributes);

            X509Certificate[] x509Certificates = securityToken.getKeyWrappingToken().getX509Certificates();
            String tokenId = securityToken.getKeyWrappingToken().getId();

            if (keyIdentifierType.name().equals(WSSConstants.KeyIdentifierType.ISSUER_SERIAL.name())) {
                createX509IssuerSerialStructure(outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType.name().equals(WSSConstants.KeyIdentifierType.SKI_KEY_IDENTIFIER.name())) {
                createX509SubjectKeyIdentifierStructure(outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType.name().equals(WSSConstants.KeyIdentifierType.X509_KEY_IDENTIFIER.name())) {
                createX509KeyIdentifierStructure(outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType.name().equals(WSSConstants.KeyIdentifierType.THUMBPRINT_IDENTIFIER.name())) {
                createThumbprintKeyIdentifierStructure(outputProcessorChain, x509Certificates);
            } else if (keyIdentifierType.name().equals(WSSConstants.KeyIdentifierType.BST_EMBEDDED.name())) {
                createBSTReferenceStructure(outputProcessorChain, tokenId, x509Certificates, useSingleCertificate, true);
            } else if (keyIdentifierType.name().equals(WSSConstants.KeyIdentifierType.BST_DIRECT_REFERENCE.name())) {
                createBSTReferenceStructure(outputProcessorChain, tokenId, x509Certificates, useSingleCertificate, false);
            } else if (keyIdentifierType.name().equals(WSSConstants.KeyIdentifierType.EMBEDDED_SECURITY_TOKEN_REF.name())) {
                createEmbeddedSecurityTokenReferenceStructure(outputProcessorChain, tokenId);
            } else {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_ENCRYPTION, "unsupportedSecurityToken", keyIdentifierType.name());
            }
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_SecurityTokenReference);
        }

        //todo common method
        protected void createX509SubjectKeyIdentifierStructure(OutputProcessorChain outputProcessorChain, X509Certificate[] x509Certificates) throws XMLSecurityException, XMLStreamException {
            // As per the 1.1 specification, SKI can only be used for a V3 certificate
            if (x509Certificates[0].getVersion() != 3) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, "invalidCertForSKI");
            }

            Map<QName, String> attributes = new HashMap<QName, String>();
            attributes.put(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING);
            attributes.put(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_X509SubjectKeyIdentifier);
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, attributes);
            byte data[] = new Merlin().getSKIBytesFromCert(x509Certificates[0]);
            createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(data));
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
        }

        //todo common method
        protected void createX509KeyIdentifierStructure(OutputProcessorChain outputProcessorChain, X509Certificate[] x509Certificates) throws XMLStreamException, XMLSecurityException {
            Map<QName, String> attributes = new HashMap<QName, String>();
            attributes.put(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING);
            attributes.put(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_X509_V3_TYPE);
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, attributes);
            try {
                createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(x509Certificates[0].getEncoded()));
            } catch (CertificateEncodingException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            }
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
        }

        //todo common methdod
        protected void createThumbprintKeyIdentifierStructure(OutputProcessorChain outputProcessorChain, X509Certificate[] x509Certificates) throws XMLStreamException, XMLSecurityException {
            Map<QName, String> attributes = new HashMap<QName, String>();
            attributes.put(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING);
            attributes.put(WSSConstants.ATT_NULL_ValueType, WSSConstants.NS_THUMBPRINT);
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier, attributes);
            try {
                MessageDigest sha;
                sha = MessageDigest.getInstance("SHA-1");
                sha.reset();
                sha.update(x509Certificates[0].getEncoded());
                byte[] data = sha.digest();

                createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(data));
            } catch (CertificateEncodingException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            } catch (NoSuchAlgorithmException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            }
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_KeyIdentifier);
        }

        //todo common method
        protected void createBSTReferenceStructure(OutputProcessorChain outputProcessorChain, String referenceId, X509Certificate[] x509Certificates, boolean useSingleCertificate, boolean embed) throws XMLStreamException, XMLSecurityException {
            Map<QName, String> attributes = new HashMap<QName, String>();
            String valueType;
            if (useSingleCertificate) {
                valueType = WSSConstants.NS_X509_V3_TYPE;
            } else {
                valueType = WSSConstants.NS_X509PKIPathv1;
            }
            attributes.put(WSSConstants.ATT_NULL_URI, "#" + referenceId);
            attributes.put(WSSConstants.ATT_NULL_ValueType, valueType);
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference, attributes);
            if (embed) {
                createBinarySecurityTokenStructure(outputProcessorChain, referenceId, x509Certificates, useSingleCertificate);
            }
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference);
        }

        //todo common method
        protected void createEmbeddedSecurityTokenReferenceStructure(OutputProcessorChain outputProcessorChain, String referenceId) throws XMLStreamException, XMLSecurityException {
            Map<QName, String> attributes = new HashMap<QName, String>();
            attributes.put(WSSConstants.ATT_NULL_URI, "#" + referenceId);
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference, attributes);
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_Reference);
        }

        //todo common method
        protected void createBinarySecurityTokenStructure(OutputProcessorChain outputProcessorChain, String referenceId, X509Certificate[] x509Certificates, boolean useSingleCertificate) throws XMLStreamException, XMLSecurityException {
            Map<QName, String> attributes = new HashMap<QName, String>();
            String valueType;
            if (useSingleCertificate) {
                valueType = WSSConstants.NS_X509_V3_TYPE;
            } else {
                valueType = WSSConstants.NS_X509PKIPathv1;
            }
            attributes.put(WSSConstants.ATT_NULL_EncodingType, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING);
            attributes.put(WSSConstants.ATT_NULL_ValueType, valueType);
            attributes.put(WSSConstants.ATT_wsu_Id, referenceId);
            createStartElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_BinarySecurityToken, attributes);
            try {
                if (useSingleCertificate) {
                    createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(x509Certificates[0].getEncoded()));
                } else {
                    try {
                        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509", "BC");
                        List<X509Certificate> certificates = Arrays.asList(x509Certificates);
                        createCharactersAndOutputAsEvent(outputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(certificateFactory.generateCertPath(certificates).getEncoded()));
                    } catch (CertificateException e) {
                        throw new XMLSecurityException(XMLSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
                    } catch (NoSuchProviderException e) {
                        throw new XMLSecurityException(XMLSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
                    }
                }
            } catch (CertificateEncodingException e) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_SIGNATURE, e);
            }
            createEndElementAndOutputAsEvent(outputProcessorChain, WSSConstants.TAG_wsse_BinarySecurityToken);
        }
    }
}
