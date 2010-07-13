package ch.gigerstyle.xmlsec.processorImpl.output;

import ch.gigerstyle.xmlsec.*;
import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import ch.gigerstyle.xmlsec.crypto.WSSecurityException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.BinarySecurityTokenType;

import javax.crypto.*;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Characters;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * User: giger
 * Date: May 29, 2010
 * Time: 3:31:17 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class EncryptOutputProcessor extends AbstractOutputProcessor {

    private List<SecurePart> secureParts;
    private Key symmetricKey;
    private String symmetricKeyId = "EncKeyId-" + UUID.randomUUID().toString();
    private List<EncryptionPartDef> encryptionPartDefList = new ArrayList<EncryptionPartDef>();

    private InternalEncryptionOutputProcessor activeInternalEncryptionOutputProcessor = null;

    public EncryptOutputProcessor(SecurityProperties securityProperties) throws XMLSecurityException {
        super(securityProperties);
        secureParts = securityProperties.getEncryptionSecureParts();

        String keyAlgorithm = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(securityProperties.getEncryptionSymAlgorithm());
        int keyLength = JCEAlgorithmMapper.getKeyLengthFromURI(securityProperties.getEncryptionSymAlgorithm());
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance(keyAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new XMLSecurityException(e);
        }
        keyGen.init(keyLength);

        symmetricKey = keyGen.generateKey();
    }

    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            //avoid double encryption when child elements matches too
            if (activeInternalEncryptionOutputProcessor == null) {
                for (int i = 0; i < secureParts.size(); i++) {
                    SecurePart securePart = secureParts.get(i);
                    if (securePart.getId() == null) {
                        if (startElement.getName().getLocalPart().equals(securePart.getName())
                                && startElement.getName().getNamespaceURI().equals(securePart.getNamespace())) {

                            logger.debug("Matched securePart for encryption");
                            InternalEncryptionOutputProcessor internalEncryptionOutputProcessor = null;
                            try {
                                EncryptionPartDef encryptionPartDef = new EncryptionPartDef();
                                encryptionPartDef.setModifier(EncryptionPartDef.Modifier.valueOf(securePart.getModifier()));
                                encryptionPartDef.setEncRefId("EncDataId-" + UUID.randomUUID().toString());//"EncDataId-1612925417"
                                encryptionPartDef.setKeyId(symmetricKeyId);//EncKeyId-1483925398
                                encryptionPartDef.setSymmetricKey(symmetricKey);
                                encryptionPartDefList.add(encryptionPartDef);
                                internalEncryptionOutputProcessor = new InternalEncryptionOutputProcessor(getSecurityProperties(), encryptionPartDef, startElement.getName(), securityContext.<XMLEventNSAllocator>get("XMLEventNSAllocator"));
                            } catch (NoSuchAlgorithmException e) {
                                throw new XMLSecurityException(e.getMessage(), e);
                            } catch (NoSuchPaddingException e) {
                                throw new XMLSecurityException(e.getMessage(), e);
                            } catch (InvalidKeyException e) {
                                throw new XMLSecurityException(e.getMessage(), e);
                            } catch (IOException e) {
                                throw new XMLSecurityException(e.getMessage(), e);
                            }

                            activeInternalEncryptionOutputProcessor = internalEncryptionOutputProcessor;
                            outputProcessorChain.addProcessor(internalEncryptionOutputProcessor);
                            break;
                        }
                    }
                }
            }
        }

        outputProcessorChain.processEvent(xmlEvent);

        if (xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();
        }
    }

    @Override
    public void processHeaderEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            if (startElement.getName().equals(Constants.TAG_wsse_Security)) {

                outputProcessorChain.processHeaderEvent(xmlEvent);

                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                X509Certificate x509Certificate;
                if (getSecurityProperties().getEncryptionUseThisCertificate() != null) {
                    x509Certificate = getSecurityProperties().getEncryptionUseThisCertificate();
                } else {
                    try {
                        X509Certificate[] certs = getSecurityProperties().getEncryptionCrypto().getCertificates(getSecurityProperties().getEncryptionUser());
                        if (certs == null || certs.length <= 0) {
                            throw new XMLSecurityException("noUserCertsFound" + " encryption");
                        }
                        x509Certificate = certs[0];
                    } catch (WSSecurityException e) {
                        throw new XMLSecurityException(e);
                    }
                }

                String certUri = "CertId-" + UUID.randomUUID().toString();
                BinarySecurityTokenType referencedBinarySecurityTokenType = null;
                if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {
                    referencedBinarySecurityTokenType = new BinarySecurityTokenType();
                    referencedBinarySecurityTokenType.setEncodingType(Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
                    referencedBinarySecurityTokenType.setValueType(Constants.NS_X509_V3_TYPE);
                    referencedBinarySecurityTokenType.setId(certUri);

                    Map<QName, String> attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_EncodingType, referencedBinarySecurityTokenType.getEncodingType());
                    attributes.put(Constants.ATT_NULL_ValueType, referencedBinarySecurityTokenType.getValueType());
                    attributes.put(Constants.ATT_wsu_Id, referencedBinarySecurityTokenType.getId());
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken, attributes);
                    try {
                        createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, Base64.encodeBase64String(x509Certificate.getEncoded()));
                    } catch (CertificateEncodingException e) {
                        throw new XMLSecurityException(e);
                    }
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken);
                }

                Map<QName, String> attributes = new HashMap<QName, String>();
                attributes.put(Constants.ATT_NULL_Id, symmetricKeyId);
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_EncryptedKey, attributes);

                attributes = new HashMap<QName, String>();
                attributes.put(Constants.ATT_NULL_Algorithm, getSecurityProperties().getEncryptionKeyTransportAlgorithm());
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_EncryptionMethod, attributes);
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_EncryptionMethod);
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_KeyInfo, null);
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_SecurityTokenReference, null);

                if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.ISSUER_SERIAL) {

                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509Data, null);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerSerial, null);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerName, null);
                    createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, RFC2253Parser.normalize(x509Certificate.getIssuerDN().getName()));
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerName);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509SerialNumber, null);
                    createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, x509Certificate.getSerialNumber().toString());
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509SerialNumber);
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509IssuerSerial);
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_X509Data);
                } else if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.SKI_KEY_IDENTIFIER) {
                    // As per the 1.1 specification, SKI can only be used for a V3 certificate
                    if (x509Certificate.getVersion() != 3) {
                        throw new XMLSecurityException("invalidCertForSKI");
                    }

                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
                    attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509SubjectKeyIdentifier);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
                    try {
                        byte data[] = getSecurityProperties().getEncryptionCrypto().getSKIBytesFromCert(x509Certificate);
                        createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, Base64.encodeBase64String(data));
                    } catch (WSSecurityException e) {
                        throw new XMLSecurityException(e);
                    }
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
                } else if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.X509_KEY_IDENTIFIER) {

                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
                    attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509_V3_TYPE);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
                    try {
                        createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, Base64.encodeBase64String(x509Certificate.getEncoded()));
                    } catch (CertificateEncodingException e) {
                        throw new XMLSecurityException(e);
                    }
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
                } else if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.THUMBPRINT_IDENTIFIER) {

                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
                    attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_THUMBPRINT);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
                    try {
                        MessageDigest sha = null;
                        sha = MessageDigest.getInstance("SHA-1");
                        sha.reset();
                        sha.update(x509Certificate.getEncoded());
                        byte[] data = sha.digest();

                        createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, Base64.encodeBase64String(data));
                    } catch (CertificateEncodingException e) {
                        throw new XMLSecurityException(e);
                    } catch (NoSuchAlgorithmException e) {
                        throw new XMLSecurityException(e);
                    }
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
                } else if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.BST_EMBEDDED) {
                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_URI, "#" + certUri);
                    attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509_V3_TYPE);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference, attributes);

                    //todo probably we can reuse BinarySecurityTokenOutputProcessor??
                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_EncodingType, Constants.SOAPMESSAGE_NS10_BASE64_ENCODING);
                    attributes.put(Constants.ATT_NULL_ValueType, Constants.NS_X509_V3_TYPE);
                    attributes.put(Constants.ATT_wsu_Id, certUri);
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken, attributes);
                    try {
                        createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, Base64.encodeBase64String(x509Certificate.getEncoded()));
                    } catch (CertificateEncodingException e) {
                        throw new XMLSecurityException(e);
                    }
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken);

                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference);
                } else if (getSecurityProperties().getEncryptionKeyIdentifierType() == Constants.KeyIdentifierType.BST_DIRECT_REFERENCE) {

                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_URI, "#" + certUri);
                    attributes.put(Constants.ATT_NULL_ValueType, referencedBinarySecurityTokenType.getValueType());
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference, attributes);
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_Reference);
                } else {
                    throw new XMLSecurityException("Unsupported SecurityToken: " + getSecurityProperties().getEncryptionKeyIdentifierType().name());
                }

                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_SecurityTokenReference);
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_KeyInfo);
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_CipherData, null);
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_CipherValue, null);

                try {
                    String jceid = JCEAlgorithmMapper.translateURItoJCEID(getSecurityProperties().getEncryptionKeyTransportAlgorithm());
                    Cipher cipher = Cipher.getInstance(jceid);
                    cipher.init(Cipher.ENCRYPT_MODE, x509Certificate);

                    byte[] ephemeralKey = symmetricKey.getEncoded();

                    int blockSize = cipher.getBlockSize();
                    if (blockSize > 0 && blockSize < ephemeralKey.length) {
                        throw new XMLSecurityException("unsupportedKeyTransp" + " public key algorithm too weak to encrypt symmetric key");
                    }

                    byte[] encryptedEphemeralKey = cipher.doFinal(ephemeralKey);

                    createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, new String(org.bouncycastle.util.encoders.Base64.encode(encryptedEphemeralKey)));

                } catch (NoSuchPaddingException e) {
                    throw new XMLSecurityException(e);
                } catch (NoSuchAlgorithmException e) {
                    throw new XMLSecurityException(e);
                } catch (InvalidKeyException e) {
                    throw new XMLSecurityException(e);
                } catch (BadPaddingException e) {
                    throw new XMLSecurityException(e);
                } catch (IllegalBlockSizeException e) {
                    throw new XMLSecurityException(e);
                }

                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_CipherValue);
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_CipherData);

                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_ReferenceList, null);

                for (int i = 0; i < encryptionPartDefList.size(); i++) {
                    EncryptionPartDef encryptionPartDef = encryptionPartDefList.get(i);

                    attributes = new HashMap<QName, String>();
                    attributes.put(Constants.ATT_NULL_URI, "#" + encryptionPartDef.getEncRefId());
                    createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_DataReference, attributes);
                    createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_DataReference);
                }

                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_ReferenceList);
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_EncryptedKey);

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

                outputProcessorChain.removeProcessor(this);

                return;
            }
        }
        outputProcessorChain.processHeaderEvent(xmlEvent);
    }

    class InternalEncryptionOutputProcessor extends AbstractOutputProcessor {

        XMLEventNSAllocator xmlEventNSAllocator;
        private EncryptionPartDef encryptionPartDef;
        private CharacterEventGeneratorOutputStream characterEventGeneratorOutputStream;
        private Writer streamWriter;

        private QName startElement;
        private int elementCounter = 0;

        InternalEncryptionOutputProcessor(SecurityProperties securityProperties, EncryptionPartDef encryptionPartDef, QName startElement, XMLEventNSAllocator xmlEventNSAllocator) throws XMLSecurityException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException {
            super(securityProperties);
            this.xmlEventNSAllocator = xmlEventNSAllocator;
            this.encryptionPartDef = encryptionPartDef;
            this.startElement = startElement;

            String jceAlgorithm = JCEAlgorithmMapper.translateURItoJCEID(securityProperties.getEncryptionSymAlgorithm());
            Cipher symmetricCipher = Cipher.getInstance(jceAlgorithm);

            // Should internally generate an IV
            // todo - allow user to set an IV
            symmetricCipher.init(Cipher.ENCRYPT_MODE, encryptionPartDef.getSymmetricKey());
            byte[] iv = symmetricCipher.getIV();

            characterEventGeneratorOutputStream = new CharacterEventGeneratorOutputStream(xmlEventNSAllocator);
            //Base64EncoderStream calls write every 78byte (line breaks). So we have to buffer again to get optimal performance
            //todo play around to find optimal size
            Base64OutputStream base64EncoderStream = new Base64OutputStream(new BufferedOutputStream(characterEventGeneratorOutputStream), true);
            base64EncoderStream.write(iv);

            CipherOutputStream cipherOutputStream = new CipherOutputStream(base64EncoderStream, symmetricCipher);
            streamWriter = new BufferedWriter(new OutputStreamWriter(cipherOutputStream), symmetricCipher.getBlockSize() * 2); //todo encoding?
        }

        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

            if (xmlEvent.isStartElement()) {

                StartElement startElement = xmlEvent.asStartElement();

                if (startElement.getName().equals(this.startElement) && elementCounter == 0) {
                    if (encryptionPartDef.getModifier() == EncryptionPartDef.Modifier.Element) {
                        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                        processHeaderEventInternal(subOutputProcessorChain);
                        encryptEvent(xmlEvent);
                    } else if (encryptionPartDef.getModifier() == EncryptionPartDef.Modifier.Content) {
                        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                        outputAsEvent(subOutputProcessorChain, xmlEvent);
                        processHeaderEventInternal(subOutputProcessorChain);
                    }
                } else {
                    encryptEvent(xmlEvent);
                }

                elementCounter++;

            } else if (xmlEvent.isEndElement()) {
                elementCounter--;

                EndElement endElement = xmlEvent.asEndElement();

                if (endElement.getName().equals(this.startElement) && elementCounter == 0) {
                    OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                    if (encryptionPartDef.getModifier() == EncryptionPartDef.Modifier.Element) {
                        encryptEvent(xmlEvent);
                        doFinalInternal(subOutputProcessorChain);
                    } else {
                        doFinalInternal(subOutputProcessorChain);
                        outputAsEvent(subOutputProcessorChain, xmlEvent);
                    }
                    subOutputProcessorChain.removeProcessor(this);
                    //from now on encryption is possible again
                    activeInternalEncryptionOutputProcessor = null;

                } else {
                    encryptEvent(xmlEvent);
                }
            } else {
                encryptEvent(xmlEvent);

                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                Iterator<Characters> charactersIterator = characterEventGeneratorOutputStream.getCharactersBuffer().iterator();
                while (charactersIterator.hasNext()) {
                    Characters characters = charactersIterator.next();
                    outputAsEvent(subOutputProcessorChain, characters);
                    charactersIterator.remove();
                }
            }
        }

        @Override
        public void processHeaderEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
            outputProcessorChain.processHeaderEvent(xmlEvent);
        }

        private void encryptEvent(XMLEvent xmlEvent) throws XMLStreamException {
            xmlEvent.writeAsEncodedUnicode(streamWriter);
        }

        public void processHeaderEventInternal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            Map<QName, String> attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_Id, encryptionPartDef.getEncRefId());
            attributes.put(Constants.ATT_NULL_Type, encryptionPartDef.getModifier().getModifier());
            createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_EncryptedData, attributes);

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_Algorithm, securityProperties.getEncryptionSymAlgorithm());
            createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_EncryptionMethod, attributes);

            createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_EncryptionMethod);
            createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_dsig_KeyInfo, null);
            createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_SecurityTokenReference, null);

            attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_URI, "#" + encryptionPartDef.getKeyId());
            createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_Reference, attributes);
            createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_Reference);
            createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse_SecurityTokenReference);
            createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_dsig_KeyInfo);
            createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_CipherData, null);
            createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_CipherValue, null);

            /*
            <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="EncDataId-1612925417"
                Type="http://www.w3.org/2001/04/xmlenc#Content">
                <xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
                    Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc" />
                <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                    <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                    <wsse:Reference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
                        URI="#EncKeyId-1483925398" />
                    </wsse:SecurityTokenReference>
                </ds:KeyInfo>
                <xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
                    <xenc:CipherValue xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
                    ...
                    </xenc:CipherValue>
                </xenc:CipherData>
            </xenc:EncryptedData>
             */
            // outputProcessorChain.processHeaderEvent(xmlEvent);
        }

        public void doFinalInternal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

            try {
                streamWriter.close();
            } catch (IOException e) {
                throw new XMLStreamException(e);
            }
            Iterator<Characters> charactersIterator = characterEventGeneratorOutputStream.getCharactersBuffer().iterator();
            while (charactersIterator.hasNext()) {
                Characters characters = charactersIterator.next();
                outputAsEvent(outputProcessorChain, characters);
                charactersIterator.remove();
            }

            createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_CipherValue);
            createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_CipherData);
            createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_EncryptedData);
        }
    }

    class CharacterEventGeneratorOutputStream extends OutputStream {

        private List<Characters> charactersBuffer = new Vector<Characters>();
        XMLEventNSAllocator xmlEventNSAllocator;

        CharacterEventGeneratorOutputStream(XMLEventNSAllocator xmlEventNSAllocator) {
            this.xmlEventNSAllocator = xmlEventNSAllocator;
        }

        public List<Characters> getCharactersBuffer() {
            return charactersBuffer;
        }

        @Override
        public void write(int b) throws IOException {
            charactersBuffer.add(xmlEventNSAllocator.createCharacters(new String(new byte[]{((byte) b)})).asCharacters());
        }

        @Override
        public void write(byte[] b) throws IOException {
            charactersBuffer.add(xmlEventNSAllocator.createCharacters(new String(b)).asCharacters());
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            charactersBuffer.add(xmlEventNSAllocator.createCharacters(new String(b, off, len)).asCharacters());
        }
    }
}
