package ch.gigerstyle.xmlsec.processorImpl.output;

import ch.gigerstyle.xmlsec.*;
import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import ch.gigerstyle.xmlsec.crypto.WSSecurityException;
import com.sun.xml.internal.messaging.saaj.packaging.mime.util.BASE64EncoderStream;

import javax.crypto.*;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
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
    private String symmetricKeyId = UUID.randomUUID().toString();
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

            //prohibit double encryption when child elements matches too
            if (activeInternalEncryptionOutputProcessor == null) {
                for (int i = 0; i < secureParts.size(); i++) {
                    SecurePart securePart = secureParts.get(i);
                    if (securePart.getId() == null) {
                        if (startElement.getName().getLocalPart().equals(securePart.getName())
                                && startElement.getName().getNamespaceURI().equals(securePart.getNamespace())) {

                            System.out.println("matched securePart for encryption");
                            InternalEncryptionOutputProcessor internalEncryptionOutputProcessor = null;
                            try {
                                EncryptionPartDef encryptionPartDef = new EncryptionPartDef();
                                encryptionPartDef.setModifier(EncryptionPartDef.Modifier.valueOf(securePart.getModifier()));
                                encryptionPartDef.setEncRefId("EncDataId-" + UUID.randomUUID().toString());//"EncDataId-1612925417"
                                encryptionPartDef.setKeyId("#EncKeyId-" + symmetricKeyId);//#EncKeyId-1483925398
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

                Map<QName, String> attributes = new HashMap<QName, String>();
                attributes.put(Constants.ATT_NULL_Id, "#EncKeyId-" + symmetricKeyId);
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xmlenc_EncryptedKey, attributes);

                attributes = new HashMap<QName, String>();
                attributes.put(Constants.ATT_NULL_Algorithm, getSecurityProperties().getEncryptionKeyTransportAlgorithm());
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_EncryptionMethod, attributes);
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_EncryptionMethod);
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_KeyInfo, null);
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_SecurityTokenReference, null);

                attributes = new HashMap<QName, String>();
                attributes.put(Constants.ATT_NULL_EncodingType, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
                attributes.put(Constants.ATT_NULL_ValueType, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier");
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier, attributes);
                createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, "pHoiKNGY2YsLBKxwIV+jURt858M=");
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_KeyIdentifier);
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_SecurityTokenReference);
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_dsig_KeyInfo);
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_CipherData, null);
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xenc_CipherValue, null);

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

                String jceid = JCEAlgorithmMapper.translateURItoJCEID(getSecurityProperties().getEncryptionKeyTransportAlgorithm());
                try {
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
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_xmlenc_EncryptedKey);

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

                return;
            }
        }
        outputProcessorChain.processHeaderEvent(xmlEvent);
    }

    class InternalEncryptionOutputProcessor extends AbstractOutputProcessor {

        XMLEventNSAllocator xmlEventNSAllocator;
        private EncryptionPartDef encryptionPartDef;
        private Cipher symmetricCipher;
        private CharacterEventGeneratorOutputStream characterEventGeneratorOutputStream;
        private BufferedOutputStream base64EncoderStream;

        private QName startElement;
        private int elementCounter = 0;

        InternalEncryptionOutputProcessor(SecurityProperties securityProperties, EncryptionPartDef encryptionPartDef,  QName startElement, XMLEventNSAllocator xmlEventNSAllocator) throws XMLSecurityException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException {
            super(securityProperties);
            this.xmlEventNSAllocator = xmlEventNSAllocator;
            this.encryptionPartDef = encryptionPartDef;
            this.startElement = startElement;

            characterEventGeneratorOutputStream = new CharacterEventGeneratorOutputStream(xmlEventNSAllocator);
            base64EncoderStream = new BufferedOutputStream(new BASE64EncoderStream(characterEventGeneratorOutputStream));

            String jceAlgorithm = JCEAlgorithmMapper.translateURItoJCEID(securityProperties.getEncryptionSymAlgorithm());
		    symmetricCipher = Cipher.getInstance(jceAlgorithm);

            // Should internally generate an IV
	    // todo - allow user to set an IV
	        symmetricCipher.init(Cipher.ENCRYPT_MODE, encryptionPartDef.getSymmetricKey());
            byte[] iv = symmetricCipher.getIV();

            base64EncoderStream.write(iv);
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
                //System.out.println("Instance: " + this.hashCode() + " Incr " + elementCounter);
            }
            else if (xmlEvent.isEndElement()) {
                elementCounter--;
                //System.out.println("Instance: " + this.hashCode() + " Decr " + elementCounter);

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

                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                Iterator<Characters> charactersIterator =  characterEventGeneratorOutputStream.getCharactersBuffer().iterator();
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
            StringWriter stringWriter = new StringWriter();
            xmlEvent.writeAsEncodedUnicode(stringWriter);

            try {
                base64EncoderStream.write(symmetricCipher.update(stringWriter.toString().getBytes()));
            } catch (IOException e) {
                throw new XMLStreamException(e);
            }
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
            attributes.put(Constants.ATT_NULL_URI, encryptionPartDef.getKeyId());
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
                base64EncoderStream.write(symmetricCipher.doFinal());
                base64EncoderStream.close();
            } catch (IOException e) {
                throw new XMLStreamException(e);
            } catch (BadPaddingException e) {
                throw new XMLSecurityException(e.getMessage(), e);
            } catch (IllegalBlockSizeException e) {
                throw new XMLSecurityException(e.getMessage(), e);
            }
            Iterator<Characters> charactersIterator =  characterEventGeneratorOutputStream.getCharactersBuffer().iterator();
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
           charactersBuffer.add(xmlEventNSAllocator.createCharacters(new String(new byte[]{((byte)b)})).asCharacters());
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
