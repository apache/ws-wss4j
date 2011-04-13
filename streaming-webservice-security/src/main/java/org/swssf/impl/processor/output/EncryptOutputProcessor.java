/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.processor.output;

import org.apache.commons.codec.binary.Base64OutputStream;
import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.ext.*;
import org.swssf.impl.EncryptionPartDef;
import org.swssf.impl.util.TrimmerOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventFactory;
import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Processor to encrypt XML structures
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class EncryptOutputProcessor extends AbstractOutputProcessor {

    private List<SecurePart> secureParts;
    private Key symmetricKey;
    private String symmetricKeyId = "EncKeyId-" + UUID.randomUUID().toString();
    private List<EncryptionPartDef> encryptionPartDefList = new LinkedList<EncryptionPartDef>();

    private InternalEncryptionOutputProcessor activeInternalEncryptionOutputProcessor = null;

    public EncryptOutputProcessor(SecurityProperties securityProperties) throws WSSecurityException {
        super(securityProperties);
        secureParts = securityProperties.getEncryptionSecureParts();

        //prepare the symmetric session key for all encryption parts
        String keyAlgorithm = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(securityProperties.getEncryptionSymAlgorithm());
        int keyLength = JCEAlgorithmMapper.getKeyLengthFromURI(securityProperties.getEncryptionSymAlgorithm());
        KeyGenerator keyGen = null;
        try {
            keyGen = KeyGenerator.getInstance(keyAlgorithm);
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
        }
        keyGen.init(keyLength);

        symmetricKey = keyGen.generateKey();
    }

    public Key getSymmetricKey() {
        return symmetricKey;
    }

    public String getSymmetricKeyId() {
        return symmetricKeyId;
    }

    public List<EncryptionPartDef> getEncryptionPartDefList() {
        return encryptionPartDefList;
    }

    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            //avoid double encryption when child elements matches too
            if (activeInternalEncryptionOutputProcessor == null) {
                //find an element which matches a user configured securePart
                Iterator<SecurePart> securePartIterator = secureParts.iterator();
                while (securePartIterator.hasNext()) {
                    SecurePart securePart = securePartIterator.next();
                    if (securePart.getId() == null) {
                        if (startElement.getName().getLocalPart().equals(securePart.getName())
                                && startElement.getName().getNamespaceURI().equals(securePart.getNamespace())) {

                            logger.debug("Matched securePart for encryption");
                            InternalEncryptionOutputProcessor internalEncryptionOutputProcessor = null;
                            try {
                                EncryptionPartDef encryptionPartDef = new EncryptionPartDef();
                                encryptionPartDef.setModifier(securePart.getModifier());
                                encryptionPartDef.setEncRefId("EncDataId-" + UUID.randomUUID().toString());//"EncDataId-1612925417"
                                encryptionPartDef.setKeyId(symmetricKeyId);//EncKeyId-1483925398
                                encryptionPartDef.setSymmetricKey(symmetricKey);
                                encryptionPartDefList.add(encryptionPartDef);
                                internalEncryptionOutputProcessor =
                                        new InternalEncryptionOutputProcessor(
                                                getSecurityProperties(),
                                                encryptionPartDef,
                                                startElement,
                                                outputProcessorChain.getDocumentContext().getEncoding()
                                        );
                            } catch (NoSuchAlgorithmException e) {
                                throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
                            } catch (NoSuchPaddingException e) {
                                throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
                            } catch (InvalidKeyException e) {
                                throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
                            } catch (IOException e) {
                                throw new WSSecurityException(WSSecurityException.FAILED_ENCRYPTION, null, e);
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
    }

    /**
     * Processor which handles the effective enryption of the data
     */
    class InternalEncryptionOutputProcessor extends AbstractOutputProcessor {

        private EncryptionPartDef encryptionPartDef;
        private CharacterEventGeneratorOutputStream characterEventGeneratorOutputStream;
        //private Writer streamWriter;
        private XMLEventWriter xmlEventWriter;
        private OutputStream cipherOutputStream;

        private StartElement startElement;
        private int elementCounter = 0;
        private boolean doEncryptedHeader = false;
        private OutputProcessorChain subOutputProcessorChain;

        InternalEncryptionOutputProcessor(SecurityProperties securityProperties, EncryptionPartDef encryptionPartDef,
                                          StartElement startElement, String encoding)
                throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, XMLStreamException {

            super(securityProperties);
            this.getBeforeProcessors().add(EncryptEndingOutputProcessor.class.getName());
            this.getBeforeProcessors().add(InternalEncryptionOutputProcessor.class.getName());
            this.getAfterProcessors().add(EncryptOutputProcessor.class.getName());
            this.encryptionPartDef = encryptionPartDef;
            this.startElement = startElement;

            //initialize the cipher
            String jceAlgorithm = JCEAlgorithmMapper.translateURItoJCEID(securityProperties.getEncryptionSymAlgorithm());
            Cipher symmetricCipher = Cipher.getInstance(jceAlgorithm);

            //Should internally generate an IV
            symmetricCipher.init(Cipher.ENCRYPT_MODE, encryptionPartDef.getSymmetricKey());
            byte[] iv = symmetricCipher.getIV();

            characterEventGeneratorOutputStream = new CharacterEventGeneratorOutputStream(encoding);
            //Base64EncoderStream calls write every 78byte (line breaks). So we have to buffer again to get optimal performance
            Base64OutputStream base64EncoderStream = new Base64OutputStream(new BufferedOutputStream(characterEventGeneratorOutputStream), true, 76, new byte[]{'\n'});
            base64EncoderStream.write(iv);

            //the trimmer output stream is needed to strip away the dummy wrapping element which must be added 
            cipherOutputStream = new TrimmerOutputStream(new CipherOutputStream(base64EncoderStream, symmetricCipher), 8192, 3, 4);

            //we create a new StAX writer for optimized namespace writing.
            XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newInstance();
            xmlOutputFactory.setProperty(XMLOutputFactory.IS_REPAIRING_NAMESPACES, true);
            //spec says (4.2): "The cleartext octet sequence obtained in step 3 is interpreted as UTF-8 encoded character data."
            xmlEventWriter = xmlOutputFactory.createXMLEventWriter(cipherOutputStream, "UTF-8");
            //we have to output a fake element to workaround text-only encryption:
            xmlEventWriter.add(XMLEventFactory.newFactory().createStartElement(new QName("a"), null, null));
        }

        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {

            if (xmlEvent.isStartElement()) {

                StartElement startElement = xmlEvent.asStartElement();

                if (startElement.getName().equals(this.startElement.getName()) && elementCounter == 0) {
                    //if the user selected element encryption we have to encrypt the current element-event...
                    if (encryptionPartDef.getModifier() == SecurePart.Modifier.Element) {
                        subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                        processEventInternal(subOutputProcessorChain);
                        //encrypt the current element event
                        encryptEvent(xmlEvent);

                    } //...the user selected content encryption, so we let pass this event as usual  
                    else if (encryptionPartDef.getModifier() == SecurePart.Modifier.Content) {
                        outputProcessorChain.processEvent(xmlEvent);
                        subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                        processEventInternal(subOutputProcessorChain);
                    }
                } else {
                    encryptEvent(xmlEvent);
                }

                elementCounter++;

            } else if (xmlEvent.isEndElement()) {
                elementCounter--;

                EndElement endElement = xmlEvent.asEndElement();

                if (endElement.getName().equals(this.startElement.getName()) && elementCounter == 0) {
                    if (encryptionPartDef.getModifier() == SecurePart.Modifier.Element) {
                        encryptEvent(xmlEvent);
                        doFinalInternal(subOutputProcessorChain);
                    } else {
                        doFinalInternal(subOutputProcessorChain);
                        outputAsEvent(subOutputProcessorChain, xmlEvent);
                    }
                    subOutputProcessorChain.removeProcessor(this);
                    subOutputProcessorChain = null;
                    //from now on encryption is possible again
                    activeInternalEncryptionOutputProcessor = null;

                } else {
                    encryptEvent(xmlEvent);
                }
            } else {
                //not an interesting start nor an interesting end element
                //so encrypt this
                encryptEvent(xmlEvent);

                //push all buffered encrypted character events through the chain
                Iterator<Characters> charactersIterator = characterEventGeneratorOutputStream.getCharactersBuffer().iterator();
                while (charactersIterator.hasNext()) {
                    Characters characters = charactersIterator.next();
                    outputAsEvent(subOutputProcessorChain, characters);
                    charactersIterator.remove();
                }
            }
        }

        private void encryptEvent(XMLEvent xmlEvent) throws XMLStreamException {
            xmlEventWriter.add(xmlEvent);
        }

        /**
         * Creates the Data structure around the cipher data
         */
        private void processEventInternal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {
            Map<QName, String> attributes = null;

            //WSS 1.1 EncryptedHeader Element:
            if (outputProcessorChain.getDocumentContext().getDocumentLevel() == 3
                    && outputProcessorChain.getDocumentContext().isInSOAPHeader()) {
                doEncryptedHeader = true;

                attributes = new HashMap<QName, String>();

                Iterator<Attribute> attributeIterator = this.startElement.getAttributes();
                while (attributeIterator.hasNext()) {
                    Attribute attribute = attributeIterator.next();
                    if (!attribute.isNamespace() &&
                            (Constants.NS_SOAP11.equals(attribute.getName().getNamespaceURI()) ||
                                    Constants.NS_SOAP12.equals(attribute.getName().getNamespaceURI()))) {
                        attributes.put(attribute.getName(), attribute.getValue());
                    }
                }
                createStartElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse11_EncryptedHeader, attributes);
            }

            attributes = new HashMap<QName, String>();
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
        }

        private void doFinalInternal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, WSSecurityException {

            try {
                //close the event writer to flush all outstanding events to the encrypt stream
                xmlEventWriter.close();
                //call close to force a cipher.doFinal()
                cipherOutputStream.close();
            } catch (IOException e) {
                throw new XMLStreamException(e);
            }

            //push all buffered encrypted character events through the chain
            Iterator<Characters> charactersIterator = characterEventGeneratorOutputStream.getCharactersBuffer().iterator();
            while (charactersIterator.hasNext()) {
                Characters characters = charactersIterator.next();
                outputAsEvent(outputProcessorChain, characters);
                charactersIterator.remove();
            }

            createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_CipherValue);
            createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_CipherData);
            createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_xenc_EncryptedData);

            if (doEncryptedHeader) {
                createEndElementAndOutputAsEvent(outputProcessorChain, Constants.TAG_wsse11_EncryptedHeader);
            }
        }
    }

    /**
     * Creates Character-XMLEvents from the byte stream
     */
    class CharacterEventGeneratorOutputStream extends OutputStream {

        private List<Characters> charactersBuffer = new Vector<Characters>();
        private String encoding;

        CharacterEventGeneratorOutputStream(String encoding) {
            this.encoding = encoding;
        }

        public List<Characters> getCharactersBuffer() {
            return charactersBuffer;
        }

        @Override
        public void write(int b) throws IOException {
            charactersBuffer.add(createCharacters(new String(new byte[]{((byte) b)}, encoding)).asCharacters());
        }

        @Override
        public void write(byte[] b) throws IOException {
            charactersBuffer.add(createCharacters(new String(b, encoding)).asCharacters());
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            charactersBuffer.add(createCharacters(new String(b, off, len, encoding)).asCharacters());
        }
    }
}
