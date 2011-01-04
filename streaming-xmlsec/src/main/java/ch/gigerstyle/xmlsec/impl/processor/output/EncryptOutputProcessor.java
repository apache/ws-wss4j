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
package ch.gigerstyle.xmlsec.impl.processor.output;

import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.impl.EncryptionPartDef;
import ch.gigerstyle.xmlsec.impl.XMLEventNSAllocator;
import ch.gigerstyle.xmlsec.impl.util.TrimmerOutputStream;
import org.apache.commons.codec.binary.Base64OutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventFactory;
import javax.xml.stream.XMLEventWriter;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Characters;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/** Processor to encrypt XML structures
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class EncryptOutputProcessor extends AbstractOutputProcessor {

    private List<SecurePart> secureParts;
    private Key symmetricKey;
    private String symmetricKeyId = "EncKeyId-" + UUID.randomUUID().toString();
    private List<EncryptionPartDef> encryptionPartDefList = new LinkedList<EncryptionPartDef>();

    private InternalEncryptionOutputProcessor activeInternalEncryptionOutputProcessor = null;

    public EncryptOutputProcessor(SecurityProperties securityProperties) throws XMLSecurityException {
        super(securityProperties);
        secureParts = securityProperties.getEncryptionSecureParts();

        //prepare the symmetric session key for all encryption parts
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

    public Key getSymmetricKey() {
        return symmetricKey;
    }

    public String getSymmetricKeyId() {
        return symmetricKeyId;
    }

    public List<EncryptionPartDef> getEncryptionPartDefList() {
        return encryptionPartDefList;
    }

    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

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
                                encryptionPartDef.setModifier(EncryptionPartDef.Modifier.valueOf(securePart.getModifier()));
                                encryptionPartDef.setEncRefId("EncDataId-" + UUID.randomUUID().toString());//"EncDataId-1612925417"
                                encryptionPartDef.setKeyId(symmetricKeyId);//EncKeyId-1483925398
                                encryptionPartDef.setSymmetricKey(symmetricKey);
                                encryptionPartDefList.add(encryptionPartDef);
                                internalEncryptionOutputProcessor = new InternalEncryptionOutputProcessor(getSecurityProperties(), encryptionPartDef, startElement.getName(), outputProcessorChain.getSecurityContext().<XMLEventNSAllocator>get(Constants.XMLEVENT_NS_ALLOCATOR));
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
    }

    /**
     * Processor which handles the effective enryption of the data
     */
    class InternalEncryptionOutputProcessor extends AbstractOutputProcessor {

        XMLEventNSAllocator xmlEventNSAllocator;
        private EncryptionPartDef encryptionPartDef;
        private CharacterEventGeneratorOutputStream characterEventGeneratorOutputStream;
        //private Writer streamWriter;
        private XMLEventWriter xmlEventWriter;
        private OutputStream cipherOutputStream;

        private QName startElement;
        private int elementCounter = 0;

        InternalEncryptionOutputProcessor(SecurityProperties securityProperties, EncryptionPartDef encryptionPartDef,
                                          QName startElement, XMLEventNSAllocator xmlEventNSAllocator)
                throws XMLSecurityException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, XMLStreamException {

            super(securityProperties);
            this.getBeforeProcessors().add(EncryptEndingOutputProcessor.class.getName());
            this.getBeforeProcessors().add(InternalEncryptionOutputProcessor.class.getName());
            this.getAfterProcessors().add(EncryptOutputProcessor.class.getName());
            this.xmlEventNSAllocator = xmlEventNSAllocator;
            this.encryptionPartDef = encryptionPartDef;
            this.startElement = startElement;

            //initialize the cipher
            String jceAlgorithm = JCEAlgorithmMapper.translateURItoJCEID(securityProperties.getEncryptionSymAlgorithm());
            Cipher symmetricCipher = Cipher.getInstance(jceAlgorithm);

            // Should internally generate an IV
            // todo - allow user to set an IV
            symmetricCipher.init(Cipher.ENCRYPT_MODE, encryptionPartDef.getSymmetricKey());
            byte[] iv = symmetricCipher.getIV();

            characterEventGeneratorOutputStream = new CharacterEventGeneratorOutputStream(xmlEventNSAllocator);
            //Base64EncoderStream calls write every 78byte (line breaks). So we have to buffer again to get optimal performance
            //todo play around to find optimal size
            Base64OutputStream base64EncoderStream = new Base64OutputStream(new BufferedOutputStream(characterEventGeneratorOutputStream), true, 76, new byte[]{'\n'});
            base64EncoderStream.write(iv);

            //the trimmer output stream is needed to strip away the dummy wrapping element which must be added 
            cipherOutputStream = new TrimmerOutputStream(new CipherOutputStream(base64EncoderStream, symmetricCipher), 8192, 3, 4);

            //we create a new StAX writer for optimized namespace writing.
            XMLOutputFactory xmlOutputFactory = XMLOutputFactory.newInstance();
            xmlOutputFactory.setProperty(XMLOutputFactory.IS_REPAIRING_NAMESPACES, true);
            //todo encoding?
            xmlEventWriter = xmlOutputFactory.createXMLEventWriter(cipherOutputStream);
            //we have to output a fake element to workaround text-only encryption:
            xmlEventWriter.add(XMLEventFactory.newFactory().createStartElement(new QName("a"), null, null));
        }

        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

            if (xmlEvent.isStartElement()) {

                StartElement startElement = xmlEvent.asStartElement();

                if (startElement.getName().equals(this.startElement) && elementCounter == 0) {
                    //if the user selected element encryption we have to encrypt the current element-event...
                    if (encryptionPartDef.getModifier() == EncryptionPartDef.Modifier.Element) {
                        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                        processEventInternal(subOutputProcessorChain);
                        //encrypt the current element event
                        encryptEvent(xmlEvent);

                    } //...the user selected content encryption, so we let pass this event as usual  
                    else if (encryptionPartDef.getModifier() == EncryptionPartDef.Modifier.Content) {
                        OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                        outputAsEvent(subOutputProcessorChain, xmlEvent);
                        processEventInternal(subOutputProcessorChain);
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
                //not an interesting start nor an interesting end element
                //so encrypt this
                encryptEvent(xmlEvent);

                //push all buffered encrypted character events through the chain
                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);
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
        private void processEventInternal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            Map<QName, String> attributes = new HashMap<QName, String>();
            attributes.put(Constants.ATT_NULL_Id, encryptionPartDef.getEncRefId());
            attributes.put(Constants.ATT_NULL_Type, encryptionPartDef.getModifier().getModifier());
            //todo WSS 1.0 says that encrypted header elements should wrap this in an EncryptedHeader Element
            //todo and copies attributes like actor mustUnderstand etc to it!
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

        private void doFinalInternal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

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
        }
    }

    /**
     * Creates Character-XMLEvents from the byte stream
     */
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
