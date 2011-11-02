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
package org.swssf.xmlsec.impl.processor.output;

import org.apache.commons.codec.binary.Base64OutputStream;
import org.swssf.xmlsec.config.JCEAlgorithmMapper;
import org.swssf.xmlsec.ext.*;
import org.swssf.xmlsec.impl.EncryptionPartDef;
import org.swssf.xmlsec.impl.util.TrimmerOutputStream;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
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
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Processor to encrypt XML structures
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractEncryptOutputProcessor extends AbstractOutputProcessor {

    private AbstractInternalEncryptionOutputProcessor activeInternalEncryptionOutputProcessor = null;

    public AbstractEncryptOutputProcessor(XMLSecurityProperties securityProperties, XMLSecurityConstants.Action action) throws XMLSecurityException {
        super(securityProperties, action);
    }

    @Override
    public abstract void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException;

    protected AbstractInternalEncryptionOutputProcessor getActiveInternalEncryptionOutputProcessor() {
        return activeInternalEncryptionOutputProcessor;
    }

    protected void setActiveInternalEncryptionOutputProcessor(AbstractInternalEncryptionOutputProcessor activeInternalEncryptionOutputProcessor) {
        this.activeInternalEncryptionOutputProcessor = activeInternalEncryptionOutputProcessor;
    }

    /**
     * Processor which handles the effective enryption of the data
     */
    public abstract class AbstractInternalEncryptionOutputProcessor extends AbstractOutputProcessor {

        private EncryptionPartDef encryptionPartDef;
        private CharacterEventGeneratorOutputStream characterEventGeneratorOutputStream;
        private XMLEventWriter xmlEventWriter;
        private OutputStream cipherOutputStream;

        private StartElement startElement;
        private int elementCounter = 0;
        private OutputProcessorChain subOutputProcessorChain;

        public AbstractInternalEncryptionOutputProcessor(XMLSecurityProperties securityProperties, XMLSecurityConstants.Action action, EncryptionPartDef encryptionPartDef,
                                                         StartElement startElement, String encoding)
                throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IOException, XMLStreamException {

            super(securityProperties, action);
            this.getBeforeProcessors().add(AbstractEncryptEndingOutputProcessor.class.getName());
            this.getBeforeProcessors().add(AbstractInternalEncryptionOutputProcessor.class.getName());
            this.getAfterProcessors().add(AbstractEncryptOutputProcessor.class.getName());
            this.setEncryptionPartDef(encryptionPartDef);
            this.setStartElement(startElement);

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
            xmlOutputFactory.setProperty(XMLOutputFactory.IS_REPAIRING_NAMESPACES, false);
            //spec says (4.2): "The cleartext octet sequence obtained in step 3 is interpreted as UTF-8 encoded character data."
            xmlEventWriter = xmlOutputFactory.createXMLEventWriter(cipherOutputStream, "UTF-8");
            //we have to output a fake element to workaround text-only encryption:
            xmlEventWriter.add(XMLEventFactory.newFactory().createStartElement(new QName("a"), null, null));
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

            if (xmlEvent.isStartElement()) {

                StartElement startElement = xmlEvent.asStartElement();

                if (startElement.getName().equals(this.getStartElement().getName()) && getElementCounter() == 0) {
                    //if the user selected element encryption we have to encrypt the current element-event...
                    if (getEncryptionPartDef().getModifier() == SecurePart.Modifier.Element) {
                        subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                        processEventInternal(subOutputProcessorChain);
                        //encrypt the current element event
                        encryptEvent(xmlEvent);

                    } //...the user selected content encryption, so we let pass this event as usual  
                    else if (getEncryptionPartDef().getModifier() == SecurePart.Modifier.Content) {
                        outputProcessorChain.processEvent(xmlEvent);
                        subOutputProcessorChain = outputProcessorChain.createSubChain(this);
                        processEventInternal(subOutputProcessorChain);
                    }
                } else {
                    encryptEvent(xmlEvent);
                }

                setElementCounter(getElementCounter() + 1);

            } else if (xmlEvent.isEndElement()) {
                setElementCounter(getElementCounter() - 1);

                EndElement endElement = xmlEvent.asEndElement();

                if (endElement.getName().equals(this.getStartElement().getName()) && getElementCounter() == 0) {
                    if (getEncryptionPartDef().getModifier() == SecurePart.Modifier.Element) {
                        encryptEvent(xmlEvent);
                        doFinalInternal(subOutputProcessorChain);
                    } else {
                        doFinalInternal(subOutputProcessorChain);
                        outputAsEvent(subOutputProcessorChain, xmlEvent);
                    }
                    subOutputProcessorChain.removeProcessor(this);
                    subOutputProcessorChain = null;
                    //from now on encryption is possible again
                    setActiveInternalEncryptionOutputProcessor(null);

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
        protected void processEventInternal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {
            Map<QName, String> attributes = null;

            attributes = new HashMap<QName, String>();
            attributes.put(XMLSecurityConstants.ATT_NULL_Id, getEncryptionPartDef().getEncRefId());
            attributes.put(XMLSecurityConstants.ATT_NULL_Type, getEncryptionPartDef().getModifier().getModifier());
            createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_EncryptedData, attributes);

            attributes = new HashMap<QName, String>();
            attributes.put(XMLSecurityConstants.ATT_NULL_Algorithm, securityProperties.getEncryptionSymAlgorithm());
            createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_EncryptionMethod, attributes);

            createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_EncryptionMethod);
            createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo, null);
            createKeyInfoStructure(outputProcessorChain);
            createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_dsig_KeyInfo);
            createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherData, null);
            createStartElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherValue, null);

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

        protected abstract void createKeyInfoStructure(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException;

        protected void doFinalInternal(OutputProcessorChain outputProcessorChain) throws XMLStreamException, XMLSecurityException {

            try {
                xmlEventWriter.add(XMLEventFactory.newFactory().createEndElement(new QName("a"), null));
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

            createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherValue);
            createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_CipherData);
            createEndElementAndOutputAsEvent(outputProcessorChain, XMLSecurityConstants.TAG_xenc_EncryptedData);
        }

        protected EncryptionPartDef getEncryptionPartDef() {
            return encryptionPartDef;
        }

        protected void setEncryptionPartDef(EncryptionPartDef encryptionPartDef) {
            this.encryptionPartDef = encryptionPartDef;
        }

        protected StartElement getStartElement() {
            return startElement;
        }

        protected void setStartElement(StartElement startElement) {
            this.startElement = startElement;
        }

        protected int getElementCounter() {
            return elementCounter;
        }

        protected void setElementCounter(int elementCounter) {
            this.elementCounter = elementCounter;
        }
    }

    /**
     * Creates Character-XMLEvents from the byte stream
     */
    public class CharacterEventGeneratorOutputStream extends OutputStream {

        private List<Characters> charactersBuffer = new Vector<Characters>();
        private String encoding;

        public CharacterEventGeneratorOutputStream(String encoding) {
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
