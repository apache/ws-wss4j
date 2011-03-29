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
package org.swssf.impl.processor.input;

import org.apache.commons.codec.binary.Base64OutputStream;
import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.ext.*;
import org.swssf.impl.EncryptionPartDef;
import org.swssf.impl.SecurityTokenFactory;
import org.swssf.impl.util.IVSplittingOutputStream;
import org.swssf.impl.util.ReplaceableOuputStream;
import org.swssf.securityEvent.*;
import org.w3._2001._04.xmlenc_.EncryptedDataType;
import org.w3._2001._04.xmlenc_.ReferenceList;
import org.w3._2001._04.xmlenc_.ReferenceType;
import org.xmlsecurity.ns.configuration.AlgorithmType;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.*;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.*;

/**
 * Processor for decryption of EncryptedData XML structures
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class DecryptInputProcessor extends AbstractInputProcessor {

    private ReferenceList referenceList;

    //the prefix must start with a letter by spec!:
    private final String uuid = "a" + UUID.randomUUID().toString().replaceAll("-", "");
    private final QName wrapperElementName = new QName("http://dummy", "dummy", uuid);

    private ArrayDeque<XMLEvent> tmpXmlEventList = new ArrayDeque<XMLEvent>();

    public DecryptInputProcessor(ReferenceList referenceList, SecurityProperties securityProperties) {
        super(securityProperties);
        this.referenceList = referenceList;
    }

    /*
    <xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="EncDataId-1612925417" Type="http://www.w3.org/2001/04/xmlenc#Content">
        <xenc:EncryptionMethod xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc" />
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                <wsse:Reference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" URI="#EncKeyId-1483925398" />
            </wsse:SecurityTokenReference>
        </ds:KeyInfo>
        <xenc:CipherData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
            <xenc:CipherValue xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
            ...
            </xenc:CipherValue>
        </xenc:CipherData>
    </xenc:EncryptedData>
     */

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        return processEvent(inputProcessorChain, true);
        //return xmlEvent;
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        return processEvent(inputProcessorChain, false);
    }

    private XMLEvent processEvent(InputProcessorChain inputProcessorChain, boolean isSecurityHeaderEvent) throws XMLStreamException, WSSecurityException {

        if (!tmpXmlEventList.isEmpty()) {
            XMLEvent xmlEvent = tmpXmlEventList.pollLast();
            if (xmlEvent.isStartElement()) {
                inputProcessorChain.getDocumentContext().addPathElement(xmlEvent.asStartElement().getName());
            } else if (xmlEvent.isEndElement()) {
                inputProcessorChain.getDocumentContext().removePathElement();
            }
            return xmlEvent;
        }

        XMLEvent xmlEvent = isSecurityHeaderEvent ? inputProcessorChain.processHeaderEvent() : inputProcessorChain.processEvent();

        boolean encryptedHeader = false;

        //todo overall null checks

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            //buffer the events until the EncryptedData Element appears and discard it if we found the reference inside it
            //otherwise replay it
            if (startElement.getName().equals(Constants.TAG_wsse11_EncryptedHeader)) {

                InputProcessorChain subInputProcessorChain = inputProcessorChain.createSubChain(this);
                do {
                    tmpXmlEventList.push(xmlEvent);

                    subInputProcessorChain.reset();
                    if (isSecurityHeaderEvent) {
                        xmlEvent = subInputProcessorChain.processHeaderEvent();
                    } else {
                        xmlEvent = subInputProcessorChain.processEvent();
                    }
                    //subInputProcessorChain.getDocumentContext().removePathElement();
                }
                while (!(xmlEvent.isStartElement() && xmlEvent.asStartElement().getName().equals(Constants.TAG_xenc_EncryptedData)));

                tmpXmlEventList.push(xmlEvent);
                //inputProcessorChain.getDocumentContext().removePathElement();
                startElement = xmlEvent.asStartElement();

                encryptedHeader = true;
            }

            //check if the current start-element has the name EncryptedData and an Id attribute
            if (startElement.getName().equals(Constants.TAG_xenc_EncryptedData)) {
                Attribute refId = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (refId != null) {
                    //exists the id in the referenceList? 
                    List<ReferenceType> references = referenceList.getDataReferenceOrKeyReference();
                    Iterator<ReferenceType> referenceTypeIterator = references.iterator();
                    while (referenceTypeIterator.hasNext()) {
                        ReferenceType referenceType = referenceTypeIterator.next();
                        if (refId.getValue().equals(referenceType.getURI())) {
                            logger.debug("Found encryption reference: " + refId.getValue() + " on element" + startElement.getName());
                            //duplicate id's are forbidden
                            if (referenceType.isProcessed()) {
                                throw new WSSecurityException("duplicate id encountered!");
                            }

                            if (encryptedHeader) {
                                tmpXmlEventList.clear();
                                inputProcessorChain.getDocumentContext().removePathElement();
                            }

                            EncryptedDataType currentEncryptedDataType = new EncryptedDataType(startElement);

                            referenceType.setProcessed(true);
                            inputProcessorChain.getDocumentContext().setIsInEncryptedContent();

                            //only fire here ContentEncryptedElementEvents
                            //the other ones will be fired later, because we don't know the encrypted element name yet
                            if (EncryptionPartDef.Modifier.Content.getModifier().equals(currentEncryptedDataType.getType())) {
                                QName parentElement = inputProcessorChain.getDocumentContext().getParentElement(xmlEvent.getEventType());
                                if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3
                                        && inputProcessorChain.getDocumentContext().isInSOAPBody()) {
                                    //soap:body content encryption counts as EncryptedPart
                                    EncryptedPartSecurityEvent encryptedPartSecurityEvent =
                                            new EncryptedPartSecurityEvent(SecurityEvent.Event.EncryptedPart, false);
                                    encryptedPartSecurityEvent.setElement(parentElement);
                                    inputProcessorChain.getSecurityContext().registerSecurityEvent(encryptedPartSecurityEvent);
                                } else {
                                    ContentEncryptedElementSecurityEvent contentEncryptedElementSecurityEvent =
                                            new ContentEncryptedElementSecurityEvent(SecurityEvent.Event.ContentEncrypted, false);
                                    contentEncryptedElementSecurityEvent.setElement(parentElement);
                                    inputProcessorChain.getSecurityContext().registerSecurityEvent(contentEncryptedElementSecurityEvent);
                                }
                            }

                            //the following logic reads the encryptedData structure and doesn't pass them further
                            //through the chain
                            InputProcessorChain subInputProcessorChain = inputProcessorChain.createSubChain(this);

                            XMLEvent encryptedDataXMLEvent;
                            do {
                                subInputProcessorChain.reset();
                                if (isSecurityHeaderEvent) {
                                    encryptedDataXMLEvent = subInputProcessorChain.processHeaderEvent();
                                } else {
                                    encryptedDataXMLEvent = subInputProcessorChain.processEvent();
                                }

                                //todo this self made parsing is ugly as hell. An idea would be to use JAXB with a custom WS-Security schema.
                                //todo the schema would have only the declared the elements which we are supporting.
                                try {
                                    currentEncryptedDataType.parseXMLEvent(encryptedDataXMLEvent);
                                } catch (ParseException e) {
                                    throw new WSSecurityException(e);
                                }
                            }
                            while (!(encryptedDataXMLEvent.isStartElement() && encryptedDataXMLEvent.asStartElement().getName().equals(Constants.TAG_xenc_CipherValue)));

                            try {
                                currentEncryptedDataType.validate();
                            } catch (ParseException e) {
                                throw new WSSecurityException(e);
                            }

                            //create a new Thread for streaming decryption
                            DecryptionThread decryptionThread = new DecryptionThread(subInputProcessorChain, isSecurityHeaderEvent,
                                    currentEncryptedDataType, (XMLEventNS) xmlEvent);

                            Thread receiverThread = new Thread(decryptionThread);
                            receiverThread.setName("decrypting thread");

                            DecryptedEventReaderInputProcessor decryptedEventReaderInputProcessor = new DecryptedEventReaderInputProcessor(getSecurityProperties(),
                                    EncryptionPartDef.Modifier.getModifier(currentEncryptedDataType.getType()), encryptedHeader);

                            //when an exception in the decryption thread occurs, we want to forward them:
                            receiverThread.setUncaughtExceptionHandler(decryptedEventReaderInputProcessor);

                            //we have to start the thread before we call decryptionThread.getDecryptedStreamInputProcessor().
                            //Otherwise we will end in a deadlock, because the StAX reader expects already data.
                            //@See some lines below: 
                            receiverThread.start();

                            inputProcessorChain.getDocumentContext().removePathElement();

                            //spec says (4.2): "The cleartext octet sequence obtained in step 3 is interpreted as UTF-8 encoded character data."
                            XMLEventReader xmlEventReader =
                                    inputProcessorChain.getSecurityContext().<XMLInputFactory>get(
                                            Constants.XMLINPUTFACTORY).createXMLEventReader(decryptionThread.getPipedInputStream(),
                                            "UTF-8");

                            //forward to wrapper element
                            XMLEvent tmpXmlEvent;
                            do {
                                tmpXmlEvent = xmlEventReader.nextEvent();
                            }
                            while (!(tmpXmlEvent.isStartElement() && tmpXmlEvent.asStartElement().getName().equals(wrapperElementName)));

                            decryptedEventReaderInputProcessor.setXmlEventReader(xmlEventReader);

                            //add the new created EventReader processor to the chain.
                            inputProcessorChain.addProcessor(decryptedEventReaderInputProcessor);
                            if (isSecurityHeaderEvent) {
                                return decryptedEventReaderInputProcessor.processNextHeaderEvent(inputProcessorChain);
                            } else {
                                return decryptedEventReaderInputProcessor.processNextEvent(inputProcessorChain);
                            }
                        }
                    }
                }
            }
        }

        if (!tmpXmlEventList.isEmpty()) {
            xmlEvent = tmpXmlEventList.pollLast();
            if (xmlEvent.isStartElement()) {
                inputProcessorChain.getDocumentContext().addPathElement(xmlEvent.asStartElement().getName());
            } else if (xmlEvent.isEndElement()) {
                inputProcessorChain.getDocumentContext().removePathElement();
            }
            return xmlEvent;
        }

        return xmlEvent;
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
        //here we check if all references where processed.
        List<ReferenceType> references = referenceList.getDataReferenceOrKeyReference();
        Iterator<ReferenceType> referenceTypeIterator = references.iterator();
        while (referenceTypeIterator.hasNext()) {
            ReferenceType referenceType = referenceTypeIterator.next();
            if (!referenceType.isProcessed()) {
                throw new WSSecurityException("Some encryption references where not processed... Probably security header ordering problem?");
            }
        }
        inputProcessorChain.doFinal();
    }

    /**
     * The DecryptedEventReaderInputProcessor reads the decrypted stream with a StAX reader and
     * forwards the generated XMLEvents
     */
    class DecryptedEventReaderInputProcessor extends AbstractInputProcessor implements Thread.UncaughtExceptionHandler {

        private XMLEventReader xmlEventReader;
        private EncryptionPartDef.Modifier encryptionModifier;
        private boolean encryptedHeader = false;
        private int documentLevel = 0;

        private boolean rootElementProcessed;

        DecryptedEventReaderInputProcessor(SecurityProperties securityProperties, EncryptionPartDef.Modifier encryptionModifier, boolean encryptedHeader) {
            super(securityProperties);
            getAfterProcessors().add(DecryptInputProcessor.class.getName());
            getAfterProcessors().add(DecryptedEventReaderInputProcessor.class.getName());
            this.encryptionModifier = encryptionModifier;
            rootElementProcessed = encryptionModifier != EncryptionPartDef.Modifier.Element;
            this.encryptedHeader = encryptedHeader;
        }

        public void setXmlEventReader(XMLEventReader xmlEventReader) {
            this.xmlEventReader = xmlEventReader;
        }

        @Override
        public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
            return processEvent(inputProcessorChain, true);
        }

        @Override
        public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
            return processEvent(inputProcessorChain, false);
        }

        private XMLEvent processEvent(InputProcessorChain inputProcessorChain, boolean headerEvent) throws XMLStreamException, WSSecurityException {
            //did a execption occur during decryption in the decryption thread?
            testAndThrowUncaughtException();
            //here we request the next XMLEvent from the decryption thread
            //instead from the processor-chain as we normally would do
            XMLEvent xmlEvent = xmlEventReader.nextEvent();

            //wrapper element skipping logic
            if (xmlEvent.isStartElement()) {
                documentLevel++;

                inputProcessorChain.getDocumentContext().addPathElement(xmlEvent.asStartElement().getName());

                if (!rootElementProcessed) {
                    //fire a SecurityEvent:
                    if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3
                            && inputProcessorChain.getDocumentContext().isInSOAPHeader()) {
                        EncryptedPartSecurityEvent encryptedPartSecurityEvent =
                                new EncryptedPartSecurityEvent(SecurityEvent.Event.EncryptedPart, false);
                        encryptedPartSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                        inputProcessorChain.getSecurityContext().registerSecurityEvent(encryptedPartSecurityEvent);
                    } else {
                        EncryptedElementSecurityEvent encryptedElementSecurityEvent =
                                new EncryptedElementSecurityEvent(SecurityEvent.Event.EncryptedElement, false);
                        encryptedElementSecurityEvent.setElement(xmlEvent.asStartElement().getName());
                        inputProcessorChain.getSecurityContext().registerSecurityEvent(encryptedElementSecurityEvent);
                    }

                    rootElementProcessed = true;
                }

            } else if (xmlEvent.isEndElement()) {

                if (xmlEvent.isEndElement() && xmlEvent.asEndElement().getName().equals(wrapperElementName)) {
                    //correct path and skip EndElements:
                    InputProcessorChain subInputProcessorChain = inputProcessorChain.createSubChain(this);

                    //skip EncryptedHeader Element when we processed it.
                    QName endElement;
                    if (encryptedHeader) {
                        subInputProcessorChain.getDocumentContext().addPathElement(Constants.TAG_wsse11_EncryptedHeader);
                        endElement = Constants.TAG_wsse11_EncryptedHeader;
                    } else {
                        endElement = Constants.TAG_xenc_EncryptedData;
                    }
                    subInputProcessorChain.getDocumentContext().addPathElement(Constants.TAG_xenc_EncryptedData);
                    subInputProcessorChain.getDocumentContext().addPathElement(Constants.TAG_xenc_CipherData);

                    //read and discard XMLEvents until the EncryptedData structure
                    XMLEvent endEvent;
                    do {
                        subInputProcessorChain.reset();
                        if (headerEvent) {
                            endEvent = subInputProcessorChain.processHeaderEvent();
                        } else {
                            endEvent = subInputProcessorChain.processEvent();
                        }
                    }
                    while (!(endEvent.isEndElement() && endEvent.asEndElement().getName().equals(endElement)));

                    inputProcessorChain.removeProcessor(this);
                    inputProcessorChain.getDocumentContext().unsetIsInEncryptedContent();

                    //...fetch the next (unencrypted) event
                    if (headerEvent) {
                        xmlEvent = inputProcessorChain.processHeaderEvent();
                    } else {
                        xmlEvent = inputProcessorChain.processEvent();
                    }
                }

                if (documentLevel > 0) {
                    inputProcessorChain.getDocumentContext().removePathElement();
                }

                documentLevel--;
            }

            return xmlEvent;
        }

        private Throwable thrownException;

        public void uncaughtException(Thread t, Throwable e) {
            this.thrownException = e;
        }

        public void testAndThrowUncaughtException() throws XMLStreamException {
            if (this.thrownException != null) {
                if (this.thrownException instanceof UncheckedWSSecurityException) {
                    UncheckedWSSecurityException uxse = (UncheckedWSSecurityException) this.thrownException;
                    throw new XMLStreamException(uxse.getCause());
                } else {
                    throw new XMLStreamException(this.thrownException.getCause());
                }
            }
        }
    }

    /**
     * The DecryptionThread handles encrypted XML-Parts
     */
    class DecryptionThread implements Runnable {

        private InputProcessorChain inputProcessorChain;
        private boolean header;
        private EncryptedDataType encryptedDataType;
        private XMLEventNS startXMLElement;
        private PipedOutputStream pipedOutputStream;
        private PipedInputStream pipedInputStream;
        private Cipher symmetricCipher;
        private Key secretKey;

        public DecryptionThread(InputProcessorChain inputProcessorChain, boolean header,
                                EncryptedDataType encryptedDataType, XMLEventNS startXMLElement) throws XMLStreamException, WSSecurityException {

            this.inputProcessorChain = inputProcessorChain;
            this.header = header;
            this.encryptedDataType = encryptedDataType;
            this.startXMLElement = startXMLElement;

            final String algorithmURI = encryptedDataType.getEncryptionMethod().getAlgorithm();

            //retrieve the securityToken which must be used for decryption
            SecurityToken securityToken = SecurityTokenFactory.newInstance().getSecurityToken(
                    encryptedDataType.getKeyInfo(), getSecurityProperties().getDecryptionCrypto(),
                    getSecurityProperties().getCallbackHandler(), inputProcessorChain.getSecurityContext());

            //fire a RecipientSecurityTokenEvent
            RecipientEncryptionTokenSecurityEvent recipientEncryptionTokenSecurityEvent =
                    new RecipientEncryptionTokenSecurityEvent(SecurityEvent.Event.RecipientEncryptionToken);
            recipientEncryptionTokenSecurityEvent.setSecurityToken(securityToken);
            inputProcessorChain.getSecurityContext().registerSecurityEvent(recipientEncryptionTokenSecurityEvent);

            if (securityToken.getKeyWrappingToken() != null) {
                AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent(SecurityEvent.Event.AlgorithmSuite);
                algorithmSuiteSecurityEvent.setAlgorithmURI(securityToken.getKeyWrappingTokenAlgorithm());
                algorithmSuiteSecurityEvent.setUsage(
                        securityToken.getKeyWrappingToken().isAsymmetric()
                                ? AlgorithmSuiteSecurityEvent.Usage.Asym_Key_Wrap
                                : AlgorithmSuiteSecurityEvent.Usage.Sym_Key_Wrap);
                inputProcessorChain.getSecurityContext().registerSecurityEvent(algorithmSuiteSecurityEvent);
            }

            secretKey = securityToken.getSecretKey(algorithmURI);

            try {
                AlgorithmType syncEncAlgo = JCEAlgorithmMapper.getAlgorithmMapping(algorithmURI);
                symmetricCipher = Cipher.getInstance(syncEncAlgo.getJCEName(), syncEncAlgo.getJCEProvider());
                //we have to defer the initialization of the cipher until we can extract the IV...
            } catch (NoSuchAlgorithmException e) {
                throw new WSSecurityException(e);
            } catch (NoSuchProviderException e) {
                throw new WSSecurityException(e);
            } catch (NoSuchPaddingException e) {
                throw new WSSecurityException(e);
            }

            //fire an AlgorithmSuiteSecurityEvent
            AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent(SecurityEvent.Event.AlgorithmSuite);
            algorithmSuiteSecurityEvent.setAlgorithmURI(algorithmURI);
            algorithmSuiteSecurityEvent.setUsage(AlgorithmSuiteSecurityEvent.Usage.Enc);
            inputProcessorChain.getSecurityContext().registerSecurityEvent(algorithmSuiteSecurityEvent);

            //prepare the piped streams and connect them:
            //5 * 8192 seems to be a fine value
            pipedInputStream = new PipedInputStream(40960);
            try {
                pipedOutputStream = new PipedOutputStream(pipedInputStream);
            } catch (IOException e) {
                throw new XMLStreamException(e);
            }
        }

        public PipedInputStream getPipedInputStream() {
            return pipedInputStream;
        }

        private XMLEvent processNextEvent() throws WSSecurityException, XMLStreamException {
            inputProcessorChain.reset();
            if (header) {
                return inputProcessorChain.processHeaderEvent();
            } else {
                return inputProcessorChain.processEvent();
            }
        }

        public void run() {

            try {
                //temporary writer to write the dummy wrapper element with all namespaces in the current scope
                //spec says (4.2): "The cleartext octet sequence obtained in step 3 is interpreted as UTF-8 encoded character data."
                BufferedWriter tempBufferedWriter = new BufferedWriter(
                        new OutputStreamWriter(
                                pipedOutputStream,
                                "UTF-8"
                        )
                );

                tempBufferedWriter.write('<');
                tempBufferedWriter.write(wrapperElementName.getPrefix());
                tempBufferedWriter.write(':');
                tempBufferedWriter.write(wrapperElementName.getLocalPart());
                tempBufferedWriter.write(' ');
                tempBufferedWriter.write("xmlns:");
                tempBufferedWriter.write(wrapperElementName.getPrefix());
                tempBufferedWriter.write("=\"");
                tempBufferedWriter.write(wrapperElementName.getNamespaceURI());
                tempBufferedWriter.write('\"');

                //apply all namespaces from current scope to get a valid documentfragment:
                List<ComparableNamespace> comparableNamespacesToApply = new LinkedList<ComparableNamespace>();
                List<ComparableNamespace>[] comparableNamespaceList = startXMLElement.getNamespaceList();
                for (int i = 0; i < comparableNamespaceList.length; i++) {
                    List<ComparableNamespace> comparableNamespaces = comparableNamespaceList[i];
                    Iterator<ComparableNamespace> comparableNamespaceIterator = comparableNamespaces.iterator();
                    while (comparableNamespaceIterator.hasNext()) {
                        ComparableNamespace comparableNamespace = comparableNamespaceIterator.next();
                        if (!comparableNamespacesToApply.contains(comparableNamespace)) {
                            comparableNamespacesToApply.add(comparableNamespace);
                        }
                    }
                }
                Iterator<ComparableNamespace> comparableNamespaceIterator = comparableNamespacesToApply.iterator();
                while (comparableNamespaceIterator.hasNext()) {
                    ComparableNamespace comparableNamespace = comparableNamespaceIterator.next();
                    tempBufferedWriter.write(' ');
                    tempBufferedWriter.write(comparableNamespace.toString());
                }

                tempBufferedWriter.write('>');
                //calling flush after every piece to prevent data salad...
                tempBufferedWriter.flush();

                IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(
                        new CipherOutputStream(new FilterOutputStream(pipedOutputStream) {

                            @Override
                            public void write(int b) throws IOException {
                                //System.out.println(new String(new byte[]{(byte)b}));
                                out.write(b);
                            }

                            @Override
                            public void write(byte[] b) throws IOException {
                                //System.out.println(new String(b));
                                out.write(b);
                            }

                            @Override
                            public void write(byte[] b, int off, int len) throws IOException {
                                //System.out.println(new String(b, off, len));
                                out.write(b, off, len);
                            }

                            @Override
                            public void close() throws IOException {
                                //we overwrite the close method and don't delegate close. Close must be done separately.
                                //The reason behind this is the Base64DecoderStream which does the final on close() but after
                                //that we have to write our dummy end tag
                                //just calling flush here, seems to be fine
                                out.flush();
                            }
                        }, symmetricCipher),
                        symmetricCipher, secretKey);
                //buffering seems not to help
                //bufferedOutputStream = new BufferedOutputStream(new Base64OutputStream(ivSplittingOutputStream, false), 8192 * 5);
                ReplaceableOuputStream replaceableOuputStream = new ReplaceableOuputStream(ivSplittingOutputStream);
                OutputStream decryptOutputStream = new Base64OutputStream(replaceableOuputStream, false);
                ivSplittingOutputStream.setParentOutputStream(replaceableOuputStream);

                //read the encrypted data from the stream until an end-element occurs and write then
                //to the decrypter-stream
                boolean finished = false;
                while (!finished) {
                    XMLEvent xmlEvent = processNextEvent();

                    switch (xmlEvent.getEventType()) {
                        case XMLStreamConstants.END_ELEMENT:
                            //this must be the CipherValue EndElement.
                            finished = true;
                            break;
                        case XMLStreamConstants.CHARACTERS:
                            decryptOutputStream.write(xmlEvent.asCharacters().getData().getBytes(inputProcessorChain.getDocumentContext().getEncoding()));
                            break;
                        default:
                            throw new WSSecurityException("Unexpected event: " + Utils.getXMLEventAsString(xmlEvent));
                    }
                }

                //close to get Cipher.doFinal() called
                decryptOutputStream.close();

                //close the dummy wrapper element:
                tempBufferedWriter.write("</");
                tempBufferedWriter.write(wrapperElementName.getPrefix());
                tempBufferedWriter.write(':');
                tempBufferedWriter.write(wrapperElementName.getLocalPart());
                tempBufferedWriter.write('>');
                //real close of the stream
                tempBufferedWriter.close();

            } catch (Exception e) {
                throw new UncheckedWSSecurityException(e);
            }
        }
    }
}
