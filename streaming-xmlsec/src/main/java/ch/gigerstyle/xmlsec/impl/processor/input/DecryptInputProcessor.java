package ch.gigerstyle.xmlsec.impl.processor.input;

import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.impl.EncryptionPartDef;
import ch.gigerstyle.xmlsec.impl.SecurityTokenFactory;
import ch.gigerstyle.xmlsec.impl.util.IVSplittingOutputStream;
import ch.gigerstyle.xmlsec.impl.util.ReplaceableOuputStream;
import ch.gigerstyle.xmlsec.securityEvent.*;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.w3._2001._04.xmlenc_.EncryptedDataType;
import org.w3._2001._04.xmlenc_.ReferenceList;
import org.w3._2001._04.xmlenc_.ReferenceType;

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
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

/**
 * User: giger
 * Date: May 13, 2010
 * Time: 7:24:49 PM
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
public class DecryptInputProcessor extends AbstractInputProcessor {

    private ReferenceList referenceList;
    private EncryptedDataType currentEncryptedDataType;

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
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        XMLEvent xmlEvent = inputProcessorChain.processHeaderEvent();
        return processEvent(xmlEvent, inputProcessorChain, true);
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        XMLEvent xmlEvent = inputProcessorChain.processEvent();
        return processEvent(xmlEvent, inputProcessorChain, false);
    }

    private XMLEvent processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, boolean isSecurityHeaderEvent) throws XMLStreamException, XMLSecurityException {

        //todo overall null checks

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            if (startElement.getName().equals(Constants.TAG_xenc_EncryptedData)) {
                Attribute refId = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (refId != null) {
                    List<ReferenceType> references = referenceList.getDataReferenceOrKeyReference();
                    Iterator<ReferenceType> referenceTypeIterator = references.iterator();
                    while (referenceTypeIterator.hasNext()) {
                        ReferenceType referenceType = referenceTypeIterator.next();
                        if (refId.getValue().equals(referenceType.getURI())) {
                            logger.debug("Found encryption reference: " + refId.getValue() + " on element" + startElement.getName());
                            if (referenceType.isProcessed()) {
                                throw new XMLSecurityException("duplicate id encountered!");
                            }
                            currentEncryptedDataType = new EncryptedDataType(startElement);

                            referenceType.setProcessed(true);
                            //todo move in decryptThread?
                            inputProcessorChain.getDocumentContext().setIsInEncryptedContent();

                            //only fire here ContentEncryptedElementEvents
                            //the other ones will be fired later, because we don't know the encrypted element name yet
                            if (EncryptionPartDef.Modifier.Content.getModifier().equals(currentEncryptedDataType.getType())) {
                                QName parentElement = inputProcessorChain.getDocumentContext().getParentElement(xmlEvent.getEventType());
                                if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 3
                                        && inputProcessorChain.getDocumentContext().isInSOAPBody()
                                        && Constants.TAG_soap11_Body.equals(parentElement)) {
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
                                    throw new XMLSecurityException(e);
                                }
                            }
                            while (!(encryptedDataXMLEvent.isStartElement() && encryptedDataXMLEvent.asStartElement().getName().equals(Constants.TAG_xenc_CipherValue)));

                            try {
                                currentEncryptedDataType.validate();
                            } catch (ParseException e) {
                                throw new XMLSecurityException(e);
                            }

                            DecryptionThread decryptionThread = new DecryptionThread(subInputProcessorChain, isSecurityHeaderEvent,
                                    currentEncryptedDataType, (XMLEventNS) xmlEvent);

                            Thread receiverThread = new Thread(decryptionThread);
                            receiverThread.setName("decrypting thread");
                            receiverThread.start();

                            inputProcessorChain.getDocumentContext().removePathElement();

                            DecryptedEventReaderInputProcessor decryptedEventReaderInputProcessor = decryptionThread.getDecryptedStreamInputProcessor();
                            receiverThread.setUncaughtExceptionHandler(decryptedEventReaderInputProcessor);
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
        } else if (xmlEvent.isEndElement() && currentEncryptedDataType != null) {
            currentEncryptedDataType = null;
        }
        return xmlEvent;
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        List<ReferenceType> references = referenceList.getDataReferenceOrKeyReference();
        Iterator<ReferenceType> referenceTypeIterator = references.iterator();
        while (referenceTypeIterator.hasNext()) {
            ReferenceType referenceType = referenceTypeIterator.next();
            if (!referenceType.isProcessed()) {
                throw new XMLSecurityException("Some encryption references where not processed... Probably security header ordering problem?");
            }
        }
        inputProcessorChain.doFinal();
    }

    class DecryptedEventReaderInputProcessor extends AbstractInputProcessor implements Thread.UncaughtExceptionHandler {

        private XMLEventReader xmlEventReader;
        private QName wrapperElementName;
        private EncryptionPartDef.Modifier encryptionModifier;
        private int documentLevel = 0;

        private boolean rootElementProcessed;

        DecryptedEventReaderInputProcessor(SecurityProperties securityProperties, XMLEventReader xmlEventReader,
                                           QName wrapperElementName, EncryptionPartDef.Modifier encryptionModifier) {
            super(securityProperties);
            getAfterProcessors().add(DecryptInputProcessor.class.getName());
            getAfterProcessors().add(DecryptedEventReaderInputProcessor.class.getName());
            this.xmlEventReader = xmlEventReader;
            this.wrapperElementName = wrapperElementName;
            this.encryptionModifier = encryptionModifier;
            rootElementProcessed = encryptionModifier != EncryptionPartDef.Modifier.Element;
        }

        @Override
        public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
            return processEvent(inputProcessorChain, true);
        }

        @Override
        public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
            return processEvent(inputProcessorChain, false);
        }

        private XMLEvent processEvent(InputProcessorChain inputProcessorChain, boolean headerEvent) throws XMLStreamException, XMLSecurityException {

            testAndThrowUncaughtException();
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
                    subInputProcessorChain.getDocumentContext().addPathElement(Constants.TAG_xenc_EncryptedData);
                    subInputProcessorChain.getDocumentContext().addPathElement(Constants.TAG_xenc_CipherData);

                    XMLEvent endEvent;
                    do {
                        subInputProcessorChain.reset();
                        if (headerEvent) {
                            endEvent = subInputProcessorChain.processHeaderEvent();
                        } else {
                            endEvent = subInputProcessorChain.processEvent();
                        }
                    }
                    while (!(endEvent.isEndElement() && endEvent.asEndElement().getName().equals(Constants.TAG_xenc_EncryptedData)));

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
                if (this.thrownException instanceof UncheckedXMLSecurityException) {
                    UncheckedXMLSecurityException uxse = (UncheckedXMLSecurityException) this.thrownException;
                    throw new XMLStreamException(uxse.getCause());
                } else {
                    throw new XMLStreamException(this.thrownException.getCause());
                }
            }
        }
    }

    class DecryptionThread implements Runnable {

        private InputProcessorChain inputProcessorChain;
        private boolean header;
        private EncryptedDataType encryptedDataType;
        private XMLEventNS startXMLElement;
        private PipedOutputStream pipedOutputStream;
        private PipedInputStream pipedInputStream;

        //todo static final init or better: hardcoded:
        //use a unique prefix; the prefix must start with a letter by spec!:
        private final String uuid = "a" + UUID.randomUUID().toString().replaceAll("-", "");
        private final QName wrapperElementName = new QName("http://dummy", "dummy", uuid);

        public DecryptionThread(InputProcessorChain inputProcessorChain, boolean header,
                                EncryptedDataType encryptedDataType, XMLEventNS startXMLElement) throws XMLStreamException {

            this.inputProcessorChain = inputProcessorChain;
            this.header = header;
            this.encryptedDataType = encryptedDataType;
            this.startXMLElement = startXMLElement;

            //5 * 8192 seems to be a fine value
            pipedInputStream = new PipedInputStream(40960);
            try {
                pipedOutputStream = new PipedOutputStream(pipedInputStream);
            } catch (IOException e) {
                throw new XMLStreamException(e);
            }
        }

        public DecryptedEventReaderInputProcessor getDecryptedStreamInputProcessor() throws XMLStreamException {

            //todo set encoding?:
            XMLEventReader xmlEventReader =
                    inputProcessorChain.getSecurityContext().<XMLInputFactory>get(
                            Constants.XMLINPUTFACTORY).createXMLEventReader(pipedInputStream,
                            inputProcessorChain.getDocumentContext().getEncoding());

            //go forward to wrapper element
            XMLEvent xmlEvent;
            do {
                xmlEvent = xmlEventReader.nextEvent();
            }
            while (!(xmlEvent.isStartElement() && xmlEvent.asStartElement().getName().equals(wrapperElementName)));

            return new DecryptedEventReaderInputProcessor(getSecurityProperties(), xmlEventReader, wrapperElementName,
                    EncryptionPartDef.Modifier.getModifier(encryptedDataType.getType()));
        }

        private XMLEvent processNextEvent() throws XMLSecurityException, XMLStreamException {
            inputProcessorChain.reset();
            if (header) {
                return inputProcessorChain.processHeaderEvent();
            } else {
                return inputProcessorChain.processEvent();
            }
        }

        public void run() {

            try {
                final String algorithmURI = encryptedDataType.getEncryptionMethod().getAlgorithm();

                SecurityToken securityToken = SecurityTokenFactory.newInstance().getSecurityToken(
                        encryptedDataType.getKeyInfo(), getSecurityProperties().getDecryptionCrypto(),
                        getSecurityProperties().getCallbackHandler(), inputProcessorChain.getSecurityContext());
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

                Key secretKey = securityToken.getSecretKey(algorithmURI);

                Cipher symmetricCipher;
                //we have to defer the initialization of the cipher until we can extract the IV...
                try {
                    String syncEncAlgo = JCEAlgorithmMapper.translateURItoJCEID(algorithmURI);
                    symmetricCipher = Cipher.getInstance(syncEncAlgo, "BC");
                } catch (NoSuchAlgorithmException e) {
                    throw new XMLSecurityException(e);
                } catch (NoSuchProviderException e) {
                    throw new XMLSecurityException(e);
                } catch (NoSuchPaddingException e) {
                    throw new XMLSecurityException(e);
                }

                AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent(SecurityEvent.Event.AlgorithmSuite);
                algorithmSuiteSecurityEvent.setAlgorithmURI(algorithmURI);
                algorithmSuiteSecurityEvent.setUsage(AlgorithmSuiteSecurityEvent.Usage.Enc);
                inputProcessorChain.getSecurityContext().registerSecurityEvent(algorithmSuiteSecurityEvent);

                //temporary writer for direct writing plaintext data
                BufferedWriter tempBufferedWriter = new BufferedWriter(
                        new OutputStreamWriter(
                                pipedOutputStream,
                                inputProcessorChain.getDocumentContext().getEncoding()
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
                                out.write(b);
                            }

                            @Override
                            public void write(byte[] b) throws IOException {
                                out.write(b);
                            }

                            @Override
                            public void write(byte[] b, int off, int len) throws IOException {
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
                            throw new XMLSecurityException("Unexpected event: " + Utils.getXMLEventAsString(xmlEvent));
                    }
                }

                //close to get Cipher.doFinal() called
                decryptOutputStream.close();

                tempBufferedWriter.write("</");
                tempBufferedWriter.write(wrapperElementName.getPrefix());
                tempBufferedWriter.write(':');
                tempBufferedWriter.write(wrapperElementName.getLocalPart());
                tempBufferedWriter.write('>');
                //real close of the stream
                tempBufferedWriter.close();

            } catch (Exception e) {
                throw new UncheckedXMLSecurityException(e);
            }
        }
    }
}
