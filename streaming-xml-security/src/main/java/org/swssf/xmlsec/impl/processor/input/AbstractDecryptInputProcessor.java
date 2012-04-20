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
package org.swssf.xmlsec.impl.processor.input;

import org.apache.commons.codec.binary.Base64OutputStream;
import org.swssf.binding.xmldsig.KeyInfoType;
import org.swssf.binding.xmldsig.TransformType;
import org.swssf.binding.xmldsig.TransformsType;
import org.swssf.binding.xmlenc.EncryptedDataType;
import org.swssf.binding.xmlenc.ReferenceList;
import org.swssf.binding.xmlenc.ReferenceType;
import org.swssf.xmlsec.config.JCEAlgorithmMapper;
import org.swssf.xmlsec.config.TransformerAlgorithmMapper;
import org.swssf.xmlsec.ext.*;
import org.swssf.xmlsec.impl.XMLSecurityEventReader;
import org.swssf.xmlsec.impl.securityToken.SecurityTokenFactory;
import org.swssf.xmlsec.impl.util.IDGenerator;
import org.swssf.xmlsec.impl.util.IVSplittingOutputStream;
import org.swssf.xmlsec.impl.util.MultiInputStream;
import org.swssf.xmlsec.impl.util.ReplaceableOuputStream;
import org.xmlsecurity.ns.configuration.AlgorithmType;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.*;

/**
 * Processor for decryption of EncryptedData XML structures
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class AbstractDecryptInputProcessor extends AbstractInputProcessor {

    private ReferenceList referenceList;
    private KeyInfoType keyInfoType;
    private List<ReferenceType> processedReferences = new ArrayList<ReferenceType>();

    private final String uuid = IDGenerator.generateID(null);
    private final QName wrapperElementName = new QName("http://dummy", "dummy", uuid);

    private ArrayDeque<XMLEvent> tmpXmlEventList = new ArrayDeque<XMLEvent>();
    private XMLEvent parentStartXMLEvent;

    public AbstractDecryptInputProcessor(KeyInfoType keyInfoType, ReferenceList referenceList,
                                         XMLSecurityProperties securityProperties) throws XMLSecurityException {
        super(securityProperties);
        this.keyInfoType = keyInfoType;
        this.referenceList = referenceList;

        if (referenceList != null) {
            List<JAXBElement<ReferenceType>> references = referenceList.getDataReferenceOrKeyReference();
            Iterator<JAXBElement<ReferenceType>> referenceTypeIterator = references.iterator();
            while (referenceTypeIterator.hasNext()) {
                ReferenceType referenceType = referenceTypeIterator.next().getValue();
                if (referenceType.getURI() == null) {
                    throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK);
                }
            }
        }
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
        return processEvent(inputProcessorChain, true);
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        return processEvent(inputProcessorChain, false);
    }

    private XMLEvent processEvent(InputProcessorChain inputProcessorChain, boolean isSecurityHeaderEvent) throws XMLStreamException, XMLSecurityException {

        if (!tmpXmlEventList.isEmpty()) {
            return getLastBufferedXMLEvent(inputProcessorChain);
        }

        XMLEvent xmlEvent = isSecurityHeaderEvent ? inputProcessorChain.processHeaderEvent() : inputProcessorChain.processEvent();

        boolean encryptedHeader = false;

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            //buffer the events until the EncryptedData Element appears and discard it if we found the reference inside it
            //otherwise replay it
            if (startElement.getName().equals(XMLSecurityConstants.TAG_wsse11_EncryptedHeader)) {
                xmlEvent = readAndBufferEncryptedHeader(inputProcessorChain, isSecurityHeaderEvent, xmlEvent);
                startElement = xmlEvent.asStartElement();
                encryptedHeader = true;
            }

            //check if the current start-element has the name EncryptedData and an Id attribute
            if (startElement.getName().equals(XMLSecurityConstants.TAG_xenc_EncryptedData)) {
                ReferenceType referenceType = matchesReferenceId(startElement);
                if (referenceType == null) {
                    //if the events were not for us (no matching reference-id the we have to replay the EncryptedHeader elements)
                    if (!tmpXmlEventList.isEmpty()) {
                        return tmpXmlEventList.pollLast();
                    }
                    return xmlEvent;
                }
                //duplicate id's are forbidden
                if (processedReferences.contains(referenceType)) {
                    throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, "duplicateId");
                }

                XMLEventNS xmlEventNS = (XMLEventNS) xmlEvent;
                List<ComparableNamespace>[] comparableNamespaceList = getNamespacesInScope(xmlEvent, encryptedHeader);
                List<ComparableAttribute>[] comparableAttributeList = getAttributesInScope(xmlEvent, encryptedHeader);
                tmpXmlEventList.clear();
                processedReferences.add(referenceType);

                //the following logic reads the encryptedData structure and doesn't pass them further
                //through the chain
                InputProcessorChain subInputProcessorChain = inputProcessorChain.createSubChain(this);

                EncryptedDataType encryptedDataType = parseEncryptedDataStructure(isSecurityHeaderEvent, xmlEvent, subInputProcessorChain);

                SecurityToken securityToken = getSecurityToken(inputProcessorChain, encryptedDataType);
                handleSecurityToken(securityToken, inputProcessorChain.getSecurityContext(), encryptedDataType);

                //only fire here ContentEncryptedElementEvents
                //the other ones will be fired later, because we don't know the encrypted element name yet
                if (SecurePart.Modifier.Content.getModifier().equals(encryptedDataType.getType())) {
                    handleEncryptedContent(inputProcessorChain, parentStartXMLEvent, xmlEvent, securityToken);
                }

                final String algorithmURI = encryptedDataType.getEncryptionMethod().getAlgorithm();
                Cipher symCipher = getCipher(algorithmURI);

                //create a new Thread for streaming decryption
                DecryptionThread decryptionThread = new DecryptionThread(subInputProcessorChain, isSecurityHeaderEvent, xmlEventNS);
                decryptionThread.setSecretKey(securityToken.getSecretKey(algorithmURI, XMLSecurityConstants.Enc));
                decryptionThread.setSymmetricCipher(symCipher);

                AbstractDecryptedEventReaderInputProcessor decryptedEventReaderInputProcessor = newDecryptedEventReaderInputProccessor(
                        encryptedHeader, comparableNamespaceList, comparableAttributeList, encryptedDataType, securityToken, inputProcessorChain.getSecurityContext()
                );

                //add the new created EventReader processor to the chain.
                inputProcessorChain.addProcessor(decryptedEventReaderInputProcessor);

                inputProcessorChain.getDocumentContext().setIsInEncryptedContent(inputProcessorChain.getProcessors().indexOf(decryptedEventReaderInputProcessor), decryptedEventReaderInputProcessor);

                Thread thread = new Thread(decryptionThread);
                thread.setName("decrypting thread");
                //when an exception in the decryption thread occurs, we want to forward them:
                thread.setUncaughtExceptionHandler(decryptedEventReaderInputProcessor);

                //we have to start the thread before we call decryptionThread.getPipedInputStream().
                //Otherwise we will end in a deadlock, because the StAX reader expects already data.
                //@See some lines below:
                logger.debug("Starting decryption thread");
                thread.start();

                inputProcessorChain.getDocumentContext().removePathElement();

                InputStream prologInputStream;
                InputStream epilogInputStream;
                try {
                    prologInputStream = writeWrapperStartElement(xmlEventNS);
                    epilogInputStream = writeWrapperEndElement();
                } catch (UnsupportedEncodingException e) {
                    throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, e);
                } catch (IOException e) {
                    throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, e);
                }

                InputStream decryptInputStream = decryptionThread.getPipedInputStream();

                TransformsType transformsType = XMLSecurityUtils.getQNameType(referenceType.getAny(), XMLSecurityConstants.TAG_dsig_Transforms);
                if (transformsType != null) {
                    List<TransformType> transformTypes = transformsType.getTransform();
                    if (transformTypes.size() > 1) {
                        throw new XMLSecurityException(XMLSecurityException.ErrorCode.INVALID_SECURITY);
                    }
                    TransformType transformType = transformTypes.get(0);
                    Class<InputStream> transformerClass = (Class<InputStream>) TransformerAlgorithmMapper.getTransformerClass(transformType.getAlgorithm(), "IN");
                    try {
                        Constructor<InputStream> constructor = transformerClass.getConstructor(InputStream.class);
                        decryptInputStream = constructor.newInstance(decryptInputStream);
                    } catch (InvocationTargetException e) {
                        throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, e);
                    } catch (NoSuchMethodException e) {
                        throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, e);
                    } catch (InstantiationException e) {
                        throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, e);
                    } catch (IllegalAccessException e) {
                        throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, e);
                    }
                }

                //spec says (4.2): "The cleartext octet sequence obtained in step 3 is interpreted as UTF-8 encoded character data."
                XMLEventReader xmlEventReader =
                        inputProcessorChain.getSecurityContext().<XMLInputFactory>get(
                                XMLSecurityConstants.XMLINPUTFACTORY).createXMLEventReader(
                                new MultiInputStream(prologInputStream, decryptInputStream, epilogInputStream), "UTF-8");

                //forward to wrapper element
                forwardToWrapperElement(xmlEventReader);

                decryptedEventReaderInputProcessor.setXmlEventReader(xmlEventReader);

                if (isSecurityHeaderEvent) {
                    return decryptedEventReaderInputProcessor.processNextHeaderEvent(inputProcessorChain);
                } else {
                    return decryptedEventReaderInputProcessor.processNextEvent(inputProcessorChain);
                }
            }
        }

        if (xmlEvent.isStartElement()) {
            parentStartXMLEvent = xmlEvent;
        }
        return xmlEvent;
    }

    private InputStream writeWrapperStartElement(XMLEventNS startXMLElement) throws IOException {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        //temporary writer to write the dummy wrapper element with all namespaces in the current scope
        //spec says (4.2): "The cleartext octet sequence obtained in step 3 is interpreted as UTF-8 encoded character data."
        Writer writer = new OutputStreamWriter(byteArrayOutputStream, "UTF-8");

        writer.write('<');
        writer.write(wrapperElementName.getPrefix());
        writer.write(':');
        writer.write(wrapperElementName.getLocalPart());
        writer.write(' ');
        writer.write("xmlns:");
        writer.write(wrapperElementName.getPrefix());
        writer.write("=\"");
        writer.write(wrapperElementName.getNamespaceURI());
        writer.write('\"');

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
            writer.write(' ');
            //todo write namespace ourself
            writer.write(comparableNamespace.toString());
        }

        writer.write('>');
        writer.close();
        return new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
    }

    private InputStream writeWrapperEndElement() throws IOException {

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        Writer writer = new OutputStreamWriter(byteArrayOutputStream, "UTF-8");

        //close the dummy wrapper element:
        writer.write("</");
        writer.write(wrapperElementName.getPrefix());
        writer.write(':');
        writer.write(wrapperElementName.getLocalPart());
        writer.write('>');
        writer.close();
        return new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
    }

    private void forwardToWrapperElement(XMLEventReader xmlEventReader) throws XMLStreamException {
        XMLEvent tmpXmlEvent;
        do {
            tmpXmlEvent = xmlEventReader.nextEvent();
        }
        while (!(tmpXmlEvent.isStartElement() && tmpXmlEvent.asStartElement().getName().equals(wrapperElementName)));
    }

    private Cipher getCipher(String algorithmURI) throws XMLSecurityException {
        Cipher symCipher;
        try {
            AlgorithmType symEncAlgo = JCEAlgorithmMapper.getAlgorithmMapping(algorithmURI);
            symCipher = Cipher.getInstance(symEncAlgo.getJCEName(), symEncAlgo.getJCEProvider());
            //we have to defer the initialization of the cipher until we can extract the IV...
        } catch (NoSuchAlgorithmException e) {
            throw new XMLSecurityException(
                    XMLSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "unsupportedKeyTransp",
                    e, "No such algorithm: " + algorithmURI
            );
        } catch (NoSuchPaddingException e) {
            throw new XMLSecurityException(
                    XMLSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, "unsupportedKeyTransp",
                    e, "No such padding: " + algorithmURI
            );
        } catch (NoSuchProviderException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILURE, "noSecProvider", e);
        }
        return symCipher;
    }

    private SecurityToken getSecurityToken(InputProcessorChain inputProcessorChain, EncryptedDataType encryptedDataType) throws XMLSecurityException {
        KeyInfoType keyInfoType;
        if (this.keyInfoType != null) {
            keyInfoType = this.keyInfoType;
        } else {
            keyInfoType = encryptedDataType.getKeyInfo();
        }

        //retrieve the securityToken which must be used for decryption
        return SecurityTokenFactory.getInstance().getSecurityToken(
                keyInfoType, getSecurityProperties().getDecryptionCrypto(),
                getSecurityProperties().getCallbackHandler(), inputProcessorChain.getSecurityContext());
    }

    private EncryptedDataType parseEncryptedDataStructure(boolean isSecurityHeaderEvent, XMLEvent xmlEvent, InputProcessorChain subInputProcessorChain) throws XMLStreamException, XMLSecurityException {
        Deque<XMLEvent> xmlEvents = new LinkedList<XMLEvent>();
        xmlEvents.push(xmlEvent);
        XMLEvent encryptedDataXMLEvent;
        int count = 0;
        do {
            subInputProcessorChain.reset();
            if (isSecurityHeaderEvent) {
                encryptedDataXMLEvent = subInputProcessorChain.processHeaderEvent();
            } else {
                encryptedDataXMLEvent = subInputProcessorChain.processEvent();
            }

            xmlEvents.push(encryptedDataXMLEvent);
            if (++count >= 50) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.INVALID_SECURITY);
            }
        }
        while (!(encryptedDataXMLEvent.isStartElement()
                && encryptedDataXMLEvent.asStartElement().getName().equals(XMLSecurityConstants.TAG_xenc_CipherValue)));

        xmlEvents.push(XMLSecurityConstants.XMLEVENTFACTORY.createEndElement(XMLSecurityConstants.TAG_xenc_CipherValue, null));
        xmlEvents.push(XMLSecurityConstants.XMLEVENTFACTORY.createEndElement(XMLSecurityConstants.TAG_xenc_CipherData, null));
        xmlEvents.push(XMLSecurityConstants.XMLEVENTFACTORY.createEndElement(XMLSecurityConstants.TAG_xenc_EncryptedData, null));

        EncryptedDataType encryptedDataType;

        try {
            Unmarshaller unmarshaller = XMLSecurityConstants.getJaxbUnmarshaller(getSecurityProperties().isDisableSchemaValidation());
            JAXBElement<EncryptedDataType> encryptedDataTypeJAXBElement =
                    (JAXBElement<EncryptedDataType>) unmarshaller.unmarshal(new XMLSecurityEventReader(xmlEvents, 0));
            encryptedDataType = encryptedDataTypeJAXBElement.getValue();

        } catch (JAXBException e) {
            throw new XMLSecurityException(XMLSecurityException.ErrorCode.INVALID_SECURITY, e);
        }
        return encryptedDataType;
    }

    private XMLEvent getLastBufferedXMLEvent(InputProcessorChain inputProcessorChain) {
        XMLEvent xmlEvent = tmpXmlEventList.pollLast();
        if (xmlEvent.isStartElement()) {
            inputProcessorChain.getDocumentContext().addPathElement(xmlEvent.asStartElement().getName());
        } else if (xmlEvent.isEndElement()) {
            inputProcessorChain.getDocumentContext().removePathElement();
        }
        return xmlEvent;
    }

    private XMLEvent readAndBufferEncryptedHeader(InputProcessorChain inputProcessorChain, boolean isSecurityHeaderEvent, XMLEvent xmlEvent) throws XMLStreamException, XMLSecurityException {
        InputProcessorChain subInputProcessorChain = inputProcessorChain.createSubChain(this);
        do {
            tmpXmlEventList.push(xmlEvent);

            subInputProcessorChain.reset();
            if (isSecurityHeaderEvent) {
                xmlEvent = subInputProcessorChain.processHeaderEvent();
            } else {
                xmlEvent = subInputProcessorChain.processEvent();
            }
        }
        while (!(xmlEvent.isStartElement() && xmlEvent.asStartElement().getName().equals(XMLSecurityConstants.TAG_xenc_EncryptedData)));

        tmpXmlEventList.push(xmlEvent);
        return xmlEvent;
    }

    private List<ComparableNamespace>[] getNamespacesInScope(XMLEvent xmlEvent, boolean encryptedHeader) {
        XMLEventNS xmlEventNS = (XMLEventNS) xmlEvent;
        if (encryptedHeader) {
            return Arrays.copyOfRange(xmlEventNS.getNamespaceList(), 2, xmlEventNS.getNamespaceList().length);
        } else {
            return Arrays.copyOfRange(xmlEventNS.getNamespaceList(), 1, xmlEventNS.getNamespaceList().length);
        }
    }

    private List<ComparableAttribute>[] getAttributesInScope(XMLEvent xmlEvent, boolean encryptedHeader) {
        XMLEventNS xmlEventNS = (XMLEventNS) xmlEvent;
        if (encryptedHeader) {
            return Arrays.copyOfRange(xmlEventNS.getAttributeList(), 2, xmlEventNS.getNamespaceList().length);
        } else {
            return Arrays.copyOfRange(xmlEventNS.getAttributeList(), 1, xmlEventNS.getNamespaceList().length);
        }
    }

    protected abstract AbstractDecryptedEventReaderInputProcessor newDecryptedEventReaderInputProccessor(
            boolean encryptedHeader, List<ComparableNamespace>[] comparableNamespaceList,
            List<ComparableAttribute>[] comparableAttributeList, EncryptedDataType currentEncryptedDataType,
            SecurityToken securityToken, SecurityContext securityContext) throws XMLSecurityException;

    protected abstract void handleSecurityToken(
            SecurityToken securityToken, SecurityContext securityContext, EncryptedDataType encryptedDataType) throws XMLSecurityException;

    protected abstract void handleEncryptedContent(
            InputProcessorChain inputProcessorChain, XMLEvent parentXMLEvent, XMLEvent xmlEvent, SecurityToken securityToken) throws XMLSecurityException;

    protected ReferenceType matchesReferenceId(StartElement startElement) {

        Attribute refId = getReferenceIDAttribute(startElement);
        if (refId != null) {
            //exists the id in the referenceList?
            List<JAXBElement<ReferenceType>> references = referenceList.getDataReferenceOrKeyReference();
            Iterator<JAXBElement<ReferenceType>> referenceTypeIterator = references.iterator();
            while (referenceTypeIterator.hasNext()) {
                ReferenceType referenceType = referenceTypeIterator.next().getValue();
                if (refId.getValue().equals(XMLSecurityUtils.dropReferenceMarker(referenceType.getURI()))) {
                    logger.debug("Found encryption reference: " + refId.getValue() + " on element" + startElement.getName());
                    return referenceType;
                }
            }
        }
        return null;
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        //here we check if all references where processed.
        List<JAXBElement<ReferenceType>> references = referenceList.getDataReferenceOrKeyReference();
        Iterator<JAXBElement<ReferenceType>> referenceTypeIterator = references.iterator();
        while (referenceTypeIterator.hasNext()) {
            ReferenceType referenceType = referenceTypeIterator.next().getValue();
            if (!processedReferences.contains(referenceType)) {
                throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, "unprocessedEncryptionReferences");
            }
        }
        inputProcessorChain.doFinal();
    }

    /**
     * The DecryptedEventReaderInputProcessor reads the decrypted stream with a StAX reader and
     * forwards the generated XMLEvents
     */
    public abstract class AbstractDecryptedEventReaderInputProcessor extends AbstractInputProcessor implements Thread.UncaughtExceptionHandler {

        private XMLEventReader xmlEventReader;
        private Deque<List<ComparableNamespace>> nsStack = new ArrayDeque<List<ComparableNamespace>>(10);
        private Deque<List<ComparableAttribute>> attrStack = new ArrayDeque<List<ComparableAttribute>>(10);
        private SecurePart.Modifier encryptionModifier;
        private boolean encryptedHeader = false;
        private int documentLevel = 0;
        private SecurityToken securityToken;

        private boolean rootElementProcessed;

        public AbstractDecryptedEventReaderInputProcessor(
                XMLSecurityProperties securityProperties, SecurePart.Modifier encryptionModifier,
                boolean encryptedHeader, List<ComparableNamespace>[] namespaceList,
                List<ComparableAttribute>[] attributeList,
                AbstractDecryptInputProcessor abstractDecryptInputProcessor,
                SecurityToken securityToken
        ) {
            super(securityProperties);
            getAfterProcessors().add(abstractDecryptInputProcessor);
            this.encryptionModifier = encryptionModifier;
            this.rootElementProcessed = encryptionModifier != SecurePart.Modifier.Element;
            this.encryptedHeader = encryptedHeader;
            this.securityToken = securityToken;
            for (int i = 0; i < namespaceList.length; i++) {
                List<ComparableNamespace> namespaces = namespaceList[i];
                this.nsStack.push(namespaces);
            }
            for (int i = 0; i < attributeList.length; i++) {
                List<ComparableAttribute> attributes = attributeList[i];
                this.attrStack.push(attributes);
            }
        }

        public void setXmlEventReader(XMLEventReader xmlEventReader) {
            this.xmlEventReader = xmlEventReader;
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
            //did a execption occur during decryption in the decryption thread?
            testAndThrowUncaughtException();
            //here we request the next XMLEvent from the decryption thread
            //instead from the processor-chain as we normally would do
            XMLEvent xmlEvent = xmlEventReader.nextEvent();

            if (xmlEvent.isStartElement()) {
                documentLevel++;

                inputProcessorChain.getDocumentContext().addPathElement(xmlEvent.asStartElement().getName());

                if (!rootElementProcessed) {
                    handleEncryptedElement(inputProcessorChain, xmlEvent, this.securityToken);
                    rootElementProcessed = true;
                }

            } else if (xmlEvent.isEndElement()) {

                if (xmlEvent.isEndElement() && xmlEvent.asEndElement().getName().equals(wrapperElementName)) {
                    //correct path and skip EndElements:
                    InputProcessorChain subInputProcessorChain = inputProcessorChain.createSubChain(this);

                    //skip EncryptedHeader Element when we processed it.
                    QName endElement;
                    if (encryptedHeader) {
                        subInputProcessorChain.getDocumentContext().addPathElement(XMLSecurityConstants.TAG_wsse11_EncryptedHeader);
                        endElement = XMLSecurityConstants.TAG_wsse11_EncryptedHeader;
                    } else {
                        endElement = XMLSecurityConstants.TAG_xenc_EncryptedData;
                    }
                    subInputProcessorChain.getDocumentContext().addPathElement(XMLSecurityConstants.TAG_xenc_EncryptedData);
                    subInputProcessorChain.getDocumentContext().addPathElement(XMLSecurityConstants.TAG_xenc_CipherData);

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

                    inputProcessorChain.getDocumentContext().unsetIsInEncryptedContent(this);

                    //...fetch the next (unencrypted) event
                    if (headerEvent) {
                        xmlEvent = inputProcessorChain.processHeaderEvent();
                    } else {
                        xmlEvent = inputProcessorChain.processEvent();
                    }

                    inputProcessorChain.removeProcessor(this);
                }

                if (documentLevel > 0) {
                    inputProcessorChain.getDocumentContext().removePathElement();
                }

                documentLevel--;
            }

            if (!(xmlEvent instanceof XMLEventNS)) {
                xmlEvent = XMLSecurityUtils.createXMLEventNS(xmlEvent, nsStack, attrStack);
            }
            return xmlEvent;
        }

        protected abstract void handleEncryptedElement(InputProcessorChain inputProcessorChain, XMLEvent xmlEvent, SecurityToken securityToken) throws XMLSecurityException;

        private Throwable thrownException;

        public void uncaughtException(Thread t, Throwable e) {
            this.thrownException = e;
        }

        private void testAndThrowUncaughtException() throws XMLStreamException {
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

    /**
     * The DecryptionThread handles encrypted XML-Parts
     */
    class DecryptionThread implements Runnable {

        private InputProcessorChain inputProcessorChain;
        private boolean header;
        private XMLEventNS startXMLElement;
        private PipedOutputStream pipedOutputStream;
        private PipedInputStream pipedInputStream;
        private Cipher symmetricCipher;
        private Key secretKey;

        protected DecryptionThread(InputProcessorChain inputProcessorChain, boolean header,
                                   XMLEventNS startXMLElement) throws XMLStreamException, XMLSecurityException {

            this.inputProcessorChain = inputProcessorChain;
            this.header = header;
            this.startXMLElement = startXMLElement;

            //prepare the piped streams and connect them:
            //5 * 8192 seems to be a fine value
            this.pipedInputStream = new PipedInputStream(40960);
            try {
                this.pipedOutputStream = new PipedOutputStream(pipedInputStream);
            } catch (IOException e) {
                throw new XMLStreamException(e);
            }
        }

        public PipedInputStream getPipedInputStream() {
            return pipedInputStream;
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
                IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(
                        new CipherOutputStream(pipedOutputStream, getSymmetricCipher()),
                        getSymmetricCipher(), getSecretKey());
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
                            throw new XMLSecurityException(XMLSecurityException.ErrorCode.FAILED_CHECK, "unexpectedXMLEvent", XMLSecurityUtils.getXMLEventAsString(xmlEvent));
                    }
                }

                //close to get Cipher.doFinal() called
                decryptOutputStream.close();
                logger.debug("Decryption thread finished");

            } catch (Exception e) {
                throw new UncheckedXMLSecurityException(e);
            }
        }

        protected Cipher getSymmetricCipher() {
            return symmetricCipher;
        }

        protected void setSymmetricCipher(Cipher symmetricCipher) {
            this.symmetricCipher = symmetricCipher;
        }

        protected Key getSecretKey() {
            return secretKey;
        }

        protected void setSecretKey(Key secretKey) {
            this.secretKey = secretKey;
        }
    }
}
