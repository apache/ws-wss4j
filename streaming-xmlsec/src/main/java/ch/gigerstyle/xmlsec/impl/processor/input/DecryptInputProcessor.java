package ch.gigerstyle.xmlsec.impl.processor.input;

import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.impl.SecurityTokenFactory;
import ch.gigerstyle.xmlsec.impl.util.IVSplittingOutputStream;
import org.apache.commons.codec.binary.Base64OutputStream;
import org.w3._2001._04.xmlenc_.EncryptedDataType;
import org.w3._2001._04.xmlenc_.ReferenceList;
import org.w3._2001._04.xmlenc_.ReferenceType;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
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
    private boolean isFinishedcurrentEncryptedDataType = false;
    private boolean isCipherValue = false;

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

    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

        //todo overall null checks

        //lastStartElement is also set for characterEvents so we dont handle the whole CipherValue subtree here
        if (currentEncryptedDataType != null && !(getLastStartElementName().equals(Constants.TAG_xenc_CipherValue))) {
            try {
                isFinishedcurrentEncryptedDataType = currentEncryptedDataType.parseXMLEvent(xmlEvent);
                //todo validation will never be called because we abort early (see above if condition)
                if (isFinishedcurrentEncryptedDataType) {
                    currentEncryptedDataType.validate();
                }
            } catch (ParseException e) {
                throw new XMLSecurityException(e);
            }
        } else if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            if (startElement.getName().equals(Constants.TAG_xenc_EncryptedData)) {
                Attribute refId = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (refId != null) {
                    List<ReferenceType> references = referenceList.getDataReferenceOrKeyReference();
                    for (int i = 0; i < references.size(); i++) {
                        ReferenceType referenceType = references.get(i);
                        if (refId.getValue().equals(referenceType.getURI())) {
                            logger.debug("Found encryption reference: " + refId.getValue() + "on element" + startElement.getName());
                            if (referenceType.isProcessed()) {
                                throw new XMLSecurityException("duplicate id encountered!");
                            }
                            currentEncryptedDataType = new EncryptedDataType(startElement);

                            referenceType.setProcessed(true);
                        }
                    }
                }
            } else if (currentEncryptedDataType != null && startElement.getName().equals(Constants.TAG_xenc_CipherValue)) {
                InternalDecryptProcessor internalDecryptProcessor = new InternalDecryptProcessor(getSecurityProperties(), (XMLEventNS) xmlEvent, currentEncryptedDataType);
                inputProcessorChain.addProcessor(internalDecryptProcessor);
                isCipherValue = true;
                return;
            }
        }

        if (xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();
            if (endElement.getName().equals(Constants.TAG_xenc_EncryptedData)) {
                currentEncryptedDataType = null;
                isFinishedcurrentEncryptedDataType = false;
                return;
            } else if (endElement.getName().equals(Constants.TAG_xenc_CipherValue)) {
                inputProcessorChain.processEvent(xmlEvent);
                isCipherValue = false;
            }
        }

        if (isCipherValue || currentEncryptedDataType == null) {
            inputProcessorChain.processEvent(xmlEvent);
        }
    }

    @Override
    public void doFinal(InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        List<ReferenceType> references = referenceList.getDataReferenceOrKeyReference();
        for (int i = 0; i < references.size(); i++) {
            ReferenceType referenceType = references.get(i);
            if (!referenceType.isProcessed()) {
                throw new XMLSecurityException("Some encryption references where not processed... Probably security header ordering problem?");
            }
        }
        inputProcessorChain.doFinal();
    }

    class InternalDecryptProcessor extends AbstractInputProcessor {

        private Cipher symmetricCipher;
        private OutputStream bufferedOutputStream;
        private OutputStream outputStream;
        private boolean isFirstCall = true;
        private EncryptedDataType encryptedDataType;
        private XMLEventNS startXMLElement;
        private Thread receiverThread;

        //todo static final init or better: hardcoded:
        //use a unique prefix; the prefix must start with a letter by spec!:
        private String uuid = "a" + UUID.randomUUID().toString().replaceAll("-", "");
        private final QName dummyStartElementName = new QName("http://dummy", "dummy", uuid);

        InternalDecryptProcessor(SecurityProperties securityProperties, XMLEventNS startXMLEvent, EncryptedDataType encryptedDataType) throws XMLSecurityException, XMLStreamException {
            super(securityProperties);
            this.encryptedDataType = encryptedDataType;
            this.startXMLElement = startXMLEvent;
        }

        @Override
        public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

            //we need to initialize the cipher here because the iv is stored in the first few bytes in the cipher stream
            if (isFirstCall) {

                if (xmlEvent.asCharacters().isIgnorableWhiteSpace()) {
                    return;
                }

                isFirstCall = false;

                try {
                    String syncEncAlgo = JCEAlgorithmMapper.translateURItoJCEID(encryptedDataType.getEncryptionMethod().getAlgorithm());
                    symmetricCipher = Cipher.getInstance(syncEncAlgo, "BC");

                } catch (NoSuchAlgorithmException e) {
                    throw new XMLSecurityException(e);
                } catch (NoSuchProviderException e) {
                    throw new XMLSecurityException(e);
                } catch (NoSuchPaddingException e) {
                    throw new XMLSecurityException(e);
                }

                final InputProcessorChain subInputProcessorChain = inputProcessorChain.createSubChain(this);

                //we have to use a threaded Piped-In/Out Stream. We don't know where we are in the decrypted xml stream
                //and therefore the XMLStreamReader can block on calling next/hasNext.
                final PipedInputStream pipedInputStream = new PipedInputStream();

                try {
                    //outputStream = new LogOutputStream(new PipedOutputStream(pipedInputStream));
                    outputStream = new PipedOutputStream(pipedInputStream);
                } catch (IOException e) {
                    throw new XMLStreamException(e);
                }

                Runnable runnable = new Runnable() {

                    public void run() {

                        try {
                            //todo set encoding?:
                            XMLEventReader xmlEventReader = Constants.xmlInputFactory.createXMLEventReader(pipedInputStream);

                            //todo rethinking about the while loops...
                            while (xmlEventReader.hasNext()) {
                                XMLEvent decXmlEvent = xmlEventReader.nextEvent();
                                if (decXmlEvent.getEventType() == XMLStreamConstants.START_DOCUMENT
                                        || decXmlEvent.getEventType() == XMLStreamConstants.END_DOCUMENT) {
                                    while (xmlEventReader.hasNext()) {
                                        decXmlEvent = xmlEventReader.nextEvent();
                                        if (decXmlEvent.isStartElement() && decXmlEvent.asStartElement().getName().equals(dummyStartElementName)) {
                                            break;
                                        }
                                    }
                                    continue;
                                } else if (decXmlEvent.isEndElement() && decXmlEvent.asEndElement().getName().equals(dummyStartElementName)) {
                                    xmlEventReader.close();
                                    break;
                                }
                                subInputProcessorChain.processEvent(decXmlEvent);
                                subInputProcessorChain.reset();
                            }
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                };

                receiverThread = new Thread(runnable);
                receiverThread.start();

                try {

                    //temporary writer for direct writing plaintext data
                    //todo encoding?:
                    BufferedWriter tempBufferedWriter = new BufferedWriter(new OutputStreamWriter(outputStream));

                    tempBufferedWriter.write('<');
                    tempBufferedWriter.write(dummyStartElementName.getPrefix());
                    tempBufferedWriter.write(':');
                    tempBufferedWriter.write(dummyStartElementName.getLocalPart());
                    tempBufferedWriter.write(' ');
                    tempBufferedWriter.write("xmlns:");
                    tempBufferedWriter.write(dummyStartElementName.getPrefix());
                    tempBufferedWriter.write("=\"");
                    tempBufferedWriter.write(dummyStartElementName.getNamespaceURI());
                    tempBufferedWriter.write("\"");

                    //apply all namespaces from current scope to get a valid documentfragment:
                    List<ComparableNamespace> comparableNamespacesToApply = new ArrayList<ComparableNamespace>();
                    List<ComparableNamespace>[] comparableNamespaceList = startXMLElement.getNamespaceList();
                    for (int i = 0; i < comparableNamespaceList.length; i++) {
                        List<ComparableNamespace> comparableNamespaces = comparableNamespaceList[i];
                        for (int j = 0; j < comparableNamespaces.size(); j++) {
                            ComparableNamespace comparableNamespace = comparableNamespaces.get(j);
                            if (!comparableNamespacesToApply.contains(comparableNamespace)) {
                                comparableNamespacesToApply.add(comparableNamespace);
                            }
                        }
                    }
                    for (int i = 0; i < comparableNamespacesToApply.size(); i++) {
                        ComparableNamespace comparableNamespace = comparableNamespacesToApply.get(i);
                        tempBufferedWriter.write(' ');
                        //todo encoding?:
                        tempBufferedWriter.write(comparableNamespace.toString());
                    }

                    tempBufferedWriter.write(">");
                    //calling flush after every piece to prevent data salad...
                    tempBufferedWriter.flush();

                    //we have to defer the initialization of the cipher until we can extract the IV...
                    SecurityToken securityToken = SecurityTokenFactory.newInstance().getSecurityToken(encryptedDataType.getKeyInfo(), getSecurityProperties().getDecryptionCrypto(), getSecurityProperties().getCallbackHandler(), securityContext);
                    String algoFamily = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(encryptedDataType.getEncryptionMethod().getAlgorithm());
                    SecretKey symmetricKey = new SecretKeySpec(securityToken.getSymmetricKey(), algoFamily);

                    IVSplittingOutputStream ivSplittingOutputStream = new IVSplittingOutputStream(
                            new CipherOutputStream(new FilterOutputStream(outputStream) {
                                @Override
                                public void close() throws IOException {
                                    //we overwrite the close method and don't delegate close. Close must be done separately.
                                    //The reason behind this is the Base64DecoderStream which does the final on close() but after
                                    //that we have to write our dummy end tag
                                    //but calling flush here seems to be fine
                                    out.flush();
                                }
                            }, symmetricCipher),
                            symmetricCipher, symmetricKey);
                    bufferedOutputStream = new BufferedOutputStream(new Base64OutputStream(ivSplittingOutputStream, false), 8192 * 5);

                    bufferedOutputStream.write(xmlEvent.asCharacters().getData().getBytes());

                } catch (IOException e) {
                    throw new XMLStreamException(e);
                }
            } else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                if (endElement.getName().equals(Constants.TAG_xenc_CipherValue)) {
                    try {
                        //flush decrypted data to xmlstreamreader
                        bufferedOutputStream.close(); //close to get Cipher.doFinal() called

                        //todo encoding?:
                        BufferedWriter tempBufferedWriter = new BufferedWriter(new OutputStreamWriter(outputStream));
                        tempBufferedWriter.write("</");
                        tempBufferedWriter.write(dummyStartElementName.getPrefix());
                        tempBufferedWriter.write(':');
                        tempBufferedWriter.write(dummyStartElementName.getLocalPart());
                        tempBufferedWriter.write('>');
                        //real close of the stream
                        tempBufferedWriter.close();
                    } catch (IOException e) {
                        throw new XMLStreamException(e);
                    }
                    inputProcessorChain.removeProcessor(this);

                    try {
                        while (receiverThread.isAlive()) {
                            Thread.sleep(10);
                        }
                        receiverThread = null;
                    } catch (InterruptedException e) {
                        throw new XMLStreamException(e);
                    }
                }
            } else if (xmlEvent.isCharacters()) {
                try {
                    bufferedOutputStream.write(xmlEvent.asCharacters().getData().getBytes());
                } catch (IOException e) {
                    throw new XMLStreamException(e);
                }
            } else {
                throw new XMLSecurityException("Unexpected event: " + Utils.getXMLEventAsString(xmlEvent));
            }
        }
    }
}
