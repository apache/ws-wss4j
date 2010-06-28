package ch.gigerstyle.xmlsec.processorImpl.input;

import ch.gigerstyle.xmlsec.*;
import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import org.bouncycastle.util.encoders.Base64;
import org.w3._2001._04.xmlenc_.EncryptedDataType;
import org.w3._2001._04.xmlenc_.ReferenceList;
import org.w3._2001._04.xmlenc_.ReferenceType;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStreamWriter;
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
                            //currentEncryptedDataType.setId(refId.getValue());
/*                            try {
                                currentEncryptedDataType.validate();
                            } catch (ParseException e) {
                                throw new XMLSecurityException(e);
                            }
*/

                            referenceType.setProcessed(true);
                        }
                    }
                }
            }
        } else if (currentEncryptedDataType != null && xmlEvent.isCharacters()) {
            //todo handle multiple character events for same text-node
            Characters characters = xmlEvent.asCharacters();

            if (getLastStartElementName().equals(Constants.TAG_xenc_CipherValue)) {
                try {
                    String syncEncAlgo = JCEAlgorithmMapper.translateURItoJCEID(currentEncryptedDataType.getEncryptionMethod().getAlgorithm());
                    String algoFamily = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(currentEncryptedDataType.getEncryptionMethod().getAlgorithm());
                    //todo use SecurityTokenFactory??
                    /*
                    SecurityTokenReferenceType securityTokenReferenceType = currentEncryptedDataType.getKeyInfo().getSecurityTokenReferenceType();
                    if (securityTokenReferenceType == null
                            || securityTokenReferenceType.getReferenceType() == null) {
                        throw new XMLSecurityException("SecurityToken not found");
                    }
                    SecurityTokenProvider securityTokenProvider = securityContext.getSecurityTokenProvider(Utils.dropReferenceMarker(securityTokenReferenceType.getReferenceType().getURI()));
                    if (securityTokenProvider == null || securityTokenProvider.getSecurityToken(getSecurityProperties().getDecryptionCrypto()) == null) {
                        throw new XMLSecurityException("SecurityToken not found");
                    }
                    */
                    SecurityToken securityToken = SecurityTokenFactory.newInstance().getSecurityToken(currentEncryptedDataType.getKeyInfo(), getSecurityProperties().getDecryptionCrypto(), getSecurityProperties().getCallbackHandler(), securityContext);
                    SecretKey symmetricKey = new SecretKeySpec(securityToken.getSymmetricKey(), algoFamily);
                    Cipher symmetricCipher = Cipher.getInstance(syncEncAlgo, "BC");

                    int ivLen = symmetricCipher.getBlockSize();
                    byte[] ivBytes = new byte[ivLen];

                    final byte[] encryptedData = Base64.decode(characters.getData());
                    System.arraycopy(encryptedData, 0, ivBytes, 0, ivLen);
                    IvParameterSpec iv = new IvParameterSpec(ivBytes);

                    symmetricCipher.init(Cipher.DECRYPT_MODE, symmetricKey, iv);

                    byte[] plainBytes = symmetricCipher.doFinal(encryptedData, ivLen, encryptedData.length - ivLen);
                    //todo static final init or better: hardcoded:
                    //use a unique prefix; the prefix must start with a letter by spec!:
                    String uuid = "a" + UUID.randomUUID().toString().replaceAll("-", "");

                    ByteArrayOutputStream baos = new ByteArrayOutputStream(plainBytes.length + 100);
                    //todo encoding:
                    OutputStreamWriter outputStreamWriter = new OutputStreamWriter(baos);

                    QName startElementName = new QName("http://dummy", "dummy", uuid);
                    outputStreamWriter.write('<');
                    outputStreamWriter.write(startElementName.getPrefix());
                    outputStreamWriter.write(':');
                    outputStreamWriter.write(startElementName.getLocalPart());
                    outputStreamWriter.write(' ');
                    outputStreamWriter.write("xmlns:");
                    outputStreamWriter.write(startElementName.getPrefix());
                    outputStreamWriter.write("=\"");
                    outputStreamWriter.write(startElementName.getNamespaceURI());
                    outputStreamWriter.write("\"");

                    //apply all namespaces from current scope to get a valid documentfragment:
                    List<ComparableNamespace> comparableNamespacesToApply = new ArrayList<ComparableNamespace>();
                    //test first before casting...should be done in XMLSec...
                    XMLEventNS xmlEventNs = (XMLEventNS) xmlEvent;
                    List<ComparableNamespace>[] comparableNamespaceList = xmlEventNs.getNamespaceList();
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
                        outputStreamWriter.write(' ');
                        //todo encoding?:
                        outputStreamWriter.write(comparableNamespace.toString());
                    }

                    outputStreamWriter.write(">");
                    outputStreamWriter.flush();
                    baos.write(plainBytes);
                    outputStreamWriter.write("</");
                    outputStreamWriter.write(startElementName.getPrefix());
                    outputStreamWriter.write(':');
                    outputStreamWriter.write(startElementName.getLocalPart());
                    outputStreamWriter.write('>');
                    outputStreamWriter.flush();
                    plainBytes = null; //let gc do its job

                    //todo set encoding?:
                    XMLEventReader xmlEventReader = Constants.xmlInputFactory.createXMLEventReader(new ByteArrayInputStream(baos.toByteArray()));

                    InputProcessorChain subInputProcessorChain = inputProcessorChain.createSubChain(this);

                    while (xmlEventReader.hasNext()) {
                        XMLEvent decXmlEvent = xmlEventReader.nextEvent();
                        if (decXmlEvent.getEventType() == XMLStreamConstants.START_DOCUMENT
                                || decXmlEvent.getEventType() == XMLStreamConstants.END_DOCUMENT) {
                            while (xmlEventReader.hasNext()) {
                                decXmlEvent = xmlEventReader.nextEvent();
                                if (decXmlEvent.isStartElement() && decXmlEvent.asStartElement().getName().equals(startElementName)) {
                                    break;
                                }
                            }
                            continue;
                        } else if (decXmlEvent.isEndElement() && decXmlEvent.asEndElement().getName().equals(startElementName)) {
                            xmlEventReader.close();
                            break;
                        }
                        subInputProcessorChain.processEvent(decXmlEvent);
                        subInputProcessorChain.reset();
                    }

                } catch (Exception e) {
                    throw new XMLSecurityException(e.getMessage(), e);
                }
            }
        }

        if (xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();
            if (endElement.getName().equals(Constants.TAG_xenc_EncryptedData)) {
                //todo remove this processor when finished processing all references
                currentEncryptedDataType = null;
                isFinishedcurrentEncryptedDataType = false;
                return;
            }
        }

        if (currentEncryptedDataType == null) {
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
    }
}
