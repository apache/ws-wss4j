package ch.gigerstyle.xmlsec.processorImpl.input;

import ch.gigerstyle.xmlsec.*;
import ch.gigerstyle.xmlsec.config.JCEAlgorithmMapper;
import org.bouncycastle.util.encoders.Base64;
import org.codehaus.stax2.XMLInputFactory2;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.*;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.X509DataType;
import org.w3._2000._09.xmldsig_.X509IssuerSerialType;
import org.w3._2001._04.xmlenc_.*;
import org.w3._2001._04.xmlenc_.ReferenceType;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.NamespaceContext;
import javax.xml.namespace.QName;
import javax.xml.stream.*;
import javax.xml.stream.events.*;
import java.io.*;
import java.nio.CharBuffer;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
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

    private EncryptedKeyType encryptedKeyType;
    private EncryptedDataType currentEncryptedDataType;
    private byte[] keyBytes;

    public DecryptInputProcessor(EncryptedKeyType encryptedKeyType, byte[] keyBytes, SecurityProperties securityProperties) {
        super(securityProperties);
        this.encryptedKeyType = encryptedKeyType;
        this.keyBytes = keyBytes;
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

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            if (startElement.getName().equals(Constants.TAG_xenc_EncryptedData)) {
                Attribute refId = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (refId != null) {
                    List<ReferenceType> references = encryptedKeyType.getReferenceList().getDataReferenceOrKeyReference();
                    for (int i = 0; i < references.size(); i++) {
                        ReferenceType referenceType =  references.get(i);
                        if (refId.getValue().equals(referenceType.getURI())) {
                            System.out.println("found " + refId.getValue());
                            //todo exception when reference is not found
                            currentEncryptedDataType = new EncryptedDataType();
                            currentEncryptedDataType.setId(refId.getValue());

                            Attribute type = startElement.getAttributeByName(Constants.ATT_NULL_Type);
                            if (type != null) {
                                currentEncryptedDataType.setType(type.getValue());
                            }
                        }
                    }
                }
            }
            else if (currentEncryptedDataType == null) {
                //do nothing...fall out
            }
            else if (startElement.getName().equals(Constants.TAG_xenc_EncryptionMethod)) {
                Attribute algorithm = startElement.getAttributeByName(Constants.ATT_NULL_Algorithm);
                if (algorithm == null) {
                    throw new XMLSecurityException("Missing Attribute " + Constants.ATT_NULL_Algorithm);
                }
                EncryptionMethodType encryptionMethodType = new EncryptionMethodType();
                encryptionMethodType.setAlgorithm(algorithm.getValue());
                currentEncryptedDataType.setEncryptionMethod(encryptionMethodType);
            }
            else if (startElement.getName().equals(Constants.TAG_dsig_KeyInfo)) {
                KeyInfoType keyInfoType = new KeyInfoType();

                Attribute id = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (id != null) {
                    keyInfoType.setId(id.getValue());
                }
                currentEncryptedDataType.setKeyInfo(keyInfoType);
            }
            else if (startElement.getName().equals(Constants.TAG_wsse_SecurityTokenReference)) {
                SecurityTokenReferenceType securityTokenReferenceType = new SecurityTokenReferenceType();

                Attribute id = startElement.getAttributeByName(Constants.ATT_wsu_Id);
                if (id != null) {
                    securityTokenReferenceType.setId(id.getValue());
                }
                currentEncryptedDataType.getKeyInfo().getContent().add(securityTokenReferenceType);
            }
            else if (startElement.getName().equals(Constants.TAG_wsse_Reference)) {
               org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.ReferenceType referenceType
                       = new org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.ReferenceType();

                Attribute uri = startElement.getAttributeByName(Constants.ATT_NULL_URI);
                if (uri != null) {
                    referenceType.setURI(uri.getValue());
                }
                Attribute valueType = startElement.getAttributeByName(Constants.ATT_NULL_ValueType);
                if (valueType != null) {
                    referenceType.setValueType(valueType.getValue());
                }
                //todo easier api for lists with unknown types @see cxf
                ((SecurityTokenReferenceType)currentEncryptedDataType.getKeyInfo().getContent().get(0)).getAny().add(referenceType);
            }
            else if (startElement.getName().equals(Constants.TAG_xenc_CipherData)) {
                CipherDataType cipherDataType = new CipherDataType();
                currentEncryptedDataType.setCipherData(cipherDataType);
            }
            else if (startElement.getName().equals(Constants.TAG_xenc_CipherValue)) {
                //nothing to-do
            }
        }
        else if (currentEncryptedDataType != null && xmlEvent.isCharacters()) {
            //todo handle multiple character events for same text-node
            Characters characters = xmlEvent.asCharacters();

            //todo this should go to EncryptedKeyInputProcessor...
            if (getLastStartElementName().equals(Constants.TAG_xenc_CipherValue)) {
                try {
                    String syncEncAlgo = JCEAlgorithmMapper.translateURItoJCEID(currentEncryptedDataType.getEncryptionMethod().getAlgorithm());
                    String algoFamily = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(currentEncryptedDataType.getEncryptionMethod().getAlgorithm());
                    SecretKey symmetricKey = new SecretKeySpec(keyBytes, algoFamily);
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
                    XMLEventNS xmlEventNs = (XMLEventNS)xmlEvent;
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
                        }
                        else if (decXmlEvent.isEndElement() && decXmlEvent.asEndElement().getName().equals(startElementName)) {
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
        else if (xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();
            if (endElement.getName().equals(Constants.TAG_xenc_EncryptedData)) {
                //todo remove this processor when finished processing all references
                currentEncryptedDataType = null;
                return;
            }
        }
        
        if (currentEncryptedDataType == null) {
            inputProcessorChain.processEvent(xmlEvent);
        }
    }
}
