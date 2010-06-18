package ch.gigerstyle.xmlsec.processorImpl.input;

import ch.gigerstyle.xmlsec.*;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.KeyIdentifierType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityTokenReferenceType;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2001._04.xmlenc_.*;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.util.HashMap;
import java.util.Map;

/**
 * User: giger
 * Date: May 13, 2010
 * Time: 1:42:42 PM
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
public class EncryptedKeyInputProcessor extends AbstractInputProcessor {

    private Map<String, EncryptedKeyType> encryptedKeys = new HashMap<String, EncryptedKeyType>();
    private EncryptedKeyType currentEncryptedKeyType;
    private KeyIdentifierType currentKeyIdentifierType;

    public EncryptedKeyInputProcessor(SecurityProperties securityProperties) {
        super(securityProperties);
    }

    /*
    <xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#" Id="EncKeyId-1483925398">
        <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5" />
        <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
            <wsse:SecurityTokenReference xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
                <wsse:KeyIdentifier EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
                    ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier">pHoiKNGY2YsLBKxwIV+jURt858M=</wsse:KeyIdentifier>
                </wsse:SecurityTokenReference>
        </ds:KeyInfo>
        <xenc:CipherData>
            <xenc:CipherValue>Khsa9SN3ALNXOgGDKOqihvfwGsXb9QN/q4Fpi9uuThgz+3D4oRSMkrGSPCqwG13vddvHywGAA/XNbWNT+5Xivz3lURCDCc2H/92YlXXo/crQNJnPlLrLZ81bGOzbNo7lnYQBLp/77K7b1bhldZAeV9ZfEW7DjbOMZ+k1dnDCu3A=</xenc:CipherValue>
        </xenc:CipherData>
        <xenc:ReferenceList>
            <xenc:DataReference URI="#EncDataId-1612925417" />
        </xenc:ReferenceList>
    </xenc:EncryptedKey>
     */

    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            if (startElement.getName().equals(Constants.TAG_xmlenc_EncryptedKey)) {
                currentEncryptedKeyType = new EncryptedKeyType();

                Attribute attribute = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (attribute != null) {
                    currentEncryptedKeyType.setId(attribute.getValue());
                    encryptedKeys.put(attribute.getValue(), currentEncryptedKeyType);
                } else {
                    encryptedKeys.put(null, currentEncryptedKeyType);
                }
            }
            else if (currentEncryptedKeyType == null) {
                //do nothing...fall out
            }
            else if (startElement.getName().equals(Constants.TAG_xmlenc_EncryptionMethod)) {

                //required:
                Attribute attribute = startElement.getAttributeByName(Constants.ATT_NULL_Algorithm);
                if (attribute == null) {
                    throw new XMLSecurityException("Missing Attribute " + Constants.ATT_NULL_Algorithm);
                }

                EncryptionMethodType encryptionMethodType = new EncryptionMethodType();
                encryptionMethodType.setAlgorithm(attribute.getValue());
                currentEncryptedKeyType.setEncryptionMethod(encryptionMethodType);
            }
            else if (startElement.getName().equals(Constants.TAG_dsig_KeyInfo)) {
                KeyInfoType keyInfoType = new KeyInfoType();
                //optional:
                Attribute idAttribute = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (idAttribute != null) {
                    keyInfoType.setId(idAttribute.getValue());
                }
                currentEncryptedKeyType.setKeyInfo(keyInfoType);
            }
            else if (startElement.getName().equals(Constants.TAG_wsse_SecurityTokenReference)) {
                SecurityTokenReferenceType securityTokenReferenceType = new SecurityTokenReferenceType();
                //optional:
                Attribute idAttribute = startElement.getAttributeByName(Constants.ATT_wsu_Id);
                if (idAttribute != null) {
                    securityTokenReferenceType.setId(idAttribute.getValue());
                }
                currentEncryptedKeyType.getKeyInfo().getContent().add(securityTokenReferenceType);
            }
            else if (startElement.getName().equals(Constants.TAG_wsse_KeyIdentifier)) {
                KeyIdentifierType keyIdentifierType = new KeyIdentifierType();

                Attribute encodingType = startElement.getAttributeByName(Constants.ATT_NULL_EncodingType);
                if (encodingType != null) {
                    keyIdentifierType.setEncodingType(encodingType.getValue());
                }

                Attribute valueType = startElement.getAttributeByName(Constants.ATT_NULL_ValueType);
                if (valueType != null) {
                    keyIdentifierType.setValueType(valueType.getValue());
                }
                //todo easier api for lists with unknown types @see cxf
                ((SecurityTokenReferenceType)currentEncryptedKeyType.getKeyInfo().getContent().get(0)).getAny().add(keyIdentifierType);
                currentKeyIdentifierType = keyIdentifierType;
            }
            else if (startElement.getName().equals(Constants.TAG_xenc_CipherData)) {
                CipherDataType cipherDataType = new CipherDataType();
                currentEncryptedKeyType.setCipherData(cipherDataType);
            }
            else if (startElement.getName().equals(Constants.TAG_xenc_CipherValue)) {
                //nothing todo
            }
            else if (startElement.getName().equals(Constants.TAG_xenc_ReferenceList)) {
                ReferenceList referenceList = new ReferenceList();
                currentEncryptedKeyType.setReferenceList(referenceList);
            }
            else if (startElement.getName().equals(Constants.TAG_xenc_DataReference)) {

                Attribute uriAttribute = startElement.getAttributeByName(Constants.ATT_NULL_URI);
                if (uriAttribute == null) {
                    throw new XMLSecurityException("Missing Attribute " + Constants.ATT_NULL_URI);
                }
                ReferenceType referenceType = new ReferenceType();
                referenceType.setURI(Utils.dropReferenceMarker(uriAttribute.getValue()));
                currentEncryptedKeyType.getReferenceList().getDataReferenceOrKeyReference().add(referenceType);
            }
        }
        else if (currentEncryptedKeyType != null && xmlEvent.isCharacters()) {
            //todo handle multiple character events for same text-node
            Characters characters = xmlEvent.asCharacters();
            if (!characters.isWhiteSpace() &&getLastStartElementName().equals(Constants.TAG_xenc_CipherValue)) {
                currentEncryptedKeyType.getCipherData().setCipherValue(characters.getData().getBytes());
            }
            else if (!characters.isWhiteSpace() &&getLastStartElementName().equals(Constants.TAG_wsse_KeyIdentifier)) {
                currentKeyIdentifierType.setValue(characters.getData());
            }
        }
        else if (currentEncryptedKeyType != null && xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();
            
            if (endElement.getName().equals(Constants.TAG_xmlenc_EncryptedKey)) {
                inputProcessorChain.addProcessor(new DecryptInputProcessor(currentEncryptedKeyType, getSecurityProperties()));
                currentEncryptedKeyType = null;
            }
            //probably we can remove this processor from the chain now?
        }

        inputProcessorChain.processEvent(xmlEvent);
    }
}
