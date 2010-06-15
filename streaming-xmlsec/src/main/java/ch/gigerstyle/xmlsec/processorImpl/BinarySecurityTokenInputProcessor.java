package ch.gigerstyle.xmlsec.processorImpl;

import ch.gigerstyle.xmlsec.*;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.BinarySecurityTokenType;

import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.util.HashMap;
import java.util.Map;

/**
 * User: giger
 * Date: May 13, 2010
 * Time: 5:55:30 PM
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
public class BinarySecurityTokenInputProcessor extends AbstractInputProcessor {

    private Map<String, BinarySecurityTokenType> binarySecurityTokens = new HashMap<String, BinarySecurityTokenType>();
    private BinarySecurityTokenType currentBinarySecurityTokenType;

    public BinarySecurityTokenInputProcessor(SecurityProperties securityProperties) {
        super(securityProperties);
    }

    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        
        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            if (startElement.getName().equals(Constants.TAG_wsse_BinarySecurityToken)) {
                currentBinarySecurityTokenType = new BinarySecurityTokenType();

                Attribute encodingType = startElement.getAttributeByName(Constants.ATT_NULL_EncodingType);
                if (encodingType != null) {
                    currentBinarySecurityTokenType.setEncodingType(encodingType.getValue());
                }

                Attribute valueType = startElement.getAttributeByName(Constants.ATT_NULL_ValueType);
                if (valueType != null) {
                    currentBinarySecurityTokenType.setValueType(valueType.getValue());
                }

                Attribute id = startElement.getAttributeByName(Constants.ATT_wsu_Id);
                if (id != null) {
                    currentBinarySecurityTokenType.setId(id.getValue());
                    binarySecurityTokens.put(id.getValue(), currentBinarySecurityTokenType);
                } else {
                    binarySecurityTokens.put(null, currentBinarySecurityTokenType);
                }
            }
            else if (currentBinarySecurityTokenType == null) {
                //do nothing...fall out
            }
        }
        else if (currentBinarySecurityTokenType != null && xmlEvent.isCharacters()) {
            //todo handle multiple character events for same text-node
            Characters characters = xmlEvent.asCharacters();
            if (getLastStartElementName().equals(Constants.TAG_wsse_BinarySecurityToken)) {
                currentBinarySecurityTokenType.setValue(characters.getData());
            }
        }
        else if (currentBinarySecurityTokenType != null && xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();

            if (endElement.getName().equals(Constants.TAG_wsse_BinarySecurityToken)) {
                securityContext.putAsList(BinarySecurityTokenType.class, currentBinarySecurityTokenType);
                currentBinarySecurityTokenType = null;
            }
        }

        inputProcessorChain.processEvent(xmlEvent);
    }
}
