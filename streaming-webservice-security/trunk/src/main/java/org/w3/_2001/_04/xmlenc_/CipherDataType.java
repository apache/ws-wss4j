/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.w3._2001._04.xmlenc_;

import org.swssf.ext.Constants;
import org.swssf.ext.ParseException;
import org.swssf.ext.Parseable;
import org.swssf.ext.Utils;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlType;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.Arrays;


/**
 * <p>Java class for CipherDataType complex type.
 * <p/>
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p/>
 * <pre>
 * &lt;complexType name="CipherDataType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;choice>
 *         &lt;element name="CipherValue" type="{http://www.w3.org/2001/XMLSchema}base64Binary"/>
 *         &lt;element ref="{http://www.w3.org/2001/04/xmlenc#}CipherReference"/>
 *       &lt;/choice>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "CipherDataType", propOrder = {
        "cipherValue",
        "cipherReference"
})
public class CipherDataType implements Parseable {

    private Parseable currentParseable;

    @XmlElement(name = "CipherValue")
    protected StringBuffer cipherValue = new StringBuffer();
    @XmlElement(name = "CipherReference")
    protected CipherReferenceType cipherReference;

    public CipherDataType(StartElement startElement) {
    }


    public boolean parseXMLEvent(XMLEvent xmlEvent) throws ParseException {
        if (currentParseable != null) {
            boolean finished = currentParseable.parseXMLEvent(xmlEvent);
            if (finished) {
                currentParseable.validate();
                currentParseable = null;
            }
            return false;
        }

        switch (xmlEvent.getEventType()) {
            case XMLStreamConstants.START_ELEMENT:
                StartElement startElement = xmlEvent.asStartElement();

                if (startElement.getName().equals(Constants.TAG_xenc_CipherValue)) {
                    currentParseable = new Parseable() {
                        public boolean parseXMLEvent(XMLEvent xmlEvent) throws ParseException {
                            switch (xmlEvent.getEventType()) {
                                case XMLStreamConstants.START_ELEMENT:
                                    StartElement startElement = xmlEvent.asStartElement();
                                    if (!startElement.getName().equals(Constants.TAG_xenc_CipherValue)) {
                                        throw new ParseException("Unsupported Element " + startElement.getName());
                                    }
                                    break;
                                case XMLStreamConstants.END_ELEMENT:
                                    EndElement endElement = xmlEvent.asEndElement();
                                    if (endElement.getName().equals(Constants.TAG_xenc_CipherValue)) {
                                        return true;
                                    }
                                    break;
                                case XMLStreamConstants.CHARACTERS:
                                    cipherValue.append(xmlEvent.asCharacters().getData());
                                    break;
                                default:
                                    throw new ParseException("Unexpected event received " + Utils.getXMLEventAsString(xmlEvent));
                            }
                            return false;
                        }

                        public void validate() throws ParseException {
                            /*
                            if (cipherValue == null) {
                                throw new ParseException("CipherValue is missing");
                            }
                            */
                        }
                    };
                } else {
                    throw new ParseException("Unsupported Element: " + startElement.getName());
                }

                break;
            case XMLStreamConstants.END_ELEMENT:
                currentParseable = null;
                EndElement endElement = xmlEvent.asEndElement();
                if (endElement.getName().equals(Constants.TAG_xenc_CipherData)) {
                    return true;
                }
                break;
            //possible ignorable withespace and comments
            case XMLStreamConstants.CHARACTERS:
            case XMLStreamConstants.COMMENT:
                break;
            default:
                throw new ParseException("Unexpected event received " + Utils.getXMLEventAsString(xmlEvent));
        }
        return false;
    }

    public void validate() throws ParseException {
        //cipherValue can/must be null for decryptionProcessor
        /*
        if (cipherValue == null) {
            throw new ParseException("CipherValue is missing");
        }
        */
    }

    /**
     * Gets the value of the cipherValue property.
     *
     * @return possible object is
     *         byte[]
     */
    public byte[] getCipherValue() {
        return cipherValue.toString().getBytes();
    }

    /**
     * Sets the value of the cipherValue property.
     *
     * @param value allowed object is
     *              byte[]
     */
    public void setCipherValue(byte[] value) {
        this.cipherValue.append(Arrays.toString(value));
    }

    /**
     * Gets the value of the cipherReference property.
     *
     * @return possible object is
     *         {@link CipherReferenceType }
     */
    public CipherReferenceType getCipherReference() {
        return cipherReference;
    }

    /**
     * Sets the value of the cipherReference property.
     *
     * @param value allowed object is
     *              {@link CipherReferenceType }
     */
    public void setCipherReference(CipherReferenceType value) {
        this.cipherReference = value;
    }

}
