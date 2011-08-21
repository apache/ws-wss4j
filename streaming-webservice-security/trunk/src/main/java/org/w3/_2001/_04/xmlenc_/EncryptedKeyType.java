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

import javax.xml.bind.annotation.*;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;


/**
 * <p>Java class for EncryptedKeyType complex type.
 * <p/>
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p/>
 * <pre>
 * &lt;complexType name="EncryptedKeyType">
 *   &lt;complexContent>
 *     &lt;extension base="{http://www.w3.org/2001/04/xmlenc#}EncryptedType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2001/04/xmlenc#}ReferenceList" minOccurs="0"/>
 *         &lt;element name="CarriedKeyName" type="{http://www.w3.org/2001/XMLSchema}string" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="Recipient" type="{http://www.w3.org/2001/XMLSchema}string" />
 *     &lt;/extension>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "EncryptedKeyType", propOrder = {
        "referenceList",
        "carriedKeyName"
})
public class EncryptedKeyType
        extends EncryptedType implements Parseable {

    private Parseable currentParseable;

    @XmlElement(name = "ReferenceList")
    protected ReferenceList referenceList;
    @XmlElement(name = "CarriedKeyName")
    protected String carriedKeyName;
    @XmlAttribute(name = "Recipient")
    protected String recipient;

    private boolean isChildFinished = false;

    public EncryptedKeyType(StartElement startElement) {
        super(startElement);
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

        if (!isChildFinished) {
            isChildFinished = super.parseXMLEvent(xmlEvent);
        }

        switch (xmlEvent.getEventType()) {
            case XMLStreamConstants.START_ELEMENT:
                StartElement startElement = xmlEvent.asStartElement();

                if (startElement.getName().equals(Constants.TAG_xenc_ReferenceList)) {
                    currentParseable = this.referenceList = new ReferenceList(startElement);
                }
                break;
            case XMLStreamConstants.END_ELEMENT:
                currentParseable = null;
                EndElement endElement = xmlEvent.asEndElement();
                if (endElement.getName().equals(Constants.TAG_xenc_EncryptedKey)) {
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
        //ReferenceList is optional (can be outside of EncryptedKey -> child element of wsse:Security
    }

    /**
     * Gets the value of the referenceList property.
     *
     * @return possible object is
     *         {@link ReferenceList }
     */
    public ReferenceList getReferenceList() {
        return referenceList;
    }

    /**
     * Sets the value of the referenceList property.
     *
     * @param value allowed object is
     *              {@link ReferenceList }
     */
    public void setReferenceList(ReferenceList value) {
        this.referenceList = value;
    }

    /**
     * Gets the value of the carriedKeyName property.
     *
     * @return possible object is
     *         {@link String }
     */
    public String getCarriedKeyName() {
        return carriedKeyName;
    }

    /**
     * Sets the value of the carriedKeyName property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setCarriedKeyName(String value) {
        this.carriedKeyName = value;
    }

    /**
     * Gets the value of the recipient property.
     *
     * @return possible object is
     *         {@link String }
     */
    public String getRecipient() {
        return recipient;
    }

    /**
     * Sets the value of the recipient property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setRecipient(String value) {
        this.recipient = value;
    }

}
