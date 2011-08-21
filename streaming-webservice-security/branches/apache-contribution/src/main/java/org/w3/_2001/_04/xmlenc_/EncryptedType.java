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
package org.w3._2001._04.xmlenc_;

import org.swssf.ext.Constants;
import org.swssf.ext.ParseException;
import org.swssf.ext.Parseable;
import org.swssf.ext.Utils;
import org.w3._2000._09.xmldsig_.KeyInfoType;

import javax.xml.bind.annotation.*;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.Iterator;


/**
 * <p>Java class for EncryptedType complex type.
 * <p/>
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p/>
 * <pre>
 * &lt;complexType name="EncryptedType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element name="EncryptionMethod" type="{http://www.w3.org/2001/04/xmlenc#}EncryptionMethodType" minOccurs="0"/>
 *         &lt;element ref="{http://www.w3.org/2000/09/xmldsig#}KeyInfo" minOccurs="0"/>
 *         &lt;element ref="{http://www.w3.org/2001/04/xmlenc#}CipherData"/>
 *         &lt;element ref="{http://www.w3.org/2001/04/xmlenc#}EncryptionProperties" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute name="Id" type="{http://www.w3.org/2001/XMLSchema}ID" />
 *       &lt;attribute name="Type" type="{http://www.w3.org/2001/XMLSchema}anyURI" />
 *       &lt;attribute name="MimeType" type="{http://www.w3.org/2001/XMLSchema}string" />
 *       &lt;attribute name="Encoding" type="{http://www.w3.org/2001/XMLSchema}anyURI" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "EncryptedType", propOrder = {
        "encryptionMethod",
        "keyInfo",
        "cipherData",
        "encryptionProperties"
})
@XmlSeeAlso({
        EncryptedKeyType.class,
        EncryptedDataType.class
})
public abstract class EncryptedType implements Parseable {

    private Parseable currentParseable;

    @XmlElement(name = "EncryptionMethod")
    protected EncryptionMethodType encryptionMethod;
    @XmlElement(name = "KeyInfo", namespace = "http://www.w3.org/2000/09/xmldsig#")
    protected KeyInfoType keyInfo;
    @XmlElement(name = "CipherData", required = true)
    protected CipherDataType cipherData;
    @XmlElement(name = "EncryptionProperties")
    protected EncryptionPropertiesType encryptionProperties;
    @XmlAttribute(name = "Id")
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlID
    @XmlSchemaType(name = "ID")
    protected String id;
    @XmlAttribute(name = "Type")
    @XmlSchemaType(name = "anyURI")
    protected String type;
    @XmlAttribute(name = "MimeType")
    protected String mimeType;
    @XmlAttribute(name = "Encoding")
    @XmlSchemaType(name = "anyURI")
    protected String encoding;

    private QName startElementName;

    protected EncryptedType(StartElement startElement) {
        this.startElementName = startElement.getName();

        @SuppressWarnings("unchecked")
        Iterator<Attribute> attributeIterator = startElement.getAttributes();
        while (attributeIterator.hasNext()) {
            Attribute attribute = attributeIterator.next();
            if (attribute.getName().equals(Constants.ATT_NULL_Id)) {
                CollapsedStringAdapter collapsedStringAdapter = new CollapsedStringAdapter();
                this.id = collapsedStringAdapter.unmarshal(attribute.getValue());
            } else if (attribute.getName().equals(Constants.ATT_NULL_Type)) {
                this.type = attribute.getValue();
            } else if (attribute.getName().equals(Constants.ATT_NULL_MimeType)) {
                this.mimeType = attribute.getValue();
            } else if (attribute.getName().equals(Constants.ATT_NULL_Encoding)) {
                this.encoding = attribute.getValue();
            }
        }
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

                if (startElement.getName().equals(Constants.TAG_xenc_EncryptionMethod)) {
                    currentParseable = this.encryptionMethod = new EncryptionMethodType(startElement);
                } else if (startElement.getName().equals(Constants.TAG_dsig_KeyInfo)) {
                    currentParseable = this.keyInfo = new KeyInfoType(startElement);
                } else if (startElement.getName().equals(Constants.TAG_xenc_CipherData)) {
                    currentParseable = this.cipherData = new CipherDataType(startElement);
                } else if (startElement.getName().equals(Constants.TAG_xenc_EncryptionProperties)) {
                    //currentParseable = this.encryptionProperties = new EncryptionPropertiesType();
                    currentParseable = new Parseable() {
                        public boolean parseXMLEvent(XMLEvent xmlEvent) throws ParseException {
                            switch (xmlEvent.getEventType()) {
                                case XMLStreamConstants.END_ELEMENT:
                                    EndElement endElement = xmlEvent.asEndElement();
                                    if (endElement.getName().equals(Constants.TAG_xenc_EncryptionProperties)) {
                                        return true;
                                    }
                                    break;
                            }
                            return false;
                        }

                        public void validate() throws ParseException {
                        }
                    };
                }
                break;
            case XMLStreamConstants.END_ELEMENT:

                currentParseable = null;
                EndElement endElement = xmlEvent.asEndElement();

                if (endElement.getName().equals(startElementName)) {
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
        if (cipherData == null) {
            throw new ParseException("Element \"CipherData\" is missing");
        }
    }

    /**
     * Gets the value of the encryptionMethod property.
     *
     * @return possible object is
     *         {@link EncryptionMethodType }
     */
    public EncryptionMethodType getEncryptionMethod() {
        return encryptionMethod;
    }

    /**
     * Sets the value of the encryptionMethod property.
     *
     * @param value allowed object is
     *              {@link EncryptionMethodType }
     */
    public void setEncryptionMethod(EncryptionMethodType value) {
        this.encryptionMethod = value;
    }

    /**
     * Gets the value of the keyInfo property.
     *
     * @return possible object is
     *         {@link KeyInfoType }
     */
    public KeyInfoType getKeyInfo() {
        return keyInfo;
    }

    /**
     * Sets the value of the keyInfo property.
     *
     * @param value allowed object is
     *              {@link KeyInfoType }
     */
    public void setKeyInfo(KeyInfoType value) {
        this.keyInfo = value;
    }

    /**
     * Gets the value of the cipherData property.
     *
     * @return possible object is
     *         {@link CipherDataType }
     */
    public CipherDataType getCipherData() {
        return cipherData;
    }

    /**
     * Sets the value of the cipherData property.
     *
     * @param value allowed object is
     *              {@link CipherDataType }
     */
    public void setCipherData(CipherDataType value) {
        this.cipherData = value;
    }

    /**
     * Gets the value of the encryptionProperties property.
     *
     * @return possible object is
     *         {@link EncryptionPropertiesType }
     */
    public EncryptionPropertiesType getEncryptionProperties() {
        return encryptionProperties;
    }

    /**
     * Sets the value of the encryptionProperties property.
     *
     * @param value allowed object is
     *              {@link EncryptionPropertiesType }
     */
    public void setEncryptionProperties(EncryptionPropertiesType value) {
        this.encryptionProperties = value;
    }

    /**
     * Gets the value of the id property.
     *
     * @return possible object is
     *         {@link String }
     */
    public String getId() {
        return id;
    }

    /**
     * Sets the value of the id property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setId(String value) {
        this.id = value;
    }

    /**
     * Gets the value of the type property.
     *
     * @return possible object is
     *         {@link String }
     */
    public String getType() {
        return type;
    }

    /**
     * Sets the value of the type property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setType(String value) {
        this.type = value;
    }

    /**
     * Gets the value of the mimeType property.
     *
     * @return possible object is
     *         {@link String }
     */
    public String getMimeType() {
        return mimeType;
    }

    /**
     * Sets the value of the mimeType property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setMimeType(String value) {
        this.mimeType = value;
    }

    /**
     * Gets the value of the encoding property.
     *
     * @return possible object is
     *         {@link String }
     */
    public String getEncoding() {
        return encoding;
    }

    /**
     * Sets the value of the encoding property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setEncoding(String value) {
        this.encoding = value;
    }
}
