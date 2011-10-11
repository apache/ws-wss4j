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


package org.oasis_open.docs.ws_sx.ws_secureconversation._200512;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityTokenReferenceType;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSUtils;
import org.swssf.xmlsec.ext.ParseException;
import org.swssf.xmlsec.ext.Parseable;

import javax.xml.bind.annotation.*;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.math.BigInteger;
import java.util.Iterator;


/**
 * <p>Java class for DerivedKeyTokenType complex type.
 * <p/>
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p/>
 * <pre>
 * &lt;complexType name="DerivedKeyTokenType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd}SecurityTokenReference" minOccurs="0"/>
 *         &lt;element name="Properties" type="{http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512}PropertiesType" minOccurs="0"/>
 *         &lt;sequence minOccurs="0">
 *           &lt;choice>
 *             &lt;element name="Generation" type="{http://www.w3.org/2001/XMLSchema}unsignedLong"/>
 *             &lt;element name="Offset" type="{http://www.w3.org/2001/XMLSchema}unsignedLong"/>
 *           &lt;/choice>
 *           &lt;element name="Length" type="{http://www.w3.org/2001/XMLSchema}unsignedLong" minOccurs="0"/>
 *         &lt;/sequence>
 *         &lt;element ref="{http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512}Label" minOccurs="0"/>
 *         &lt;element ref="{http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512}Nonce" minOccurs="0"/>
 *       &lt;/sequence>
 *       &lt;attribute ref="{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Id"/>
 *       &lt;attribute name="Algorithm" type="{http://www.w3.org/2001/XMLSchema}anyURI" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "DerivedKeyTokenType", propOrder = {
        "securityTokenReference",
        "properties",
        "generation",
        "offset",
        "length",
        "label",
        "nonce"
})
public class DerivedKeyTokenType implements Parseable {

    @XmlElement(name = "SecurityTokenReference", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd")
    protected SecurityTokenReferenceType securityTokenReference;
    @XmlElement(name = "Properties")
    protected PropertiesType properties;
    @XmlElement(name = "Generation")
    @XmlSchemaType(name = "unsignedLong")
    protected BigInteger generation;
    @XmlElement(name = "Offset")
    @XmlSchemaType(name = "unsignedLong")
    protected int offset;
    @XmlElement(name = "Length")
    @XmlSchemaType(name = "unsignedLong")
    protected int length;
    @XmlElement(name = "Label")
    protected String label;
    @XmlElement(name = "Nonce")
    protected byte[] nonce;
    @XmlAttribute(name = "Id", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlID
    @XmlSchemaType(name = "ID")
    protected String id;
    @XmlAttribute(name = "Algorithm")
    @XmlSchemaType(name = "anyURI")
    protected String algorithm;

    private Parseable currentParseable;
    private StartElement startElement;

    public DerivedKeyTokenType(StartElement startElement) {
        this.startElement = startElement;
        @SuppressWarnings("unchecked")
        Iterator<Attribute> attributeIterator = startElement.getAttributes();
        while (attributeIterator.hasNext()) {
            Attribute attribute = attributeIterator.next();
            if (attribute.getName().equals(WSSConstants.ATT_wsu_Id)) {
                this.id = attribute.getValue();
            } else if (attribute.getName().equals(WSSConstants.ATT_NULL_Algorithm)) {
                this.algorithm = attribute.getValue();
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

                if (startElement.getName().equals(WSSConstants.TAG_wsse_SecurityTokenReference)) {
                    currentParseable = securityTokenReference = new SecurityTokenReferenceType(startElement);
                } else if (startElement.getName().getLocalPart().equals(WSSConstants.TAG_wsc0502_Properties.getLocalPart())) {
                    currentParseable = properties = new PropertiesType(startElement);
                } else if (startElement.getName().getLocalPart().equals(WSSConstants.TAG_wsc0502_Generation.getLocalPart())) {
                    currentParseable = new Parseable() {
                        public boolean parseXMLEvent(XMLEvent xmlEvent) throws ParseException {
                            switch (xmlEvent.getEventType()) {
                                case XMLStreamConstants.START_ELEMENT:
                                    StartElement startElement = xmlEvent.asStartElement();
                                    throw new ParseException("Unsupported Element: " + startElement.getName());
                                case XMLStreamConstants.END_ELEMENT:
                                    return true;
                                case XMLStreamConstants.CHARACTERS:
                                    generation = new BigInteger(xmlEvent.asCharacters().getData());
                                    break;
                            }
                            return false;
                        }

                        public void validate() throws ParseException {
                        }
                    };
                } else if (startElement.getName().getLocalPart().equals(WSSConstants.TAG_wsc0502_Offset.getLocalPart())) {
                    currentParseable = new Parseable() {
                        public boolean parseXMLEvent(XMLEvent xmlEvent) throws ParseException {
                            switch (xmlEvent.getEventType()) {
                                case XMLStreamConstants.START_ELEMENT:
                                    StartElement startElement = xmlEvent.asStartElement();
                                    throw new ParseException("Unsupported Element: " + startElement.getName());
                                case XMLStreamConstants.END_ELEMENT:
                                    return true;
                                case XMLStreamConstants.CHARACTERS:
                                    offset = Integer.parseInt(xmlEvent.asCharacters().getData());
                                    break;
                            }
                            return false;
                        }

                        public void validate() throws ParseException {
                        }
                    };
                } else if (startElement.getName().getLocalPart().equals(WSSConstants.TAG_wsc0502_Length.getLocalPart())) {
                    currentParseable = new Parseable() {
                        public boolean parseXMLEvent(XMLEvent xmlEvent) throws ParseException {
                            switch (xmlEvent.getEventType()) {
                                case XMLStreamConstants.START_ELEMENT:
                                    StartElement startElement = xmlEvent.asStartElement();
                                    throw new ParseException("Unsupported Element: " + startElement.getName());
                                case XMLStreamConstants.END_ELEMENT:
                                    return true;
                                case XMLStreamConstants.CHARACTERS:
                                    length = Integer.parseInt(xmlEvent.asCharacters().getData());
                                    break;
                            }
                            return false;
                        }

                        public void validate() throws ParseException {
                        }
                    };
                } else if (startElement.getName().getLocalPart().equals(WSSConstants.TAG_wsc0502_Label.getLocalPart())) {
                    currentParseable = new Parseable() {
                        public boolean parseXMLEvent(XMLEvent xmlEvent) throws ParseException {
                            switch (xmlEvent.getEventType()) {
                                case XMLStreamConstants.START_ELEMENT:
                                    StartElement startElement = xmlEvent.asStartElement();
                                    throw new ParseException("Unsupported Element: " + startElement.getName());
                                case XMLStreamConstants.END_ELEMENT:
                                    return true;
                                case XMLStreamConstants.CHARACTERS:
                                    label = xmlEvent.asCharacters().getData();
                                    break;
                            }
                            return false;
                        }

                        public void validate() throws ParseException {
                        }
                    };
                } else if (startElement.getName().getLocalPart().equals(WSSConstants.TAG_wsc0502_Nonce.getLocalPart())) {
                    currentParseable = new Parseable() {
                        public boolean parseXMLEvent(XMLEvent xmlEvent) throws ParseException {
                            switch (xmlEvent.getEventType()) {
                                case XMLStreamConstants.START_ELEMENT:
                                    StartElement startElement = xmlEvent.asStartElement();
                                    throw new ParseException("Unsupported Element: " + startElement.getName());
                                case XMLStreamConstants.END_ELEMENT:
                                    return true;
                                case XMLStreamConstants.CHARACTERS:
                                    nonce = xmlEvent.asCharacters().getData().getBytes();
                                    break;
                            }
                            return false;
                        }

                        public void validate() throws ParseException {
                        }
                    };
                } else {
                    throw new ParseException("Unsupported Element: " + startElement.getName());
                }

                break;
            case XMLStreamConstants.END_ELEMENT:
                currentParseable = null;
                EndElement endElement = xmlEvent.asEndElement();
                if (endElement.getName().getLocalPart().equals(WSSConstants.TAG_wsc0502_DerivedKeyToken.getLocalPart())) {
                    return true;
                }
                break;
            default:
                throw new ParseException("Unexpected event received " + WSSUtils.getXMLEventAsString(xmlEvent));
        }
        return false;
    }

    public void validate() throws ParseException {
    }

    /**
     * Gets the value of the securityTokenReference property.
     *
     * @return possible object is
     *         {@link SecurityTokenReferenceType }
     */
    public SecurityTokenReferenceType getSecurityTokenReference() {
        return securityTokenReference;
    }

    /**
     * Sets the value of the securityTokenReference property.
     *
     * @param value allowed object is
     *              {@link SecurityTokenReferenceType }
     */
    public void setSecurityTokenReference(SecurityTokenReferenceType value) {
        this.securityTokenReference = value;
    }

    /**
     * Gets the value of the properties property.
     *
     * @return possible object is
     *         {@link PropertiesType }
     */
    public PropertiesType getProperties() {
        return properties;
    }

    /**
     * Sets the value of the properties property.
     *
     * @param value allowed object is
     *              {@link PropertiesType }
     */
    public void setProperties(PropertiesType value) {
        this.properties = value;
    }

    /**
     * Gets the value of the generation property.
     *
     * @return possible object is
     *         {@link BigInteger }
     */
    public BigInteger getGeneration() {
        return generation;
    }

    /**
     * Sets the value of the generation property.
     *
     * @param value allowed object is
     *              {@link BigInteger }
     */
    public void setGeneration(BigInteger value) {
        this.generation = value;
    }

    /**
     * Gets the value of the offset property.
     *
     * @return possible object is
     *         {@link BigInteger }
     */
    public int getOffset() {
        return offset;
    }

    /**
     * Sets the value of the offset property.
     *
     * @param value allowed object is
     *              {@link BigInteger }
     */
    public void setOffset(int value) {
        this.offset = value;
    }

    /**
     * Gets the value of the length property.
     *
     * @return possible object is
     *         {@link BigInteger }
     */
    public int getLength() {
        return length;
    }

    /**
     * Sets the value of the length property.
     *
     * @param value allowed object is
     *              {@link BigInteger }
     */
    public void setLength(int value) {
        this.length = value;
    }

    /**
     * Gets the value of the label property.
     *
     * @return possible object is
     *         {@link String }
     */
    public String getLabel() {
        return label;
    }

    /**
     * Sets the value of the label property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setLabel(String value) {
        this.label = value;
    }

    /**
     * Gets the value of the nonce property.
     *
     * @return possible object is
     *         byte[]
     */
    public byte[] getNonce() {
        return nonce;
    }

    /**
     * Sets the value of the nonce property.
     *
     * @param value allowed object is
     *              byte[]
     */
    public void setNonce(byte[] value) {
        this.nonce = value;
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
     * Gets the value of the algorithm property.
     *
     * @return possible object is
     *         {@link String }
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Sets the value of the algorithm property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setAlgorithm(String value) {
        this.algorithm = value;
    }

}
