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
package org.w3._2000._09.xmldsig_;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.TransformationParametersType;
import org.swssf.ext.Constants;
import org.swssf.ext.ParseException;
import org.swssf.ext.Parseable;
import org.swssf.ext.Utils;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.*;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;


/**
 * <p>Java class for TransformType complex type.
 * <p/>
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p/>
 * <pre>
 * &lt;complexType name="TransformType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;choice maxOccurs="unbounded" minOccurs="0">
 *         &lt;any processContents='lax' namespace='##other'/>
 *         &lt;element name="XPath" type="{http://www.w3.org/2001/XMLSchema}string"/>
 *       &lt;/choice>
 *       &lt;attribute name="Algorithm" use="required" type="{http://www.w3.org/2001/XMLSchema}anyURI" />
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "TransformType", propOrder = {
        "content"
})
public class TransformType implements Parseable {

    @XmlElementRef(name = "XPath", namespace = "http://www.w3.org/2000/09/xmldsig#", type = JAXBElement.class)
    @XmlMixed
    @XmlAnyElement(lax = true)
    protected List<Object> content;
    @XmlAttribute(name = "Algorithm", required = true)
    @XmlSchemaType(name = "anyURI")
    protected String algorithm;
    protected String inclusiveNamespaces;
    protected TransformationParametersType transformationParametersType;

    private Parseable currentParseable;

    public TransformType(StartElement startElement) {
        @SuppressWarnings("unchecked")
        Iterator<Attribute> attributeIterator = startElement.getAttributes();
        while (attributeIterator.hasNext()) {
            Attribute attribute = attributeIterator.next();
            if (attribute.getName().equals(Constants.ATT_NULL_Algorithm)) {
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
                if (startElement.getName().equals(Constants.TAG_c14nExcl_InclusiveNamespaces)) {
                    Attribute attribute = startElement.getAttributeByName(Constants.ATT_NULL_PrefixList);
                    if (attribute != null) {
                        inclusiveNamespaces = attribute.getValue();
                    }
                    currentParseable = new Parseable() {
                        public boolean parseXMLEvent(XMLEvent xmlEvent) throws ParseException {
                            switch (xmlEvent.getEventType()) {
                                case XMLStreamConstants.START_ELEMENT:
                                    StartElement startElement = xmlEvent.asStartElement();
                                    throw new ParseException("Unsupported Element: " + startElement.getName());
                                case XMLStreamConstants.END_ELEMENT:
                                    return true;
                                case XMLStreamConstants.CHARACTERS:
                                    break;
                            }
                            return false;
                        }

                        public void validate() throws ParseException {
                        }
                    };
                } else if (startElement.getName().equals(Constants.TAG_wsse_TransformationParameters)) {
                    currentParseable = transformationParametersType = new TransformationParametersType(startElement);
                } else {
                    throw new ParseException("Unsupported Element: " + startElement.getName());
                }
                break;
            case XMLStreamConstants.END_ELEMENT:
                currentParseable = null;
                EndElement endElement = xmlEvent.asEndElement();
                if (endElement.getName().equals(Constants.TAG_dsig_Transform)) {
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
        if (algorithm == null) {
            throw new ParseException("Attribute \"Algorithm\" is missing");
        }
    }

    /**
     * Gets the value of the content property.
     * <p/>
     * <p/>
     * This accessor method returns a reference to the live list,
     * not a snapshot. Therefore any modification you make to the
     * returned list will be present inside the JAXB object.
     * This is why there is not a <CODE>set</CODE> method for the content property.
     * <p/>
     * <p/>
     * For example, to add a new item, do as follows:
     * <pre>
     *    getContent().add(newItem);
     * </pre>
     * <p/>
     * <p/>
     * <p/>
     * Objects of the following type(s) are allowed in the list
     * {@link Element }
     * {@link Object }
     * {@link String }
     * {@link JAXBElement }{@code <}{@link String }{@code >}
     */
    public List<Object> getContent() {
        if (content == null) {
            content = new ArrayList<Object>();
        }
        return this.content;
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

    public String getInclusiveNamespaces() {
        return inclusiveNamespaces;
    }

    public void setInclusiveNamespaces(String inclusiveNamespaces) {
        this.inclusiveNamespaces = inclusiveNamespaces;
    }

    public TransformationParametersType getTransformationParametersType() {
        return transformationParametersType;
    }
}
