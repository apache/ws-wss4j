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
package org.oasis_open.docs.wss.oasis_wss_wssecurity_secext_1_1;

import org.w3._2001._04.xmlenc_.EncryptedDataType;

import javax.xml.bind.annotation.*;
import javax.xml.bind.annotation.adapters.CollapsedStringAdapter;
import javax.xml.bind.annotation.adapters.XmlJavaTypeAdapter;


/**
 * <p>Java class for EncryptedHeaderType complex type.
 * <p/>
 * <p>The following schema fragment specifies the expected content contained within this class.
 * <p/>
 * <pre>
 * &lt;complexType name="EncryptedHeaderType">
 *   &lt;complexContent>
 *     &lt;restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
 *       &lt;sequence>
 *         &lt;element ref="{http://www.w3.org/2001/04/xmlenc#}EncryptedData"/>
 *       &lt;/sequence>
 *       &lt;attribute ref="{http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd}Id"/>
 *       &lt;attribute ref="{http://schemas.xmlsoap.org/soap/envelope/}mustUnderstand"/>
 *       &lt;attribute ref="{http://schemas.xmlsoap.org/soap/envelope/}actor"/>
 *       &lt;attribute ref="{http://www.w3.org/2003/05/soap-envelope}role"/>
 *       &lt;attribute ref="{http://www.w3.org/2003/05/soap-envelope}relay"/>
 *     &lt;/restriction>
 *   &lt;/complexContent>
 * &lt;/complexType>
 * </pre>
 */
@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "EncryptedHeaderType", namespace = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd", propOrder = {
        "encryptedData"
})
public class EncryptedHeaderType {

    @XmlElement(name = "EncryptedData", namespace = "http://www.w3.org/2001/04/xmlenc#", required = true)
    protected EncryptedDataType encryptedData;
    @XmlAttribute(name = "Id", namespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd")
    @XmlJavaTypeAdapter(CollapsedStringAdapter.class)
    @XmlID
    @XmlSchemaType(name = "ID")
    protected String id;
    @XmlAttribute(namespace = "http://schemas.xmlsoap.org/soap/envelope/")
    protected Boolean mustUnderstand;
    @XmlAttribute(namespace = "http://schemas.xmlsoap.org/soap/envelope/")
    @XmlSchemaType(name = "anyURI")
    protected String actor;
    @XmlAttribute(namespace = "http://www.w3.org/2003/05/soap-envelope")
    @XmlSchemaType(name = "anyURI")
    protected String role;
    @XmlAttribute(namespace = "http://www.w3.org/2003/05/soap-envelope")
    protected Boolean relay;

    /**
     * Gets the value of the encryptedData property.
     *
     * @return possible object is
     *         {@link EncryptedDataType }
     */
    public EncryptedDataType getEncryptedData() {
        return encryptedData;
    }

    /**
     * Sets the value of the encryptedData property.
     *
     * @param value allowed object is
     *              {@link EncryptedDataType }
     */
    public void setEncryptedData(EncryptedDataType value) {
        this.encryptedData = value;
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
     * Gets the value of the mustUnderstand property.
     *
     * @return possible object is
     *         {@link String }
     */
    public Boolean isMustUnderstand() {
        return mustUnderstand;
    }

    /**
     * Sets the value of the mustUnderstand property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setMustUnderstand(Boolean value) {
        this.mustUnderstand = value;
    }

    /**
     * Gets the value of the actor property.
     *
     * @return possible object is
     *         {@link String }
     */
    public String getActor() {
        return actor;
    }

    /**
     * Sets the value of the actor property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setActor(String value) {
        this.actor = value;
    }

    /**
     * Gets the value of the role property.
     *
     * @return possible object is
     *         {@link String }
     */
    public String getRole() {
        return role;
    }

    /**
     * Sets the value of the role property.
     *
     * @param value allowed object is
     *              {@link String }
     */
    public void setRole(String value) {
        this.role = value;
    }

    /**
     * Gets the value of the relay property.
     *
     * @return possible object is
     *         {@link Boolean }
     */
    public boolean isRelay() {
        if (relay == null) {
            return false;
        } else {
            return relay;
        }
    }

    /**
     * Sets the value of the relay property.
     *
     * @param value allowed object is
     *              {@link Boolean }
     */
    public void setRelay(Boolean value) {
        this.relay = value;
    }

}
