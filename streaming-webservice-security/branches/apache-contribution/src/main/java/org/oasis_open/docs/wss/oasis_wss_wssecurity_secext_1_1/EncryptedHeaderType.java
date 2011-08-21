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
