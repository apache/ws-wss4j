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
//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.6
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a>
// Any modifications to this file will be lost upon recompilation of the source schema.
// Generated on: 2014.03.27 at 03:31:22 PM GMT
//


package org.apache.wss4j.binding.wss11;

import jakarta.xml.bind.JAXBElement;
import jakarta.xml.bind.annotation.XmlElementDecl;
import jakarta.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each
 * Java content interface and Java element interface
 * generated in the org.apache.wss4j.binding.wss11 package.
 * <p>An ObjectFactory allows you to programatically
 * construct new instances of the Java representation
 * for XML content. The Java representation of XML
 * content can consist of schema derived interfaces
 * and classes representing the binding of schema
 * type definitions, element declarations and model
 * groups.  Factory methods for each of these are
 * provided in this class.
 *
 */
@XmlRegistry
public class ObjectFactory {

    private static final String WSSE11_NS = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";
    private static final QName _EncryptedHeader_QNAME = new QName(WSSE11_NS, "EncryptedHeader");
    private static final QName _SignatureConfirmation_QNAME = new QName(WSSE11_NS, "SignatureConfirmation");
    private static final QName _Salt_QNAME = new QName(WSSE11_NS, "Salt");
    private static final QName _Iteration_QNAME = new QName(WSSE11_NS, "Iteration");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: org.apache.wss4j.binding.wss11
     *
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link SignatureConfirmationType }
     *
     */
    public SignatureConfirmationType createSignatureConfirmationType() {
        return new SignatureConfirmationType();
    }

    /**
     * Create an instance of {@link EncryptedHeaderType }
     *
     */
    public EncryptedHeaderType createEncryptedHeaderType() {
        return new EncryptedHeaderType();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link EncryptedHeaderType }{@code >}}
     *
     */
    @XmlElementDecl(namespace = WSSE11_NS, name = "EncryptedHeader")
    public JAXBElement<EncryptedHeaderType> createEncryptedHeader(EncryptedHeaderType value) {
        return new JAXBElement<EncryptedHeaderType>(_EncryptedHeader_QNAME, EncryptedHeaderType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link SignatureConfirmationType }{@code >}}
     *
     */
    @XmlElementDecl(namespace = WSSE11_NS, name = "SignatureConfirmation")
    public JAXBElement<SignatureConfirmationType> createSignatureConfirmation(SignatureConfirmationType value) {
        return new JAXBElement<SignatureConfirmationType>(_SignatureConfirmation_QNAME, SignatureConfirmationType.class, null, value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link byte[]}{@code >}}
     *
     */
    @XmlElementDecl(namespace = WSSE11_NS, name = "Salt")
    public JAXBElement<byte[]> createSalt(byte[] value) {
        return new JAXBElement<byte[]>(_Salt_QNAME, byte[].class, null, (byte[]) value);
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link Long }{@code >}}
     *
     */
    @XmlElementDecl(namespace = WSSE11_NS, name = "Iteration")
    public JAXBElement<Long> createIteration(Long value) {
        return new JAXBElement<Long>(_Iteration_QNAME, Long.class, null, value);
    }

}
