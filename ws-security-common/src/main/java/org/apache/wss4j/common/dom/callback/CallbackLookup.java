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

package org.apache.wss4j.common.dom.callback;

import java.util.List;

import javax.xml.crypto.dom.DOMCryptoContext;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.w3c.dom.Element;

/**
 * This interface defines a pluggable way of locating Elements that are referenced via an Id.
 */
public interface CallbackLookup {

    /**
     * Get the DOM element that corresponds to the given id and ValueType reference. The Id can
     * be a wsu:Id or else an Id attribute, or a SAML Id when the ValueType refers to a SAML
     * Assertion.
     *
     * @param id The id of the element to locate
     * @param valueType The ValueType attribute of the element to locate (can be null)
     * @param checkMultipleElements If true then go through the entire tree and return
     *        null if there are multiple elements with the same Id
     * @return the located element
     * @throws WSSecurityException
     */
    Element getElement(String id, String valueType, boolean checkMultipleElements) throws WSSecurityException;

    /**
     * Get the DOM element that corresponds to the given id and ValueType reference. The Id can
     * be a wsu:Id or else an Id attribute, or a SAML Id when the ValueType refers to a SAML
     * Assertion. The implementation is also responsible to register the retrieved Element on the
     * DOMCryptoContext argument, so that the XML Signature implementation can find the Element.
     *
     * @param id The id of the element to locate
     * @param valueType The ValueType attribute of the element to locate (can be null)
     * @param checkMultipleElements If true then go through the entire tree and return
     *        null if there are multiple elements with the same Id
     * @param context The DOMCryptoContext to store the Element in
     * @return the located element
     * @throws WSSecurityException
     */
    Element getAndRegisterElement(
        String id, String valueType, boolean checkMultipleElements, DOMCryptoContext context
    ) throws WSSecurityException;

    /**
     * Get the DOM element(s) that correspond to the given localname/namespace.
     * @param localname The localname of the Element(s)
     * @param namespace The namespace of the Element(s)
     * @return the located element(s)
     * @throws WSSecurityException
     */
    List<Element> getElements(
        String localname, String namespace
    ) throws WSSecurityException;

    /**
     * Get the SOAP Body
     */
    Element getSOAPBody();
}
