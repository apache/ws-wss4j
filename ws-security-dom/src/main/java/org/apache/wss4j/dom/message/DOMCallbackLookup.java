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

package org.apache.wss4j.dom.message;

import java.util.Collections;
import java.util.List;

import javax.xml.crypto.dom.DOMCryptoContext;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * This class uses a DOM-based approach to locate Elements that are referenced via an Id.
 */
public class DOMCallbackLookup implements CallbackLookup {
    
    private Document doc;
    
    public DOMCallbackLookup(Document doc) {
        this.doc = doc;
    }

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
    public Element getElement(
        String id, String valueType, boolean checkMultipleElements
    ) throws WSSecurityException {
        return getAndRegisterElement(id, valueType, checkMultipleElements, null);
    }
    
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
    public Element getAndRegisterElement(
        String id, String valueType, boolean checkMultipleElements, DOMCryptoContext context
    ) throws WSSecurityException {
        String idToMatch = XMLUtils.getIDFromReference(id);
        
        //
        // Try the SOAP Body first
        //
        Element bodyElement = getSOAPBody();
        if (bodyElement != null) {
            String cId = bodyElement.getAttributeNS(WSConstants.WSU_NS, "Id");
            if (cId.equals(idToMatch)) {
                if (context != null) {
                    context.setIdAttributeNS(bodyElement, WSConstants.WSU_NS, "Id");
                }
                return bodyElement;
            }
        }
        // Otherwise do a general search
        Element foundElement = 
            XMLUtils.findElementById(doc.getDocumentElement(), idToMatch, checkMultipleElements);
        if (foundElement != null) {
            if (context != null) {
                if (foundElement.hasAttributeNS(WSConstants.WSU_NS, "Id")
                    && idToMatch.equals(foundElement.getAttributeNS(WSConstants.WSU_NS, "Id"))) {
                    context.setIdAttributeNS(foundElement, WSConstants.WSU_NS, "Id");
                }
                if (foundElement.hasAttributeNS(null, "Id")
                    && idToMatch.equals(foundElement.getAttributeNS(null, "Id"))) {
                    context.setIdAttributeNS(foundElement, null, "Id");
                }
            }
            return foundElement;
        }
        
        //
        // Try to find a SAML Assertion Element if the ValueType corresponds to a SAML Assertion
        // (or is empty)
        //
        if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(valueType) 
            || WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(valueType)
            || "".equals(valueType)
            || valueType == null) {
            foundElement = 
                XMLUtils.findSAMLAssertionElementById(
                    doc.getDocumentElement(), idToMatch
                );
            if (foundElement != null) {
                if (context != null) {
                    if (foundElement.hasAttributeNS(null, "ID")
                        && idToMatch.equals(foundElement.getAttributeNS(null, "ID"))) {
                        context.setIdAttributeNS(foundElement, null, "ID");
                    }
                    if (foundElement.hasAttributeNS(null, "AssertionID")
                        && idToMatch.equals(foundElement.getAttributeNS(null, "AssertionID"))) {
                        context.setIdAttributeNS(foundElement, null, "AssertionID");
                    }
                }
                return foundElement;
            }
        }
        
        return null;
    }
    
    /**
     * Get the DOM element(s) that correspond to the given localname/namespace. 
     * @param localname The localname of the Element(s)
     * @param namespace The namespace of the Element(s)
     * @return the located element(s)
     * @throws WSSecurityException
     */
    public List<Element> getElements(
        String localname, String namespace
    ) throws WSSecurityException {
        //
        // Try the SOAP Body first
        //
        Element bodyElement = getSOAPBody();
        if (WSConstants.ELEM_BODY.equals(localname) &&
            bodyElement.getNamespaceURI().equals(namespace)) {
            return Collections.singletonList(bodyElement);
        }
        return XMLUtils.findElements(doc.getDocumentElement(), localname, namespace);
    }

    
    /**
     * Get the SOAP Body
     */
    public Element getSOAPBody() {
        return WSSecurityUtil.findBodyElement(doc);
    }
}
