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

package org.apache.ws.security.message;

import java.util.Collections;
import java.util.List;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * This class uses a DOM-based approach to locate Elements that are referenced via an Id.
 */
public class DOMCallbackLookup implements CallbackLookup {
    
    protected Document doc;
    
    public DOMCallbackLookup(Document doc) {
        this.doc = doc;
    }

    /**
     * Get the DOM element that corresponds to the given id and ValueType reference. The Id can 
     * be a wsu:Id or else an Id attribute, or a SAML Id when the ValueType refers to a SAML
     * Assertion.
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
        //
        // Try the SOAP Body first
        //
        Element bodyElement = WSSecurityUtil.findBodyElement(doc);
        if (bodyElement != null) {
            String cId = bodyElement.getAttributeNS(WSConstants.WSU_NS, "Id");
            if (cId.equals(id)) {
                 return bodyElement;
            }
        }
        // Otherwise do a general search
        Element foundElement = 
            WSSecurityUtil.findElementById(doc.getDocumentElement(), id, checkMultipleElements);
        if (foundElement != null) {
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
            return 
                WSSecurityUtil.findSAMLAssertionElementById(
                    doc.getDocumentElement(), id
                );
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
        Element bodyElement = WSSecurityUtil.findBodyElement(doc);
        if (WSConstants.ELEM_BODY.equals(localname) &&
            bodyElement.getNamespaceURI().equals(namespace)) {
            return Collections.singletonList(bodyElement);
        }
        return WSSecurityUtil.findElements(doc.getDocumentElement(), localname, namespace);
    }
}
