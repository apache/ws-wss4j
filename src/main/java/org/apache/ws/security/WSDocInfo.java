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

package org.apache.ws.security;

/**
 * WSDocInfo holds information about the document to process. It provides a 
 * method to store and access document information about BinarySecurityToken, 
 * used Crypto, and others.
 * 
 * Using the Document's hash a caller can identify a document and get
 * the stored information that me be necessary to process the document.
 * The main usage for this is (are) the transformation functions that
 * are called during Signature/Verification process. 
 * 
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 */

import org.apache.ws.security.components.crypto.Crypto;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.ArrayList;
import java.util.List;

public class WSDocInfo {
    Document doc = null;
    Crypto crypto = null;
    List<Element> tokenList = null;
    List<Element> elementList = null;
    List<WSSecurityEngineResult> resultsList = null;

    public WSDocInfo(Document doc) {
        //
        // This is a bit of a hack. When the Document is a SAAJ SOAPPart instance, it may
        // be that the "owner" document of any child elements is an internal Document, rather
        // than the SOAPPart. This is the case for the SUN SAAJ implementation.
        //
        this.doc = doc.getDocumentElement().getOwnerDocument();
    }
    
    /**
     * Clears the data stored in this object
     */
    public void clear() {
        crypto = null;
        if (tokenList != null && tokenList.size() > 0) {
            tokenList.clear();
        }
        if (elementList != null && elementList.size() > 0) {
            elementList.clear();
        }
        if (resultsList != null && resultsList.size() > 0) {
            resultsList.clear();
        }
        
        tokenList = null;
        elementList = null;
        resultsList = null;
    }
    
    /**
     * Store a token element for later retrieval. The token element is one of:
     *  - SecurityTokenReference element
     *  - BinarySecurityToken element
     *  - SAML Assertion element
     *  - SecurityContextToken element
     *  - UsernameToken element
     *  - DerivedKeyToken element
     *  - Timestamp element
     * @param elem is the token element to store
     */
    public void addTokenElement(Element elem) {
        if (tokenList == null) {
            tokenList = new ArrayList<Element>();
        }
        tokenList.add(elem);
    }
    
    /**
     * Get a token Element for the given Id. The Id can be either a wsu:Id or a 
     * SAML AssertionID/ID.
     * TODO think about if it is better to restrict the default Id to wsu:Id?
     * @param uri is the (relative) uri of the id
     * @return the token element or null if nothing found
     */
    public Element getTokenElement(String uri) {
        String id = uri;
        if (id == null) {
            return null;
        } else if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        if (tokenList != null) {
            for (Element elem : tokenList) {
                String cId = elem.getAttributeNS(WSConstants.WSU_NS, "Id");
                String samlId = elem.getAttribute("AssertionID");
                String samlId2 = elem.getAttribute("ID");
                if (id.equals(cId) || id.equals(samlId) || id.equals(samlId2)) {
                    return elem;
                }
            }
        }
        return null;
    }
    
    /**
     * Store a protection element for later retrieval. 
     * @param element is the protection element to store
     */
    public void addProtectionElement(Element element) {
        if (elementList == null) {
            elementList = new ArrayList<Element>();
        }
        elementList.add(element);
    }
    
    /**
     * Get a protection element for the given (wsu) Id.
     * @param uri is the (relative) uri of the id
     * @return the protection element or null if nothing found
     */
    public Element getProtectionElement(String uri) {
        String id = uri;
        if (id == null) {
            return null;
        } else if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        if (elementList != null) {
            for (Element element : elementList) {
                if (element != null) {
                    String cId = element.getAttributeNS(WSConstants.WSU_NS, "Id");
                    if (id.equals(cId)) {
                        return element;
                    }
                }
            }
        }
        return null;
    }
    
    /**
     * Store a WSSecurityEngineResult for later retrieval. 
     * @param result is the WSSecurityEngineResult to store
     */
    public void addResult(WSSecurityEngineResult result) {
        if (resultsList == null) {
            resultsList = new ArrayList<WSSecurityEngineResult>();
        }
        resultsList.add(result);
    }
    
    /**
     * Get a WSSecurityEngineResult for the given Id.
     * @param uri is the (relative) uri of the id
     * @return the WSSecurityEngineResult or null if nothing found
     */
    public WSSecurityEngineResult getResult(String uri) {
        String id = uri;
        if (id == null) {
            return null;
        } else if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        if (resultsList != null) {
            for (WSSecurityEngineResult result : resultsList) {
                if (result != null) {
                    String cId = (String)result.get(WSSecurityEngineResult.TAG_ID);
                    if (id.equals(cId)) {
                        return result;
                    }
                }
            }
        }
        return null;
    }

    /**
     * @return the signature crypto class used to process
     *         the signature/verify
     */
    public Crypto getCrypto() {
        return crypto;
    }

    /**
     * @return the document
     */
    public Document getDocument() {
        return doc;
    }

    /**
     * @param crypto is the signature crypto class used to
     *               process signature/verify
     */
    public void setCrypto(Crypto crypto) {
        this.crypto = crypto;
    }

}
