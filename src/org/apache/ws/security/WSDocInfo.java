/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security;

/**
 * WSDocInfo holds information about the document to process. Together
 * with the WSDocInfoStore it provides a method to store and access document
 * information about BinarySecurityToken, used Crypto, and others.
 * </p>
 * Using the Document's hash a caller can identify a document and get
 * the stored information that me be necessary to process the document.
 * The main usage for this is (are) the transformation functions that
 * are called during Signature/Verfication process. 
 * 
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 *
 */

import org.apache.ws.security.components.crypto.Crypto;
import org.w3c.dom.Element;

import java.util.Enumeration;
import java.util.Vector;

public class WSDocInfo {
    int hash;
    Crypto crypto = null;
    Vector bst = null;
    Element assertion = null;

    public WSDocInfo(int hash) {
        this.hash = hash;
    }

    /**
     * Clears the info data except the hash code
     */
    public void clear() {
        crypto = null;
        assertion = null;
        if (bst != null && bst.size() > 0) {
            bst.removeAllElements();
        }
        bst = null;
    }

    /**
     * Get a BinarySecurityToken for the given Id
     *
     * @param uri is the relative uri (starts with #) of the id
     * @return the BST element or null if nothing found
     */
    public Element getBst(String uri) {
        String id = uri.substring(1);
        Element elem = null;

        if (bst != null) {
            for (Enumeration e = bst.elements(); e.hasMoreElements();) {
                elem = (Element) e.nextElement();
                String cId = elem.getAttribute("Id");
                if (id.equals(cId)) {
                    break;
                }
            }
        }
        return elem;
    }

    /**
     * @return the signature crypto class used to process
     *         the signature/verfiy
     */
    public Crypto getCrypto() {
        return crypto;
    }

    /**
     * @return the hash value of the document
     */
    public int getHash() {
        return hash;
    }

    /**
     * @param elem is the BinarySecurityToken to store
     */
    public void setBst(Element elem) {
        if (bst == null) {
            bst = new Vector();
        }
        bst.add(elem);
    }

    /**
     * @param crypto is the signature crypto class used to
     *               process signature/verify
     */
    public void setCrypto(Crypto crypto) {
        this.crypto = crypto;
    }

    /**
     * @return Returns the assertion.
     */
    public Element getAssertion() {
        return assertion;
    }

    /**
     * @param assertion The assertion to set.
     */
    public void setAssertion(Element assertion) {
        this.assertion = assertion;
    }
}
