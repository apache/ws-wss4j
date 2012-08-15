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

package org.apache.ws.security.message.token;

import javax.xml.namespace.QName;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * Reference.
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class Reference {
    public static final QName TOKEN = new QName(WSConstants.WSSE_NS, "Reference");
    protected Element element = null;
    
    /**
     * Constructor.
     * 
     * @param elem The Reference element
     * @throws WSSecurityException 
     */
    public Reference(Element elem) throws WSSecurityException {
        if (elem == null) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY, "noReference");
        }
        element = elem;
        QName el = new QName(element.getNamespaceURI(), element.getLocalName());
        if (!el.equals(TOKEN)) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "badElement", new Object[] {TOKEN, el}
            );
        }

        String uri = getURI();
        // Reference URI cannot be null or empty
        if (uri == null || "".equals(uri)) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "badReferenceURI"
            );
        }
    }

    /**
     * Constructor.
     * 
     * @param doc 
     */
    public Reference(Document doc) {
        element = doc.createElementNS(WSConstants.WSSE_NS, "wsse:Reference");
    }
    
    /**
     * Add the WSSE Namespace to this reference. The namespace is not added by default for
     * efficiency purposes, as the reference is embedded in a wsse:SecurityTokenReference.
     */
    public void addWSSENamespace() {
        WSSecurityUtil.setNamespace(this.element, WSConstants.WSSE_NS, WSConstants.WSSE_PREFIX);
    }

    /**
     * Get the DOM element.
     * 
     * @return the DOM element
     */
    public Element getElement() {
        return element;
    }

    /**
     * Get the ValueType attribute.
     * 
     * @return the ValueType attribute
     */
    public String getValueType() {
        return element.getAttribute("ValueType");
    }

    /**
     * Get the URI.
     * 
     * @return the URI
     */
    public String getURI() {
        return element.getAttribute("URI");
    }

    /**
     * Set the Value type.
     * 
     * @param valueType the ValueType attribute to set
     */
    public void setValueType(String valueType) {
        element.setAttributeNS(null, "ValueType", valueType);
    }

    /**
     * Set the URI.
     * 
     * @param uri the URI to set
     */
    public void setURI(String uri) {
        element.setAttributeNS(null, "URI", uri);
    }

    /**
     * Return the string representation.
     * 
     * @return the string representation.
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node)element);
    }
    
    @Override
    public int hashCode() {
        int result = 17;
        String uri = getURI();
        if (uri != null) {
            result = 31 * result + uri.hashCode();
        }
        String valueType = getValueType();
        if (valueType != null) {
            result = 31 * result + valueType.hashCode();
        }
        return result;
    }
    
    @Override
    public boolean equals(Object object) {
        if (!(object instanceof Reference)) {
            return false;
        }
        Reference reference = (Reference)object;
        if (!compare(getURI(), reference.getURI())) {
            return false;
        }
        if (!compare(getValueType(), reference.getValueType())) {
            return false;
        }
        return true;
    }
    
    private boolean compare(String item1, String item2) {
        if (item1 == null && item2 != null) { 
            return false;
        } else if (item1 != null && !item1.equals(item2)) {
            return false;
        }
        return true;
    }
}
