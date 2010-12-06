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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.namespace.QName;

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
     * @param elem 
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
     * get the dom element.
     * 
     * @return TODO
     */
    public Element getElement() {
        return element;
    }

    /**
     * get the URI.
     * 
     * @return TODO
     */
    public String getValueType() {
        return element.getAttribute("ValueType");
    }

    /**
     * get the URI.
     * 
     * @return TODO
     */
    public String getURI() {
        return element.getAttribute("URI");
    }

    /**
     * set the Value type.
     * 
     * @param valueType
     */
    public void setValueType(String valueType) {
        element.setAttributeNS(null, "ValueType", valueType);
    }

    /**
     * set the URI.
     * 
     * @param uri 
     */
    public void setURI(String uri) {
        element.setAttributeNS(null, "URI", uri);
    }

    /**
     * return the string representation.
     * 
     * @return TODO
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node)element);
    }
}
