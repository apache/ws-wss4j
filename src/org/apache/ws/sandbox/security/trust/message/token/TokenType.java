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
package org.apache.ws.security.trust.message.token;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.xml.namespace.QName;

/**
 * @author Malinda Kaushalye
 *         <p/>
 *         TokenType element
 */
public class TokenType {
    public static final String UNT = "http://schemas.xmlsoap.org/ws/2004/04/security/sc/unt";
    public static final String SCT = "http://schemas.xmlsoap.org/ws/2004/04/security/sc/sct";

    public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.TOKEN_TYPE_LN, TrustConstants.WST_PREFIX);
    Element element = null;

    /**
     * Constructor for TokenType
     *
     * @param elem
     * @throws WSSecurityException
     */
    public TokenType(Element elem) throws WSSecurityException {
        this.element = elem;
        QName el = new QName(this.element.getNamespaceURI(), this.element.getLocalName());
        if (!el.equals(TOKEN)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType", new Object[]{el});
        }
    }

    /**
     * Constructor for TokenType
     *
     * @param doc
     */
    public TokenType(Document doc) {
        this.element = doc.createElementNS(TOKEN.getNamespaceURI(), TOKEN.getPrefix() + ":" + TOKEN.getLocalPart());
        WSSecurityUtil.setNamespace(this.element, TrustConstants.WST_NS, TrustConstants.WST_PREFIX);
        this.element.appendChild(doc.createTextNode(""));
    }

    public Text getFirstNode() {
        Node node = this.element.getFirstChild();
        return ((node != null) && node instanceof Text) ? (Text) node : null;
    }

    /**
     * This will return the text node of the element
     *
     * @return
     */
    public String getValue() {
        String val = "";
        if (this.element.getFirstChild().getNodeType() != Node.TEXT_NODE) {
            return null;
        }
        val = this.element.getFirstChild().getNodeValue();
        return val;
    }

    /**
     * This will append the text node to the element
     *
     * @param val
     */
    public void setValue(String val) {
        this.element.appendChild(element.getOwnerDocument().createTextNode(val));
    }

    /**
     * @return
     */
    public Element getElement() {
        return element;
    }

    /**
     * @param element
     */
    public void setElement(Element element) {
        this.element = element;
    }

    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }

}
