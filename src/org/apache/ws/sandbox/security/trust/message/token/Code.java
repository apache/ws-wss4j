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
import javax.xml.namespace.QName;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;
/**
 * @author Malinda
 * Code token
 * @see org.apache.ws.security.trust.message.token.Status
 */
public class Code {
    public static final QName TOKEN =
        new QName(
            TrustConstants.WST_NS,
            TrustConstants.CODE_LN,
            TrustConstants.WST_PREFIX);
    Element element = null;
    /**
     * Constructor for Code
     * @param elem
     * @throws WSSecurityException
     */
    public Code(Element elem) throws WSSecurityException {
        this.element = elem;
        QName el =
            new QName(
                this.element.getNamespaceURI(),
                this.element.getLocalName());
        if (!el.equals(TOKEN)) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY_TOKEN,
                "badTokenType",
                new Object[] { el });
        }
    }
    /**
     * Constructor for Code
     * @param doc
     */
    public Code(Document doc) {
        this.element =
            doc.createElementNS(
                TOKEN.getNamespaceURI(),
                TOKEN.getPrefix() + ":" + TOKEN.getLocalPart());
        WSSecurityUtil.setNamespace(
            this.element,
            TrustConstants.WST_NS,
            TrustConstants.WST_PREFIX);
        this.element.appendChild(doc.createTextNode(""));
    }
    /**
     * Constructor for Code
     * @param doc 
     * @param value Text to be inserted to Code
     */
    public Code(Document doc, String value) {
        this.element =
            doc.createElementNS(
                TOKEN.getNamespaceURI(),
                TOKEN.getPrefix() + ":" + TOKEN.getLocalPart());
        WSSecurityUtil.setNamespace(
            this.element,
            TrustConstants.WST_NS,
            TrustConstants.WST_PREFIX);
        this.element.appendChild(doc.createTextNode(value));
    }
    /**
     * 
     * @return the first (Text) node 
     */
    public Text getFirstNode() {
        Node node = this.element.getFirstChild();
        return ((node != null) && node instanceof Text) ? (Text) node : null;
    }

    /**
     * @return Code element
     */
    public Element getElement() {
        return element;
    }

    /**
     * @param element Code element
     */
    public void setElement(Element element) {
        this.element = element;
    }
    /**
     * Sets the Text node
     * @param val
     */
    public void setValue(String val) {
        this.element.appendChild(
            element.getOwnerDocument().createTextNode(val));
    }

    /**
     * To display the token
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }
    /**
     * 
     * @return value of the Code element
     */
    public String getValue() {
        String val = "";
        if (this.element.getFirstChild().getNodeType() != Node.TEXT_NODE) {
            return null;
        }
        val = this.element.getFirstChild().getNodeValue();
        return val;
    }
}
