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

import javax.xml.namespace.QName;

/**
 * @author Malinda Kaushalye
 */
public class Status {
    public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.STATUS_LN, TrustConstants.WST_PREFIX);
    Element element = null;

    /**
     * Constructor for Status
     *
     * @param elem
     * @throws WSSecurityException
     */
    public Status(Element elem) throws WSSecurityException {
        this.element = elem;
        QName el = new QName(this.element.getNamespaceURI(), this.element.getLocalName());
        if (!el.equals(TOKEN)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType", new Object[]{el});
        }
    }

    /**
     * Constructor for Status
     *
     * @param doc
     */
    public Status(Document doc) {
        this.element = doc.createElementNS(TOKEN.getNamespaceURI(), TOKEN.getPrefix() + ":" + TOKEN.getLocalPart());
        WSSecurityUtil.setNamespace(this.element, TrustConstants.WST_NS, TrustConstants.WST_PREFIX);
        this.element.appendChild(doc.createTextNode(""));
    }

    /**
     * Sets the code of the status
     *
     * @param code
     */
    public void setCode(Code code) {

        this.element.appendChild(code.getElement());
    }

    /**
     * Gets the code of the status
     *
     * @return
     * @throws WSSecurityException
     */
    public Code getCode() throws WSSecurityException {
        Element elem = (Element) WSSecurityUtil.findElement(this.element, Code.TOKEN.getLocalPart(), Code.TOKEN.getNamespaceURI());
        return new Code(elem);
    }

    /**
     * Sets the reason of the status
     *
     * @param reason
     */
    public void setReason(Reason reason) {
        this.element.appendChild(reason.getElement());
    }

    /**
     * Gets the reason of the status
     *
     * @return
     * @throws WSSecurityException
     */
    public Reason getReason() throws WSSecurityException {
        Element elem = (Element) WSSecurityUtil.findElement(this.element, Reason.TOKEN.getLocalPart(), Reason.TOKEN.getNamespaceURI());
        return new Reason(elem);
    }

    /**
     * @return first element of the status
     */
    public Element getFirstElement() {
        for (Node currentChild = this.element.getFirstChild();
             currentChild != null;
             currentChild = currentChild.getNextSibling()) {
            if (currentChild instanceof Element) {
                return (Element) currentChild;
            }
        }
        return null;
    }

    /**
     * @return status element
     */
    public Element getElement() {
        return element;
    }

    /**
     * @param element status element
     */
    public void setElement(Element element) {
        this.element = element;
    }

    /**
     * 
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }

}
