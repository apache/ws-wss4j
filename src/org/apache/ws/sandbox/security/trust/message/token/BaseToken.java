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
package org.apache.ws.sandbox.security.trust.message.token;

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.sandbox.security.trust.TrustConstants;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.namespace.QName;

/**
 * @author Malinda Kaushalye
 *         <p/>
 *         Base token.
 */
public class BaseToken {
    
	public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.BASE_LN, TrustConstants.WST_PREFIX);
    Element element;

    /**
     * Constructor for Base
     *
     * @param elem
     * @throws WSSecurityException
     */
    public BaseToken(Element elem) throws WSSecurityException {
        this.element = elem;
        QName el = new QName(this.element.getNamespaceURI(),
                        this.element.getLocalName());
        if (!el.equals(TOKEN)) {

            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN,
                    "badTokenType:base",
                    new Object[]{el});
        }

    }

    /**
     * Constructor for Base
     *
     * @param doc
     */
    public BaseToken(Document doc) {
        this.element =
                doc.createElementNS(TOKEN.getNamespaceURI(),
                        TOKEN.getPrefix() + ":" + TOKEN.getLocalPart());
        WSSecurityUtil.setNamespace(this.element,
                TOKEN.getNamespaceURI(),
                TrustConstants.WST_PREFIX);
        this.element.appendChild(doc.createTextNode(""));
    }

    /**
     * Return the binary security token of the base token if any
     *
     * @return
     * @throws WSSecurityException
     */
    public BinarySecurity getBinarySecurityToken() throws WSSecurityException {
        BinarySecurity binarySecToken;

        binarySecToken = null;
        String firstChild = this.element.getFirstChild().getLocalName();

        if ("BinarySecurityToken" == firstChild) {

            binarySecToken =
                    new BinarySecurity((Element) this.element.getFirstChild());
            return binarySecToken;
        } else if ("SecurityTokenReference" == firstChild) {

            SecurityTokenReference secTokRef =
                    new SecurityTokenReference((Element) this.element.getFirstChild());
            binarySecToken =
                    new BinarySecurity(secTokRef.getTokenElement(element.getOwnerDocument(),
                                    null));
            return binarySecToken;
        } else {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN,
                    "badTokenType");
        }

    }

    /**
     * Currently support only direct reference
     *
     * @param binarySecurity
     * @param asReference
     */
    public void setBinarySecurityToken(BinarySecurity binarySecurity) {
        Element elem = getFirstElement();
        if (elem != null) {
            this.element.replaceChild(binarySecurity.getElement(), elem);
        } else {
            this.element.appendChild(binarySecurity.getElement());
        }
    }

    /**
     * get the first child element.
     *
     * @return the first <code>Element</code> child node
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
     * @return
     */
    public Element getElement() {
        return this.element;
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

    /**
     * Other tokens can be added through this method
     *
     * @param childToken
     */
    public void addToken(Element childToken) {
        this.element.appendChild(childToken);
    }

    /**
     * Tokens can be removed through this method
     *
     * @param childToken
     */
    public void removeToken(Element childToken) {
        this.element.removeChild(childToken);
    }

}
