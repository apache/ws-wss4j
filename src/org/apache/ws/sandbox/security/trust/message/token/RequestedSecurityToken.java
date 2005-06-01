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
import org.apache.ws.security.conversation.message.token.SecurityContextToken;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class RequestedSecurityToken {

    // private SecurityContextToken securityContextToken;
	private Element element = null;
    
    public static final QName TOKEN =
            new QName(TrustConstants.WST_NS,
                    TrustConstants.REQUESTED_SECURITY_TOKEN_LN);
    //for customUsage only
    // No getters and setters will be generated for these members
    SecurityContextToken sct;
    UsernameToken unt;

    /**
     * Constructor
     *
     * @param doc
     */
    public RequestedSecurityToken(Document doc) throws Exception {

        this.element =
                doc.createElementNS(TOKEN.getNamespaceURI(),
                        TrustConstants.WST_PREFIX + ":" + TOKEN.getLocalPart());

        WSSecurityUtil.setNamespace(this.element,
                TOKEN.getNamespaceURI(),
                TrustConstants.WST_PREFIX);

        this.element.appendChild(doc.createTextNode(""));

    }

    /**
     * Constructor
     *
     * @param doc
     */
    public RequestedSecurityToken(Document doc, boolean generateChildren) throws Exception {
        this(doc);
        if (generateChildren) {
            this.sct = new SecurityContextToken(doc);
            this.element.appendChild(sct.getElement());

        }
    }

    /**
     * To create a RequestSecurityTokenResponse token form an element passed
     *
     * @param elem
     * @throws WSSecurityException
     */
    public RequestedSecurityToken(Element elem) throws WSSecurityException {
        this.element = elem;
        QName el =
                new QName(this.element.getNamespaceURI(),
                        this.element.getLocalName());
        if (!el.equals(TOKEN)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN,
                    "badTokenType00",
                    new Object[]{el});
        }
    }

    /**
     * May not be usefull in future developments.
     * Always try to use parseChildElements as false
     *
     * @param elem
     * @param parseChildElements
     * @throws WSSecurityException
     */

    public RequestedSecurityToken(Element elem, boolean parseChildElements)
            throws WSSecurityException {
        this(elem);
        if (!parseChildElements) {
            return;
        }

        this.sct =
                new SecurityContextToken((Element) WSSecurityUtil.getDirectChild(//elem.getOwnerDocument(),
                        elem,
                        SecurityContextToken.TOKEN.getLocalPart(),
                        SecurityContextToken.TOKEN.getNamespaceURI()));

    }

    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }

    /**
     * @return
     */
    public Element getElement() {
        return element;
    }

    public void setElement(Element element) {
        this.element = element;
    }

    public void addToken(Element childToken) {
        this.element.appendChild(childToken);
    }

    /**
     * @return
     */
    public SecurityContextToken getSct() {
        return sct;
    }

}
