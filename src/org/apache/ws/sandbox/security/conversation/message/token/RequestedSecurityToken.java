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
package org.apache.ws.security.conversation.message.token;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.namespace.QName;

/**
 * Class RequestedSecurityToken
 */
public class RequestedSecurityToken {

    /**
     * Field securityContextToken
     */
    private SecurityContextToken securityContextToken;

    /**
     * Field element
     */
    private Element element = null;

    /**
     * Field TOKEN
     */
    public static final QName TOKEN =
            new QName(WSConstants.WSSE_NS,
                    TrustConstants.REQUESTED_SECURITY_TOKEN_LN);

    /**
     * Constructor
     * 
     * @param doc                  
     * @param securityContextToken 
     * @throws Exception 
     */
    public RequestedSecurityToken(Document doc, SecurityContextToken securityContextToken)
            throws Exception {
        this.securityContextToken = securityContextToken;
        this.element = doc.createElementNS(WSConstants.WSSE_NS,
                "wsse:" + TrustConstants.REQUESTED_SECURITY_TOKEN_LN);
        this.securityContextToken = securityContextToken;
        this.element.appendChild(securityContextToken.getElement());
    }

    /**
     * To create a RequestSecurityTokenResponse token form an element passed
     * 
     * @param elem 
     * @throws WSSecurityException 
     */
    public RequestedSecurityToken(Element elem) throws WSSecurityException {
        this.element = elem;
        QName el = new QName(this.element.getNamespaceURI(),
                this.element.getLocalName());
        if (!el.equals(TOKEN)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType00",
                    new Object[]{el});
        }
        Element token = (Element) WSSecurityUtil.getDirectChild(element,
                ConversationConstants.SECURITY_CONTEXT_TOKEN_LN,
                WSConstants.WSSE_NS);
        securityContextToken = new SecurityContextToken(token);

        // ??? Discuss what elements are optional and wht are not
    }

    /**
     * Method toString
     * 
     * @return 
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }

    /**
     * @return 
     */
    public Element getElement() {
        return element;
    }

    /**
     * Method setElement
     * 
     * @param element 
     */
    public void setElement(Element element) {
        this.element = element;
    }

    /**
     * Method getSecurityContextToken
     * 
     * @return 
     */
    public SecurityContextToken getSecurityContextToken() {
        return securityContextToken;
    }

    /**
     * Method setSecurityContextToken
     * 
     * @param securityContextToken 
     */
    public void setSecurityContextToken(SecurityContextToken securityContextToken) {
        this.securityContextToken = securityContextToken;
    }
}
