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

import org.apache.axis.components.logger.LogFactory;
import org.apache.commons.logging.Log;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.message.token.TokenType;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.namespace.QName;
import java.io.ByteArrayOutputStream;

public class RequestSecurityTokenResponse {
    private static Log log =
            LogFactory.getLog(RequestSecurityTokenResponse.class.getName());

    private Element element = null;
    //for custom usage
    //No getters and setters will be generated for these members
    private RequestedSecurityToken requestedSecurityToken = null;
    private RequestedProofToken requestedProofToken = null;
    private Element tokenType = null;
    private Element lifeTime = null;

    public static final QName TOKEN =
            new QName(TrustConstants.WST_NS,
                    TrustConstants.REQUEST_SECURITY_TOKEN_RESPONSE_LN,
                    TrustConstants.WST_PREFIX);
    //
    /**
     * Constructor
     *
     * @param doc
     * @throws java.lang.Exception
     */
    public RequestSecurityTokenResponse(Document doc) throws Exception {
        this.element =
                doc.createElementNS(TOKEN.getNamespaceURI(),
                        TOKEN.getPrefix() + ":" + TOKEN.getLocalPart());
        WSSecurityUtil.setNamespace(this.element,
                TOKEN.getNamespaceURI(),
                TrustConstants.WST_PREFIX);
        this.element.appendChild(doc.createTextNode(""));

    }

    /**
     * Constructor
     *
     * @param doc
     * @throws java.lang.Exception
     */
    public RequestSecurityTokenResponse(Document doc, boolean generateChildren) throws Exception {
        this(doc);
        if (generateChildren) {
            this.requestedSecurityToken = new RequestedSecurityToken(doc, true);
            this.requestedProofToken = new RequestedProofToken(doc);
            this.element.appendChild(requestedSecurityToken.getElement());//ruchith
            this.element.appendChild(requestedProofToken.getElement());//dimuthu
        }
    }

    /**
     * To create a RequestSecurityTokenResponse token form an element passed
     *
     * @param elem
     * @throws WSSecurityException
     */
    public RequestSecurityTokenResponse(Element elem)
            throws WSSecurityException {
        this.element = elem;
        QName el =
                new QName(this.element.getNamespaceURI(),
                        this.element.getLocalName());
        if (!el.equals(TOKEN)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN,
                    "badTokenType00",
                    new Object[]{el});
        }

        //System.out.println("RequestSecurityTokenResponse created");

    }

    /**
     * May not be usefull in future developments.
     * Always try to use parseChildElements as false
     *
     * @param elem
     * @param setChildElement
     * @throws WSSecurityException
     */
    public RequestSecurityTokenResponse(Element elem,
                                        boolean parseChildElements)
            throws WSSecurityException {
        this(elem);
        if (!parseChildElements) {
            return;
        }
        Element elemTemp;

        this.tokenType =
                (Element) WSSecurityUtil.getDirectChild(elem.getOwnerDocument(),
                        TokenType.TOKEN.getLocalPart(),
                        TokenType.TOKEN.getNamespaceURI());

        if ((elemTemp = (Element) WSSecurityUtil.getDirectChild(//elem.getOwnerDocument(),
                elem,
                RequestedSecurityToken.TOKEN.getLocalPart(),
                RequestedSecurityToken.TOKEN.getNamespaceURI())) != null) {
            this.requestedSecurityToken =
                    new RequestedSecurityToken(elemTemp, true);
        }
//            this.requestedSecurityToken =
//                new RequestedSecurityToken(
//                    (Element) WSSecurityUtil.getDirectChild(
//                        elem.getOwnerDocument(),
//                        RequestedSecurityToken.TOKEN.getLocalPart(),
//                        RequestedSecurityToken.TOKEN.getNamespaceURI()));

        if ((elemTemp = (Element) WSSecurityUtil.getDirectChild(//elem.getOwnerDocument(),
                elem,
                RequestedProofToken.TOKEN.getLocalPart(),
                RequestedProofToken.TOKEN.getNamespaceURI())) != null) {
            this.requestedProofToken =
                    new RequestedProofToken(elemTemp);
        }
//        this.requestedProofToken =
//            new RequestedProofToken(
//                (Element) WSSecurityUtil.getDirectChild(
//                    elem.getOwnerDocument(),
//                    RequestedProofToken.TOKEN.getLocalPart(),
//                    RequestedProofToken.TOKEN.getNamespaceURI()));
        //this.lifeTime=(Element)WSSecurityUtil.findElement(elem.getOwnerDocument(),LifeTime.TOKEN.getLocalPart(),LifeTime.TOKEN.getNamespaceURI());

        //System.out.println("RequestSecurityTokenResponse created");

    }

    public void setContext(String context) {
        this.element.setAttribute("Context", context);
    }

    public String getContext() {
        return this.element.getAttribute("Context");
    }

    public Element getElement() {
        return element;
    }

    public void setElement(Element element) {
        this.element = element;
    }

    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }

    public void addToken(Element childToken) {
        this.element.appendChild(childToken);
    }

    public void removeToken(Element childToken) {
        this.element.removeChild(childToken);
    }

    /**
     * @return
     */
    public RequestedProofToken getRequestedProofToken() {
        return requestedProofToken;
    }

    /**
     * @return
     */
    public RequestedSecurityToken getRequestedSecurityToken() {
        return requestedSecurityToken;
    }

    public void build(Document doc) {
        Element securityHeader = WSSecurityUtil.findWsseSecurityHeaderBlock(WSSConfig.getDefaultWSConfig(), doc, doc.getDocumentElement(), true);
        WSSecurityUtil.appendChildElement(doc, securityHeader, this.element);
//              WSSecurityUtil.setNamespace(securityHeader, WSConstants.WSU_NS,
        //                                          WSConstants.WSU_PREFIX);
        if (log.isInfoEnabled()) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            XMLUtils.outputDOM(doc, os, true);
            String osStr = os.toString();
        }
    }

}
