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
import org.apache.ws.security.message.WSBaseMessage;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.namespace.QName;
import java.io.ByteArrayOutputStream;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * Class RequestSecurityTokenResponse
 */
public class RequestSecurityTokenResponse extends WSBaseMessage {

    /**
     * Field element
     */
    private Element element = null;

    /**
     * Field tokenTypeEle
     */
    private Element tokenTypeEle;

    /**
     * Field keyTypeEle
     */
    private Element keyTypeEle;

    /**
     * Field keySizeEle
     */
    private Element keySizeEle;

    /**
     * Field LifeTime
     */
    private Element LifeTime = null;

    /**
     * Field Created
     */
    private Element Created = null;

    /**
     * Field Expires
     */
    private Element Expires = null;

    /**
     * Field tokenType
     */
    private String tokenType;

    /**
     * Field keyType
     */
    private String keyType;

    /**
     * Field keySize
     */
    private String keySize;

    /**
     * Field requestedProofToken
     */
    private RequestedProofToken requestedProofToken;

    /**
     * Field requestedSecurityToken
     */
    private RequestedSecurityToken requestedSecurityToken;

    /**
     * Field keyInfo
     */
    private KeyInfo keyInfo;

    /**
     * Field TOKEN
     */
    public static final QName TOKEN =
            new QName(WSConstants.WSSE_NS,
                    TrustConstants.SECURITY_CONTEXT_TOKEN_RESPONSE_LN);

    /**
     * Constructor
     * 
     * @param doc 
     * @throws java.lang.Exception 
     * @throws Exception           
     */
    public RequestSecurityTokenResponse(Document doc) throws Exception {
        this.element = doc.createElementNS(WSConstants.WSSE_NS,
                "wsse:" + TrustConstants.SECURITY_CONTEXT_TOKEN_RESPONSE_LN);
        this.tokenTypeEle = doc.createElementNS(WSConstants.WSSE_NS,
                "wsse:"
                + TrustConstants.TOKEN_TYPE_LN);
        this.keyTypeEle = doc.createElementNS(WSConstants.WSSE_NS,
                "wsse:"
                + TrustConstants.KEY_TYPE_LN);

        /*
         * WSSecurityUtil.setNamespace(this.element, WSConstants.WSSE_NS,
         *                           WSConstants.WSSE_PREFIX);
         * WSSecurityUtil.setNamespace(this.tokenTypeEle, WSConstants.WSSE_NS,
         *                           WSConstants.WSSE_PREFIX);
         * WSSecurityUtil.setNamespace(this.keyTypeEle, WSConstants.WSSE_NS,
         *                           WSConstants.WSSE_PREFIX);
         */
        this.keySizeEle = doc.createElementNS(WSConstants.WSSE_NS,
                "wsse:"
                + TrustConstants.KEY_SIZE_LN);
        WSSecurityUtil.setNamespace(this.keySizeEle, WSConstants.WSSE_NS,
                WSConstants.WSSE_PREFIX);
        this.tokenTypeEle.appendChild(doc.createTextNode(""));
        this.keyTypeEle.appendChild(doc.createTextNode(""));
        this.keySizeEle.appendChild(doc.createTextNode(""));
        SecurityContextToken cntxtToken = new SecurityContextToken(doc);
        this.requestedSecurityToken = new RequestedSecurityToken(doc,
                cntxtToken);

        /*
         * elements are added without any logic.???
         */
        this.element.appendChild(this.tokenTypeEle);
        this.element.appendChild(this.keyTypeEle);
        this.element.appendChild(this.keySizeEle);
        this.element.appendChild(this.createLifeTimeElement(doc));
        this.element.appendChild(requestedSecurityToken.getElement());    // ruchith
        this.element.appendChild(this.createRequestedProofToken(doc));    // dimuthu
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
        QName el = new QName(this.element.getNamespaceURI(),
                this.element.getLocalName());
        if (!el.equals(TOKEN)) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN, "badTokenType00",
                    new Object[]{el});
        }
        tokenTypeEle = (Element) WSSecurityUtil.getDirectChild(element,
                TrustConstants.TOKEN_TYPE_LN, WSConstants.WSSE_NS);
        keyTypeEle = (Element) WSSecurityUtil.getDirectChild(element,
                TrustConstants.KEY_TYPE_LN, WSConstants.WSSE_NS);
        keySizeEle = (Element) WSSecurityUtil.getDirectChild(element,
                TrustConstants.KEY_SIZE_LN, WSConstants.WSSE_NS);
        LifeTime = (Element) WSSecurityUtil.getDirectChild(element,
                TrustConstants.LIFE_TIME_LN, WSConstants.WSU_NS);
        Created = (Element) WSSecurityUtil.getDirectChild(element,
                WSConstants.CREATED_LN, WSConstants.WSSE_NS);
        Expires = (Element) WSSecurityUtil.getDirectChild(element,
                ConversationConstants.EXPIRES_LN, WSConstants.WSU_NS);

        // ??? Discuss what elements are optional and wht are not
        this.requestedSecurityToken = new RequestedSecurityToken((Element) WSSecurityUtil.getDirectChild(element, TrustConstants.REQUESTED_SECURITY_TOKEN_LN,
                WSConstants.WSSE_NS));
        this.requestedProofToken = new RequestedProofToken((Element) WSSecurityUtil.getDirectChild(element, "RequestedProofToken", WSConstants.WSSE_NS));
    }

    /**
     * @param doc 
     * @return 
     * @throws WSSecurityException 
     */
    private Element createRequestedProofToken(Document doc)
            throws WSSecurityException {
        this.requestedProofToken = new RequestedProofToken(doc);
        return this.requestedProofToken.getElement();
    }

    /**
     * Set requested security token
     * 
     * @param requestedSecurityToken 
     */
    public void setRequestedSecurityToken(RequestedSecurityToken requestedSecurityToken) {
        this.requestedSecurityToken = requestedSecurityToken;
    }

    /**
     * set Requested ProofToken
     * 
     * @param requestedProofToken 
     */
    public void setRequestedProofToken(RequestedProofToken requestedProofToken) {
        this.requestedProofToken = requestedProofToken;
    }

    /**
     * @return 
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }

    /**
     * Sets the lifetime element refer SAML document
     * 
     * @param doc 
     * @return 
     */
    private Element createLifeTimeElement(Document doc) {
        SimpleDateFormat sdtf =
                new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdtf.setTimeZone(TimeZone.getTimeZone("GMT"));
        Calendar rightNow = Calendar.getInstance();
        this.LifeTime = doc.createElementNS(WSConstants.WSU_NS,
                "wsu:"
                + TrustConstants.LIFE_TIME_LN);
        WSSecurityUtil.setNamespace(this.LifeTime, WSConstants.WSU_NS,
                WSConstants.WSU_PREFIX);
        this.Created = doc.createElementNS(WSConstants.WSU_NS,
                "wsu:" + WSConstants.CREATED_LN);
        WSSecurityUtil.setNamespace(this.Created, WSConstants.WSU_NS,
                WSConstants.WSU_PREFIX);
        this.Expires = doc.createElementNS(WSConstants.WSU_NS,
                "wsu:"
                + ConversationConstants.EXPIRES_LN);
        this.Created.appendChild(doc.createTextNode(sdtf.format(rightNow.getTime())));
        this.Expires.appendChild(doc.createTextNode(sdtf.format(rightNow.getTime())));    // Increment by 12 hrs ???
        this.LifeTime.appendChild(Created);
        this.LifeTime.appendChild(Expires);
        return this.LifeTime;

        /*
         * String expTimeZone = "GMT+" + this.timeout + ":00";
         *  sdtf.setTimeZone(TimeZone.getTimeZone(expTimeZone));
         *  this.elementExpires.appendChild(doc.createTextNode(sdtf.format(rightNow.getTime())));
         *  element.appendChild(elementExpires);
         */
    }

    /**
     * Method getRequestedProfToken
     * 
     * @return 
     */
    public RequestedProofToken getRequestedProfToken() {
        return requestedProofToken;
    }

    /**
     * Method getRequestedProofToken
     * 
     * @return 
     */
    public RequestedProofToken getRequestedProofToken() {
        return requestedProofToken;
    }

    /**
     * Method getRequestedSecurityToken
     * 
     * @return 
     */
    public RequestedSecurityToken getRequestedSecurityToken() {
        return requestedSecurityToken;
    }

    /**
     * Method getElement
     * 
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

    // added by Dimuthu

    /**
     * Method build
     * 
     * @param doc 
     */
    public void build(Document doc) {
        Element securityHeader = insertSecurityHeader(doc);
        WSSecurityUtil.appendChildElement(doc, securityHeader, this.element);
        WSSecurityUtil.setNamespace(securityHeader, WSConstants.WSU_NS,
                WSConstants.WSU_PREFIX);

        // TODO :: Remove this.........
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        XMLUtils.outputDOM(doc, os, true);
        String osStr = os.toString();
        System.out.println(osStr);
    }
}
