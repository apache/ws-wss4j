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

import java.io.ByteArrayOutputStream;

import javax.xml.namespace.QName;

import org.apache.axis.components.logger.LogFactory;
import org.apache.commons.logging.Log;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.sandbox.security.trust.TrustConstants;
import org.apache.ws.sandbox.security.trust.WSTrustException;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

public class RequestSecurityTokenResponse extends AbstractToken {
	
    private static Log log = LogFactory.getLog(RequestSecurityTokenResponse.class.getName());

    private RequestedSecurityToken requestedSecurityToken;
    private RequestedProofToken requestedProofToken;

    private TokenType tokenTypeElement;
    private Lifetime lifeTimeElement;

    public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.REQUEST_SECURITY_TOKEN_RESPONSE_LN, TrustConstants.WST_PREFIX);
    //
    /**
     * Constructor
     *
     * @param doc
     * @throws java.lang.Exception
     */
    public RequestSecurityTokenResponse(Document doc) throws Exception {
    	super(doc);
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
    public RequestSecurityTokenResponse(Element elem) throws WSTrustException {
    	super(elem);
    }

    /**
     * May not be usefull in future developments.
     * Always try to use parseChildElements as false
     *
     * @param elem
     * @param setChildElement
     * @throws WSSecurityException
     */
    public RequestSecurityTokenResponse(Element elem, boolean parseChildElements) throws WSTrustException {
        this(elem);
        if (!parseChildElements) {
            return;
        }
        //TODO: This should be removed - parsing the child elements should eb teh default behaviour 
        //which will be provided in the default element constructor
    }

    public void setContextAttr(String context) {
        this.element.setAttribute(TrustConstants.CONTEXT_ATTR, context);
    }

    public String getContextAttr() {
        return this.element.getAttribute(TrustConstants.CONTEXT_ATTR);
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

    /**
     * TODO: Should be removed
     * @param doc
     */
    public void build(Document doc) {
        Element securityHeader = WSSecurityUtil.findWsseSecurityHeaderBlock(WSSConfig.getDefaultWSConfig(), doc, doc.getDocumentElement(), true);
        WSSecurityUtil.appendChildElement(doc, securityHeader, this.element);

        if (log.isInfoEnabled()) {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            XMLUtils.outputDOM(doc, os, true);
            String osStr = os.toString();
        }
    }
    
	
	/**
	 * This is provided as an extensibility mechanism to add any child element 
	 * @param childToken
	 */
	public void addToken(Element childToken) {
		this.element.appendChild(childToken);
	}
	
	/**
	 * This is provided as an extensibility mechnism to as any attrbute 
	 * @param attribute
	 * @param value
	 */
	public void addAttribute(String attribute, String value) {
		this.element.setAttribute(attribute, value);
	}

	/**
	 * This is provided to be used to extract custom elements
	 * @param namespace
	 * @param tagName
	 * @return
	 */
	public Element getTokenByTagNameNS(String namespace, String tagName) {
		return (Element)this.element.getElementsByTagNameNS(namespace, tagName);
	}
	
	/**
	 * This is to be used to retrieve the value of the 
	 * custom attrbutes added
	 * @param attribute
	 * @return
	 */
	public String getAttributeValue(String attribute) {
		return this.element.getAttribute(attribute);		
	}
    
    
	/**
	 * Returns the QName of this type
	 * 
	 * @see org.apache.ws.sandbox.security.trust.message.token.AbstractToken#getToken()
	 */
	protected QName getToken() {
		return TOKEN;
	}

	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#deserializeElement(org.w3c.dom.Element)
	 */
	protected void deserializeChildElement(Element elem) {
		// TODO Auto-generated method stub
		
	}

	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#deserializeElementText(org.w3c.dom.Text)
	 */
	protected void setElementTextValue(Text textNode) {
		// TODO Auto-generated method stub
		
	}

    
}
