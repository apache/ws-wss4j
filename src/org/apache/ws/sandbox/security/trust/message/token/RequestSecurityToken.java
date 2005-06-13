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
import org.apache.ws.security.trust.WSTrustException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

public abstract class RequestSecurityToken extends CompositeElement {
	
    protected TokenType tokenTypeElement;
    protected RequestType requestTypeElement;
	
	public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.REQUEST_SECURITY_TOKEN_LN, TrustConstants.WST_PREFIX);

	/**
	 * Creates a new <code>wst:RequestSecurityToken</code> with the 
	 * given request type 
	 * @param doc
	 * @param requestType
	 */
	public RequestSecurityToken(Document doc, String requestType){
		super(doc);
		this.setRequestType(requestType);
	}
	
	/**
	 * Instanciate a new <code>RequestSecurityToken</code> with a <code>wst:RequestSecurityToken</code> 
	 * token's element 
	 * @param elem 
	 * @throws WSSecurityException
	 */
	public RequestSecurityToken(Element elem) throws WSTrustException{
	  	super(elem);
	  	//TODO  Parse and populate the elements
	  	
	}  
  
	/**
	 * Sets the <code>wst:TokenType</code> value of this <code>wst:RequestSecurityToken</code>
	 * @param tokenType The <code>wst:TokenType</code> uri as a <code>String</code>
	 */
	public void setTokenType(String tokenType) {
	  	if(this.tokenTypeElement == null) { 
	  		this.tokenTypeElement = new TokenType(this.element.getOwnerDocument());
	  		this.element.appendChild(this.tokenTypeElement.getElement());
	  	}

	  	this.tokenTypeElement.setValue(tokenType);
	  	
	}

	/**
	 * Returns the value of the TokenType element 
	 * @return
	 */
	public String getTokenType() {
		if(this.tokenTypeElement != null)
			return this.tokenTypeElement.getValue();
		else
			return null;
	}

  
	/**
	 * Sets the <code>wst:RequestType</code> value of this <code>wst:RequestSecurityToken</code>
	 * @param requestType The <code>wst:RequestType</code> uri as a <code>String
	 */
	public void setRequestType(String requestType) {
	  	if(this.requestTypeElement == null) {
	  		this.requestTypeElement = new RequestType(this.element.getOwnerDocument());
	  		this.element.appendChild(this.requestTypeElement.getElement());
	  	}

		this.requestTypeElement.setValue(requestType);

	}

	/**
	 * Returns the value of the <code>RequestType</code> element
	 * @return
	 */
	public String getRequesType() {
	  	if(this.requestTypeElement != null)
	  		return this.requestTypeElement.getValue();
	  	else 
	  		return null;
	}
  
	public void setContextAttr(String contextAttrValue) {
		this.element.setAttribute(TrustConstants.CONTEXT_ATTR, contextAttrValue);
	}
  
	
	/**
	 * This is provided as an extensibility mechanism to add any
	 * child element to the <code>wst:RequestSecyrityToken</code> element
	 * @param childToken
	 */
	public void addToken(Element childToken) {
		this.element.appendChild(childToken);
	}
	
	/**
	 * This is provided as an extensibility mechnism to 
	 * ass any attrbute to the <code>wst:RequestSecyrityToken</code> element
	 * @param attribute
	 * @param value
	 */
	public void addAttribute(String attribute, String value) {
		this.element.setAttribute(attribute, value);
	}

	/**
	 * This is provided to be used to extract custom elements from the 
	 * <code>wst:RequestSecyrityToken</code>
	 * @param namespace
	 * @param tagName
	 * @return
	 */
	public NodeList getTokensByTagNameNS(String namespace, String tagName) {
		return this.element.getElementsByTagNameNS(namespace, tagName);
	}
	
	/**
	 * This is to be used to retrieve the value of the 
	 * custom attrbutes added to the 
	 * <code>wst:RequestSecyrityToken</code>
	 * @param attribute
	 * @return
	 */
	public String getAttributeValue(String attribute) {
		return this.element.getAttribute(attribute);		
	}
	
	/**
	 * Returns the QName of this type
	 * 
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#getToken()
	 */
	protected QName getToken() {
		return TOKEN;
	}

	/**
	 * Returns the root element of this token
	 * TODO: This should be removed
	 */
	public Element getElement() {
		return this.element;
	}

	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#deserializeElement(org.w3c.dom.Element)
	 */
	protected void deserializeChildElement(Element elem) throws WSTrustException {
		QName el =  new QName(elem.getNamespaceURI(), elem.getLocalName());
		
		if(el.equals(RequestType.TOKEN)) {
			this.requestTypeElement = new RequestType(elem);
		} else if(el.equals(TokenType.TOKEN)) {
			this.tokenTypeElement = new TokenType(elem);
		} else {
			this.handleSpecificChildren(elem);
		}
		
	}
	
	/**
	 * This is used to handle the specific child elements for the 
	 * four types of requests
	 * <ul>
	 * <li>Issue</li> @see TrustConstants#ISSUE_SECURITY_TOKEN
	 * <li>Renew</li> @see TrustConstants#RENEW_SECURITY_TOKEN
	 * <li>Cancel</li> @see TrustConstants#CANCEL_SECURITY_TOKEN
	 * <li>Validate</li> @see TrustConstants#VALIDATE_SECURITY_TOKEN
	 * </ul>
	 * @param elem
	 * @throws WSTrustException
	 */
	protected abstract void handleSpecificChildren(Element elem) throws WSTrustException;
}
