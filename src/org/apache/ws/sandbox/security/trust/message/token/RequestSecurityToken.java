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
import javax.xml.soap.Node;

import org.apache.axis.components.logger.LogFactory;
import org.apache.commons.logging.Log;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.policy.message.token.AppliesTo;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class RequestSecurityToken {

	
	
	private static Log log = LogFactory.getLog(RequestSecurityTokenResponse.class.getName());

	private Element element = null;
    
    private TokenType tokenTypeElement = null;
    private RequestType requestTypeElement = null;
    private AppliesTo appliesToElement = null;
    private Entropy entropyElement = null;
    private KeySize keySizeElement = null;
    private Lifetime lifetimeElement = null;
		
	public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.REQUEST_SECURITY_TOKEN_LN, TrustConstants.WST_PREFIX);

	
	public RequestSecurityToken(Document doc){
		this.element = doc.createElementNS(TOKEN.getNamespaceURI(), TrustConstants.WST_PREFIX + ":" + TOKEN.getLocalPart());
	}
	
	/**
	 * @param elem
	 * @throws WSSecurityException
	 */
  public RequestSecurityToken(Element elem) throws WSSecurityException{
	this.element = elem;
	QName el =
		new QName(
			this.element.getNamespaceURI(),
			this.element.getLocalName());
	if (!el.equals(TOKEN)) {
		throw new WSSecurityException(WSSecurityException.INVALID_SECURITY_TOKEN,
			"badTokenType00",
			new Object[] { el });
	}

  }  
  
  /**
   * Sets the <code>wst:TokenType</code> value of this <code>wst:RequestSecurityToken</code>
   * @param tokenType The <code>wst:TokenType</code> uri as a <code>String</code>
   */
  public void setTokenType(String tokenType) {
  	if(this.tokenTypeElement != null) //If there's an element already there remove it
  		this.element.removeChild(this.tokenTypeElement.getElement());

	this.tokenTypeElement = new TokenType(this.element.getOwnerDocument());
	this.tokenTypeElement.setValue(tokenType);
	this.addToken(this.tokenTypeElement.getElement()); 
  	
  }
  
  /**
   * Sets the <code>wst:RequestType</code> value of this <code>wst:RequestSecurityToken</code>
   * @param requestType The <code>wst:RequestType</code> uri as a <code>String
   */
  public void setRequestType(String requestType) {
  	if(this.requestTypeElement != null)
  		this.element.removeChild(this.requestTypeElement.getElement());

	this.requestTypeElement = new RequestType(this.element.getOwnerDocument());
	this.requestTypeElement.setValue(requestType);
	this.addToken(this.requestTypeElement.getElement());  	
  	
  }
  
  /**
   * Sets the <code>wst:AppliesTo</code> value of the <code>wst:RequestSecurityToken</code>
   * @param appliesTo The <code>wst:AppliesTo/wsa:EndpointReference<code> as a <code>String</code> 
   */
  public void setAppliesTo(String appliesTo) {
  	if(this.appliesToElement != null)
  		this.element.removeChild(this.appliesToElement.getElement());

	this.appliesToElement = new AppliesTo(this.element.getOwnerDocument());
  	this.appliesToElement.setEndpointReference(appliesTo);
	this.addToken(this.appliesToElement.getElement());

  }
  
  /**
   * Sets the <code>wst:Entropy/wst:BinarySecret</code> value and 
   * <code>wst:Entropy/wst:BinarySecret@Type</code> of the 
   * <code>wst:RequestSecurityToken</code>
   * @param binarySecretType 
   * @param entropyValue
   */
  public void setEntropy(String binarySecretType, String entropyValue) {
  	if(this.entropyElement != null)
  		this.element.removeChild(this.entropyElement.getElement());
  	
  	
	this.entropyElement = new Entropy(this.element.getOwnerDocument());
  	this.entropyElement.setBinarySecret(binarySecretType,entropyValue);
	this.addToken(this.entropyElement.getElement());
	
  }
  
  /**
   * Sets the binary secret of the Entropy element when the its of type <code>Nonce</code>
   * @see BinarySecret#NONCE_VAL
   * @param entropyValue The nonce value
   */
  public void setEntropyNonce(String nonceValue) {
  	this.setEntropy(TrustConstants.BINARY_SECRET_NONCE_VAL,nonceValue);
  }
  
  /**
   * Adds a <code>wst:Lifetime</code> element with the given duration to the 
   * <code>wst:RequestSecurityToken</code>
   * @param duration
   */
  public void setLifetime(int duration) {
  	if(this.lifetimeElement != null)
  		this.element.removeChild(this.lifetimeElement.getElement());
  	this.lifetimeElement = new Lifetime(this.element.getOwnerDocument(),duration);
  }
  
  /**
   * Sets the <code>wst:KeySize</code> value of the <code>wst:RequestSecurityToken</code>
   * @param size
   */
  public void setKeySize(int size) {
  	if(this.keySizeElement != null)
  		this.element.removeChild(this.keySizeElement.getElement());
  		
	this.keySizeElement = new KeySize(this.element.getOwnerDocument());
  	this.keySizeElement.setKeySize(size);
	this.addToken(this.keySizeElement.getElement());

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


}
