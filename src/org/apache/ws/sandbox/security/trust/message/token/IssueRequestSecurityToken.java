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

import javax.xml.namespace.QName;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.sandbox.security.policy.message.token.AppliesTo;
import org.apache.ws.sandbox.security.trust.TrustConstants;
import org.apache.ws.sandbox.security.trust.WSTrustException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * This is the class to be used to enerate a RequestSecurityToken for the 
 * RST issuance binding
 * Some additional child elements are provided for the convenience of the 
 * developer to carry out an issue request
 * @see org.apache.ws.sandbox.security.trust.TrustConstants#ISSUE_SECURITY_TOKEN
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class IssueRequestSecurityToken extends RequestSecurityToken {
	
    private AppliesTo appliesToElement;
    private Claims claimsElement;
    private Entropy entropyElement;
    private Lifetime lifetimeElement;

    private KeySize keySizeElement;
    
    private Renewing renewingElement;
    	
	/**
	 * @param doc
	 * @param requestType
	 */
	public IssueRequestSecurityToken(Document doc) {
		super(doc, TrustConstants.ISSUE_SECURITY_TOKEN);
	}

	/**
	 * @param elem
	 * @throws WSSecurityException
	 */
	public IssueRequestSecurityToken(Element elem) throws WSTrustException {
		super(elem);
	}

	/**
	 * Sets the <code>wst:AppliesTo</code> value of the <code>wst:RequestSecurityToken</code>
	 * @param appliesTo The <code>wst:AppliesTo/wsa:EndpointReference<code> as a <code>String</code> 
	 */
	public void setAppliesTo(String appliesTo) {
	  	if(this.appliesToElement == null) {
	  		this.appliesToElement = new AppliesTo(this.element.getOwnerDocument());
	  		this.element.appendChild(this.appliesToElement.getElement());
	  	}

	  	this.appliesToElement.setEndpointReference(appliesTo);
	}
  
	/**
	 * Sets the <code>wst:Entropy/wst:BinarySecret</code> value and 
	 * <code>wst:Entropy/wst:BinarySecret@Type</code> of the 
	 * <code>wst:RequestSecurityToken</code>
	 * @param binarySecretType 
	 * @param entropyValue
	 */
	public void setEntropy(String binarySecretType, String entropyValue) {
	  	if(this.entropyElement == null) {
	  		this.entropyElement = new Entropy(this.document);
	  		this.addChild(this.entropyElement);
	  	}
	  	
	  	this.entropyElement.setBinarySecret(binarySecretType,entropyValue);
		
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
	  	if(this.lifetimeElement == null)
	  		this.removeChild(this.lifetimeElement);
	  	this.lifetimeElement = new Lifetime(this.document,duration);
	}
	
	/**
	 * Sets the <code>wst:KeySize</code> value of the <code>wst:RequestSecurityToken</code>
	 * @param size
	 */
	public void setKeySize(int size) {
	  	if(this.keySizeElement == null) {
	  		this.keySizeElement = new KeySize(this.document);
	  		this.addChild(this.keySizeElement);
	  	}
	  		
	  	this.keySizeElement.setKeySize(size);
	}
	
	
	/**
	 * Sets the values of the <code>wst:Claims</code> element of the 
	 * <code>wst:RequestSecurityToken</code>
	 * @param dialectURI
	 * @param claimsElement An <code>Element</code> representing a claim
	 */
	public void setClaims(String dialectURI, Element claimsElement) {
		if(this.claimsElement == null){
			this.claimsElement = new Claims(this.document);
			this.addChild(this.claimsElement);
		}
		
		this.claimsElement.setDialectAttribute(dialectURI);
		this.claimsElement.addToken(claimsElement);
	}

	/**
	 * Sets a set of claims
	 * @param dialectURI
	 * @param claims
	 */
	public void setClaims(String dialectURI, NodeList claims) {
		if(this.claimsElement == null){
			this.claimsElement = new Claims(this.document);
			this.addChild(this.claimsElement);
		}
		
		this.claimsElement.setDialectAttribute(dialectURI);
		this.claimsElement.addClaims(claims);
	}
	
	/**
	 * Sets the dialect attribute value of the <code>wst:Claims</code> element
	 * @param dialectURI
	 */
	public void setClaimsDialectAttr(String dialectURI) {
		if(this.claimsElement == null){
			this.claimsElement = new Claims(this.document);
			this.addChild(this.claimsElement);
		}
		
		this.claimsElement.setDialectAttribute(dialectURI);
	}
	
	/**
	 * Sets the <code>wst:Renewing</code> element of the 
	 * <code>wst:RequestSecurityToken</code>
	 * @param allow
	 * @param ok
	 */
	public void setRenewing(boolean allow, boolean ok) {
		if(this.renewingElement == null) {
			this.renewingElement = new Renewing(this.document);
			this.addChild(this.renewingElement);
		}
		
		this.renewingElement.setAllow(allow);
		this.renewingElement.setOK(ok);
	}
	

	/**
	 * Returns the <code>AppliesTo</code> element
	 * @return
	 */
	public AppliesTo getAppliesToElement() {
		return appliesToElement;
	}
	
	/**
	 * Returns the <code>Claims</code> element
	 * @return
	 */
	public Claims getClaimsElement() {
		return claimsElement;
	}
	
	/**
	 * Returns the <code>Entropy</code> element
	 * @return
	 */
	public Entropy getEntropyElement() {
		return entropyElement;
	}
	
	/**
	 * Returns the <code>KeySize</code> element
	 * @return
	 */
	public KeySize getKeySizeElement() {
		return keySizeElement;
	}
	
	/**
	 * Returns the <code>Lifetime</code>
	 * @return
	 */
	public Lifetime getLifetimeElement() {
		return lifetimeElement;
	}
	
	/**
	 * Returns the <code>Renewing</code> element
	 * @return
	 */
	public Renewing getRenewingElement() {
		return renewingElement;
	}
	
	/**
	 * Handle the serialization of child elements specific to this type
	 * @see org.apache.ws.sandbox.security.trust.message.token.RequestSecurityToken#handleSpecificChildren(org.w3c.dom.Element)
	 */
	protected void handleSpecificChildren(Element elem) throws WSTrustException {
		QName el =  new QName(elem.getNamespaceURI(), elem.getLocalName());
		
		if(el.equals(AppliesTo.TOKEN)) {
			this.appliesToElement = new AppliesTo(elem);
		} else if(el.equals(Claims.TOKEN)) {
			this.claimsElement = new Claims(elem);			
		} else if(el.equals(Entropy.TOKEN)) {
			this.entropyElement = new Entropy(elem);
		} else if(el.equals(Lifetime.TOKEN)) {
			this.lifetimeElement = new Lifetime(elem);
		} else if(el.equals(KeySize.TOKEN)) {
			this.keySizeElement = new KeySize(elem);
		} else if(el.equals(Renewing.TOKEN)) {
			this.renewingElement = new Renewing(elem);
		} else {
        	throw new WSTrustException(WSTrustException.INVALID_REQUEST,
        			WSTrustException.DESC_INCORRECT_CHILD_ELEM,
					new Object[] {
        			TOKEN.getPrefix(),TOKEN.getLocalPart(),
					el.getNamespaceURI(),el.getLocalPart()});
		}
		
	}
}
