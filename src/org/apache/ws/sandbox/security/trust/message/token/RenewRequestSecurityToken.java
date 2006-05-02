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

import org.apache.ws.sandbox.security.trust.TrustConstants;
import org.apache.ws.sandbox.security.trust.WSTrustException;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;

/**
 * This is the class to be used to enerate a RequestSecurityToken for the 
 * RST renewal binding
 *
 * Additinal child elemets required for a renewal request is provided here
 * 
 * NOTE: This should no tbe used in requesting a renewable security token
 * In such a situation IssueRequestSecurityToken should be used setting the
 * renewal properties
 * 
 * @see org.apache.ws.sandbox.security.trust.TrustConstants#RENEW_SECURITY_TOKEN
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class RenewRequestSecurityToken extends RequestSecurityToken {

	private RenewTarget renewTargetElement;
	private AllowPostdating allowPostdatingElement;
	
	private Lifetime lifetimeElement;
	
	/**
	 * @param doc
	 * @param requestType
	 */
	public RenewRequestSecurityToken(Document doc) {
		super(doc, TrustConstants.RENEW_SECURITY_TOKEN);
	}

	/**
	 * @param elem
	 * @throws WSSecurityException
	 */
	public RenewRequestSecurityToken(Element elem) throws WSTrustException {
		super(elem);
	}
	
	/**
	 * Set a custom token as the token being renewed
	 * @param tokenToBeRenewed
	 */
	public void setRenewTarget(Element tokenBeingRenewed) {
		if(this.renewTargetElement == null) {
			this.renewTargetElement = new RenewTarget(this.document);
			this.addChild(this.renewTargetElement);
		}
		this.renewTargetElement.setTokenToBeRenewed(tokenBeingRenewed);
	}
	
	/**
	 * sets a <code>wsse:SecurityTokenReference</code> in the
	 * <code>wst:RenewTarget</code> element
	 * @see SecurityTokenReference
	 * @param securityTokenReference
	 */
	public void setRenewTarget(SecurityTokenReference securityTokenReference) {
		if(this.renewTargetElement == null) {
			this.renewTargetElement = new RenewTarget(this.document);
			this.addChild(this.renewTargetElement);
		}
		this.renewTargetElement.setSecurityTokenReference(securityTokenReference);
	}

	public void setAllowPostdating() {
		if(this.allowPostdatingElement == null) {
			this.allowPostdatingElement = new AllowPostdating(this.document);
			this.addChild(this.allowPostdatingElement);
		}
		
	}

	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.RequestSecurityToken#handleSpecificChildren(org.w3c.dom.Element)
	 */
	protected void handleSpecificChildren(Element elem) throws WSTrustException {
		QName el =  new QName(elem.getNamespaceURI(), elem.getLocalName());
		
		if(el.equals(RenewTarget.TOKEN)) {
			this.renewTargetElement = new RenewTarget(elem);
		} else if(el.equals(AllowPostdating.TOKEN)) {
			this.allowPostdatingElement = new AllowPostdating(elem);
		} else if(el.equals(Lifetime.TOKEN)) {
			this.lifetimeElement = new Lifetime(elem);
		} else {
        	throw new WSTrustException(WSTrustException.INVALID_REQUEST,
        			WSTrustException.DESC_INCORRECT_CHILD_ELEM,
					new Object[] {
        			TOKEN.getPrefix(),TOKEN.getLocalPart(),
					el.getNamespaceURI(),el.getLocalPart()});
		}
	}
}
