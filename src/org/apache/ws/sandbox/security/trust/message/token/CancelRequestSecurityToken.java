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
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.sandbox.security.trust.TrustConstants;
import org.apache.ws.sandbox.security.trust.WSTrustException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * This is the class to be used to enerate a RequestSecurityToken for the 
 * RST cancel binding
 * 
 * The additional child elements required for a cancel request is provided here
 * 
 * @see org.apache.ws.sandbox.security.trust.TrustConstants#CANCEL_SECURITY_TOKEN
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class CancelRequestSecurityToken extends RequestSecurityToken {

	private CancelTarget cancelTargetElement;
	
	/**
	 * Creates a new <code>wst:RequestSecurityToken</code> element
	 * setting the given element as the cancel target
	 * @param doc
	 * @param targetElement
	 */
	public CancelRequestSecurityToken(Document doc, Element targetElement) {
		super(doc, TrustConstants.CANCEL_SECURITY_TOKEN);
		this.cancelTargetElement = new CancelTarget(this.document,targetElement);
		this.addChild(this.cancelTargetElement);
	}

	/**
	 * @param elem
	 * @throws WSSecurityException
	 */
	public CancelRequestSecurityToken(Element elem) throws WSTrustException {
		super(elem);
	}

	/**
	 * Sets the given element as the cancel target
	 * @param targetToken
	 */
	public void setCancelTarget(Element targetToken) {
		if(this.cancelTargetElement == null) {
			this.cancelTargetElement = new CancelTarget(this.document,targetToken);
			this.addChild(this.cancelTargetElement);
		}
		this.cancelTargetElement.setCancelTarget(targetToken);
	}
	
	/**
	 * Sets the given security token reference as the cancel target
	 * NOTE: This method is not necessary but for the completeness sake this was included
	 * This is because the DOM element of the SecurityTokenReference element
	 * can be set as the cancel target, But this will be useful if something is to be 
	 * changed with the SecurityTokenReference
	 * @param securityTokenReference
	 */
	public void setCancelTarget(SecurityTokenReference securityTokenReference) {
		if(this.cancelTargetElement == null) {
			this.cancelTargetElement = new CancelTarget(this.document,securityTokenReference);
			this.addChild(this.cancelTargetElement);
		}
		this.cancelTargetElement.setCancelTarget(securityTokenReference);
	}

	/**
	 * Handle the serialization of child elements specific to this type
	 * @see org.apache.ws.sandbox.security.trust.message.token.RequestSecurityToken#handleSpecificChildren(org.w3c.dom.Element)
	 */
	protected void handleSpecificChildren(Element elem) throws WSTrustException {
		QName el =  new QName(elem.getNamespaceURI(), elem.getLocalName());
		
		if(el.equals(CancelTarget.TOKEN)) {
			this.cancelTargetElement = new CancelTarget(elem);
		} else {
        	throw new WSTrustException(WSTrustException.INVALID_REQUEST,
        			WSTrustException.DESC_INCORRECT_CHILD_ELEM,
					new Object[] {
        			TOKEN.getPrefix(),TOKEN.getLocalPart(),
					el.getNamespaceURI(),el.getLocalPart()});
		}
	}
}
