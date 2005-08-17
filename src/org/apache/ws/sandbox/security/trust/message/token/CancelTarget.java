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
import org.w3c.dom.Text;

/**
 * The <code>wst:CancelTarget</code> element
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class CancelTarget extends AbstractToken {

	
    public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.CANCEL_TARGET_LN, TrustConstants.WST_PREFIX);
	
    private Element targetToken;
    private SecurityTokenReference securityTokenReference;
    
	/**
	 * @param doc
	 */
	public CancelTarget(Document doc, SecurityTokenReference securityTokenReference) {
		super(doc);
		this.securityTokenReference = securityTokenReference;
		this.element.appendChild(this.securityTokenReference.getElement());
	}
	
	/**
	 * @param doc
	 */
	public CancelTarget(Document doc, Element targetToken) {
		super(doc);
		this.targetToken = targetToken;
		this.element.appendChild(this.targetToken);
	}
	

	/**
	 * @param elem
	 * @throws WSSecurityException
	 */
	public CancelTarget(Element elem) throws WSTrustException {
		super(elem);
	}


	/**
	 * Sets a token as the token to be cancelled
	 * @param targetToken
	 */
	public void setCancelTarget(Element targetToken) {
		if(this.securityTokenReference != null)
			this.element.removeChild(this.securityTokenReference.getElement());
		if(this.targetToken != null)
			this.element.removeChild(this.targetToken);
		
		this.targetToken = targetToken;
		this.element.appendChild(this.targetToken);
	}
	
	/**
	 * Sets the given security token reference as the cancel target
	 * @param securityTokenReference
	 */
	public void setCancelTarget(SecurityTokenReference securityTokenReference) {
		if(this.securityTokenReference != null)
			this.element.removeChild(this.securityTokenReference.getElement());
		if(this.targetToken != null)
			this.element.removeChild(this.targetToken);
		
		this.securityTokenReference = securityTokenReference;
		this.element.appendChild(this.securityTokenReference.getElement());
	}
	
	/**
	 * Returns the security token reference to the token to be cancelled
	 * @return
	 */
	public SecurityTokenReference getSecurityTokenReference() {
		return securityTokenReference;
	}
	
	/**
	 * Returns the target token to be cancelled
	 * @return
	 */
	public Element getTargetToken() {
		return targetToken;
	}
	/**
	 * Returns the QName of this type
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
