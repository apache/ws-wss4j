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
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;

/**
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class RenewTarget extends CompositeElement {
	
    public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.RENEW_TARGET_LN, TrustConstants.WST_PREFIX);

    private Element tokenToBeRenewed;
    private SecurityTokenReference securityTokenReference;
    
    public RenewTarget(Element elem) throws WSTrustException {
    	super(elem);
    }
    
    public RenewTarget(Document doc) {
        super(doc);
    }
    
	/**
	 * Returns the <code>wsse:SecurityTokenReference</code>
	 * @return
	 */    
	public SecurityTokenReference getSecurityTokenReference() {
		return securityTokenReference;
	}
	
	/**
	 * Sets a <code>wsse:SecurityTokenReference</code>
	 * @param securityTokenReference
	 */
	public void setSecurityTokenReference(SecurityTokenReference securityTokenReference) {
		if(this.tokenToBeRenewed != null)//If there's another token remove it
			this.element.removeChild(this.tokenToBeRenewed);
		if(this.securityTokenReference != null)//IF there's sec tok ref remove it
			this.element.removeChild(this.securityTokenReference.getElement());
		this.securityTokenReference = securityTokenReference;
		this.element.appendChild(this.securityTokenReference.getElement());
	}
	
	/**
	 * Returns the token to be renewed
	 * @return
	 */
	public Element getTokenToBeRenewed() {
		return tokenToBeRenewed;
	}
	
	/**
	 * Sets the token to be renewed
	 * @param tokenToBeRenewed
	 */
	public void setTokenToBeRenewed(Element tokenToBeRenewed) {
		if(this.securityTokenReference != null)//if there's wsse:SecurityTokenReference remove it
			this.element.removeChild(this.securityTokenReference.getElement());
		if(this.tokenToBeRenewed != null)//If there's some token remove it
			this.element.removeChild(this.tokenToBeRenewed);
		this.tokenToBeRenewed = tokenToBeRenewed;
		this.element.appendChild(this.tokenToBeRenewed);
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
	protected void deserializeChildElement(Element elem) throws WSTrustException {
        QName el =  new QName(elem.getNamespaceURI(), elem.getLocalName());
        
        QName secTokRef = new QName(WSConstants.WSSE_NS, SecurityTokenReference.SECURITY_TOKEN_REFERENCE);

        if(el.equals(secTokRef) && this.tokenToBeRenewed == null) {
        	try {
        	this.securityTokenReference = new SecurityTokenReference(elem);
        	} catch (WSSecurityException ex) {
        		throw new WSTrustException(WSTrustException.INVALID_REQUEST, ex.getMessage());
        	}
        } else if(this.securityTokenReference == null) {
        	this.tokenToBeRenewed = elem;
        }
	}

}
