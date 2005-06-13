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

/**
/**
 * This is the class to be used to enerate a RequestSecurityToken for the 
 * RST validation binding
 * 
 * Even though the ES-Trust spec does not directly specify any specific 
 * child elements for this RST element, this can be used to extend the 
 * fuctionality 
 * 
 * @see org.apache.ws.security.trust.TrustConstants#RENEW_SECURITY_TOKEN
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class ValidateRequestSecurityToken extends RequestSecurityToken {

	
	/**
	 * @param doc
	 * @param requestType
	 */
	public ValidateRequestSecurityToken(Document doc) {
		super(doc, TrustConstants.VALIDATE_SECURITY_TOKEN);
	}

	/**
	 * @param elem
	 * @throws WSSecurityException
	 */
	public ValidateRequestSecurityToken(Element elem) throws WSTrustException {
		super(elem);
	}

	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.RequestSecurityToken#handleSpecificChildren(org.w3c.dom.Element)
	 */
	protected void handleSpecificChildren(Element elem) throws WSTrustException {
		
		QName el =  new QName(elem.getNamespaceURI(), elem.getLocalName());
		
    	throw new WSTrustException(WSTrustException.INVALID_REQUEST,
    			WSTrustException.DESC_INCORRECT_CHILD_ELEM,
				new Object[] {
    			TOKEN.getPrefix(),TOKEN.getLocalPart(),
				el.getNamespaceURI(),el.getLocalPart()});
		
	}

}
