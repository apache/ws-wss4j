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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.WSTrustException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * 
 * @author Dimuthu Leelarathne. (muthulee@yahoo.com)
 * @author Ruchith Fernando
 */
public class Entropy extends CompositeElement {
	private static Log log = LogFactory.getLog(Entropy.class.getName());

	public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.ENTROPY_LN, TrustConstants.WST_PREFIX);

	private BinarySecret binarySecretElement;
	
	/**
	 * Constructor.
	 * <p/>
	 *
	 * @param wssConfig
	 * @param elem
	 * @throws WSSecurityException
	 */
	public Entropy(Element elem) throws WSTrustException {
		super(elem);
	}


	/**
	 * Create a new <code>wst:Entropy</code> element
	 * 
	 * @param doc
	 */
	public Entropy(Document doc) {
		super(doc);
	}


	/**
	 * TODO: IMPORTANT : This method should be removed
	 * set the BinarySecret.
	 * <p/>
	 *
	 * @param secret
	 */
	public void setBinarySecret(BinarySecret secret) {
		this.binarySecretElement = secret;
	}

	/**
	 * Sets the binary secret value
	 * @param type The type uri of the binary secret as a <code>String</code>
	 * @param secretValue The binary secret value as a <code>String</code>
	 */
	public void setBinarySecret(String type, String secretValue) {
		if(this.binarySecretElement == null) {
			this.binarySecretElement = new BinarySecret(this.document);
			this.addChild(this.binarySecretElement);
		}
		
		this.binarySecretElement.setTypeAttribute(type);
		this.binarySecretElement.setValue(secretValue);
	}
	
	/**
	 * 
	 * @return
	 * @throws WSTrustException
	 */
	public BinarySecret getBinarySecret() throws WSTrustException {
		return this.binarySecretElement;
	}
	
	/**
	 * Returns the QName of this type
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#getToken()
	 */
	protected QName getToken() {
		return TOKEN;
	}


	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#deserializeElement(org.w3c.dom.Element)
	 */
	protected void deserializeChildElement(Element elem) throws WSTrustException {
        QName el =  new QName(elem.getNamespaceURI(), elem.getLocalName());
        
        if(el.equals(BinarySecret.TOKEN)) {
        	this.binarySecretElement = new BinarySecret(elem);
        } else {
        	throw new WSTrustException(WSTrustException.INVALID_REQUEST,
        			WSTrustException.DESC_INCORRECT_CHILD_ELEM,
					new Object[] {
        			TOKEN.getPrefix(),TOKEN.getLocalPart(),
					el.getNamespaceURI(),el.getLocalPart()});
        }
		
	}


}
