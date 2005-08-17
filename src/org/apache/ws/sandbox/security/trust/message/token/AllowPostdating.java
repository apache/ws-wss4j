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
import org.apache.ws.sandbox.security.trust.TrustConstants;
import org.apache.ws.sandbox.security.trust.WSTrustException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

/**
 * @author Malinda Kaushalye 
 * @author Ruchith Fernando
 * 
 * AllowPostdating element <p/>This element indicates
 * that returned tokens should allow requests for postdated tokens.
 */
public class AllowPostdating extends ValueElement {
	
    public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.ALLOWPOSTDATING_LN, TrustConstants.WST_PREFIX);

    /**
     * Constructor for AllowPostdating
     *
     * @param elem
     * @throws WSSecurityException
     */
    public AllowPostdating(Element elem) throws WSTrustException {
    	super(elem);
    }

    /**
     * Constructor for AllowPostdating
     *
     * @param doc
     */
    public AllowPostdating(Document doc) {
        super(doc);
    }

	/**
	 * Returns the QName of this type
	 * @see org.apache.ws.sandbox.security.trust.message.token.AbstractToken#getToken()
	 */
	protected QName getToken() {
		return TOKEN;
	}

	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#deserializeElementText(org.w3c.dom.Text)
	 */
	protected void setElementTextValue(Text textNode) throws WSTrustException{
		throw new WSTrustException(WSTrustException.INVALID_REQUEST,
				"There cannot be a value in this element");
	}

}
