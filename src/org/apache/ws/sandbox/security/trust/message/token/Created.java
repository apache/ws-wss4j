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

import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.WSTrustException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class Created extends ValueElement {

	public static final QName TOKEN = new QName(TrustConstants.WSU_NS, TrustConstants.CREATED_LN, TrustConstants.WSU_PREFIX);
	
	/**
	 * @param doc
	 */
	public Created(Document doc) {
		super(doc);
	}

	/**
	 * @param elem
	 * @throws WSTrustException
	 */
	public Created(Element elem) throws WSTrustException {
		super(elem);
	}

	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#getToken()
	 */
	protected QName getToken() {
		return TOKEN;
	}

}
