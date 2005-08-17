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

import org.apache.ws.sandbox.security.trust.WSTrustException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

/**
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public abstract class CompositeElement extends AbstractToken {

	/**
	 * @param doc
	 */
	public CompositeElement(Document doc) {
		super(doc);
	}

	/**
	 * @param elem
	 * @throws WSTrustException
	 */
	public CompositeElement(Element elem) throws WSTrustException {
		super(elem);
	}

	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#setElementTextValue(org.w3c.dom.Text)
	 */
	protected void setElementTextValue(Text textNode) throws WSTrustException {
		throw new WSTrustException(WSTrustException.INVALID_REQUEST,
				WSTrustException.DESC_TEXT_IN_COMPOSITE_ELEM,
				new Object[]{this.getToken().getNamespaceURI(),
				this.getToken().getLocalPart(),
				textNode.getNodeValue()});
	}

}
