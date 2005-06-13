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

import org.apache.ws.security.trust.WSTrustException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

/**
 * This is the base class for the elements that carries a
 * value in the element
 * Example:
 * 	<wsu:Created>...</wsu:Created>
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public abstract class ValueElement extends AbstractToken {

	protected Text valueText;
	
	/**
	 * @param doc
	 */
	public ValueElement(Document doc) {
		super(doc);
	}

	/**
	 * @param elem
	 * @throws WSTrustException
	 */
	public ValueElement(Element elem) throws WSTrustException {
		super(elem);
	}


	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#deserializeChildElement(org.w3c.dom.Element)
	 */
	protected void deserializeChildElement(Element elem)
			throws WSTrustException {
		//There cannot be any children in this token
		throw new WSTrustException(WSTrustException.INVALID_REQUEST,
				WSTrustException.DESC_CHILD_IN_VALUE_ELEM,
				new Object[] {
				this.getToken().getNamespaceURI(),this.getToken().getLocalPart(),
				elem.getNamespaceURI(),elem.getLocalName()});

	}

	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#setElementTextValue(org.w3c.dom.Text)
	 */
	protected void setElementTextValue(Text textNode) throws WSTrustException {
		this.valueText = textNode;
	}

	/**
	 * Returns the value of the token
	 * @return
	 */
	public String getValue() {
		if(this.valueText != null) 
			return this.valueText.getNodeValue();
		else
			return null;
	}
	
	/**
	 * Sets the value of the token
	 * @param value
	 */
	public void setValue(String value) {
    	if(this.valueText != null)
    		this.element.removeChild(this.valueText);
    	
    	this.valueText = element.getOwnerDocument().createTextNode(value);
        this.element.appendChild(this.valueText);
	}
	
}
