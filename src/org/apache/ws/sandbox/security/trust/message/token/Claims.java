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
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

/**
 * <code>wst:Claims</code> token
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class Claims extends AbstractToken {
	
	public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.CLAIMS_LN, TrustConstants.WST_PREFIX);

	private String dialectArrtValue = null;
	private Text valueText = null;
	
	
	public Claims(Document doc) {
		super(doc);
	}
	
	public Claims(Element elem) throws WSSecurityException {
        super(elem);	
	}
	/**
	 * Sets the value of this <code>wst:Claims</code> element
	 * @param value
	 */
	public void setValue(String value) {
		if(this.valueText != null)
			this.element.removeChild(this.valueText);
		
		this.valueText = this.element.getOwnerDocument().createTextNode(value);
		this.element.appendChild(this.valueText);
	}
	
	/**
	 * Returns the value of the <code>wst:Claims</code> element
	 * @return
	 */
	public String getValue() {
		if(this.valueText != null)
			return this.valueText.getNodeValue();
		else 
			return null;
	}
	
	/**
	 * Set the value of the wst:Claims/@Dialect
	 * @param value
	 */
	public void setDialectAttribute(String value) {
		if(this.dialectArrtValue != null)
			this.element.removeAttribute(TrustConstants.CLAIMS_DIALECT_ATTR);
		
		this.dialectArrtValue = value;
		this.element.setAttribute(TrustConstants.CLAIMS_DIALECT_ATTR, this.dialectArrtValue);
		
	}
	
	/**
	 * Returns the value of the <code>Dialect</code> attribute
	 * @return
	 */
	public String getDialectAttribute() {
		return this.dialectArrtValue;
	}
	
	/**
	 * Returns the QName of this type
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#getToken()
	 */
	protected QName getToken() {
		return TOKEN;
	}
}
