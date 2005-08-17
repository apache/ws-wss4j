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

import org.apache.ws.sandbox.security.trust.TrustConstants;
import org.apache.ws.sandbox.security.trust.WSTrustException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * <code>wst:Claims</code> token
 * Example token
 * <pre>
  <Claims>
      <SubjectName MatchType="...">...</SubjectName>
      <X509Extension OID="..." Critical="..." MatchType="...">
        ...
      </X509Extension>
  </Claims>
  </pre> 
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class Claims extends CompositeElement {
	
	public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.CLAIMS_LN, TrustConstants.WST_PREFIX);

		
	public Claims(Document doc) {
		super(doc);
	}
	
	public Claims(Element elem) throws WSTrustException {
        super(elem);	
	}
	
	/**
	 * Set the value of the wst:Claims/@Dialect
	 * @param value
	 */
	public void setDialectAttribute(String value) {
//		Will worry about null/removing attribute values later
//		if(value == null) {
//			if(this.element.getAttribute(TrustConstants.CLAIMS_DIALECT_ATTR) == null)
//				this.element.removeAttribute(TrustConstants.CLAIMS_DIALECT_ATTR);
//		}
		this.element.setAttribute(TrustConstants.CLAIMS_DIALECT_ATTR, value);
		
	}
	
	/**
	 * Returns the value of the <code>Dialect</code> attribute
	 * @return
	 */
	public String getDialectAttribute() {
		return this.element.getAttribute(TrustConstants.CLAIMS_DIALECT_ATTR);
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
		/*
		 * We don't have to do anything since the elemets that
		 * are given in here are custom elements and they can
		 * be retrieved using getTokenByTagNameNS method
		 */
	}
	
	/**
	 * This is provided as an extensibility mechanism to add any
	 * child element to the <code>wst:Claims</code> element
	 * @param childToken
	 */
	public void addToken(Element childToken) {
		this.element.appendChild(childToken);
	}
	
	/**
	 * Adds a list of nodes as children of this 
	 * <code>wst:Claims</code> element
	 * @param claimsList A <code>NodeList</code> of the elements
	 */
	public void addClaims(NodeList claimsList) {
		for (int i = 0; i < claimsList.getLength(); i++) {
			this.element.appendChild(claimsList.item(i));
		}
	}
	
	
	/**
	 * This is provided to be used to extract custom elements from the 
	 * <code>wst:Claims</code>
	 * @param namespace
	 * @param tagName
	 * @return
	 */
	public NodeList getTokensByTagNameNS(String namespace, String tagName) {
		return this.element.getElementsByTagNameNS(namespace, tagName);
	}
	
}
