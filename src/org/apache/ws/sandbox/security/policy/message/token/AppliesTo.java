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

package org.apache.ws.sandbox.security.policy.message.token;
import javax.xml.namespace.QName;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.sandbox.security.trust.TrustConstants;
import org.apache.ws.sandbox.security.trust.WSTrustException;
import org.apache.ws.sandbox.security.trust.message.token.AbstractToken;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
/**
 * @author Malinda Kaushalye
 * @author Ruchith Fernando
 */
public class AppliesTo extends AbstractToken {
	
	public static final QName TOKEN = new QName(TrustConstants.WSP_NS, TrustConstants.APPLIESTO_LN, TrustConstants.WSP_PREFIX);

	/**
	 * The WS-Addressing impl is bound to Apache Axis, therefore the 
	 * org.apache.axis.message.addressing.EndpointReference cannot be used here
	 * since it will bring Axis specific stuff into the common core of wss4j 
	 */
	private Element endpointReferenceElement;
	private Text addressValueText;

	/**
	 * Constructor for AppliesTo
	 * @param elem
	 * @throws WSSecurityException
	 */
	public AppliesTo(Element elem) throws WSTrustException {	
		super(elem);
	}
	
	/**
	 * Constructor for AppliesTo
	 * @param doc
	 */
	public AppliesTo(Document doc) {
		super(doc);
	}

	/**
	 * Set the value of the <code>wsa:EndpointReference/wsa:Address</code>
	 * @param eprValue
	 */
	public void setEndpointReference(String eprValue) {
		if(this.endpointReferenceElement != null)  //If there's an existing element remove it and
			this.element.removeChild(this.endpointReferenceElement);
		
		//Create a new element and add it
		this.endpointReferenceElement = this.element.getOwnerDocument().createElementNS(TrustConstants.WSA_NS, TrustConstants.WSA_PREFIX + ":" + TrustConstants.ENDPOINT_REFERENCE_LN);
		Element tempAddrElem = this.element.getOwnerDocument().createElementNS(TrustConstants.WSA_NS, TrustConstants.WSA_PREFIX + ":" + TrustConstants.ADDRESS_LN);
		
		this.addressValueText = this.element.getOwnerDocument().createTextNode(eprValue);
		tempAddrElem.appendChild(addressValueText);
		this.endpointReferenceElement.appendChild(tempAddrElem);
		this.element.appendChild(endpointReferenceElement);
		
	}
	
	/**
	 * Returns the value of the <code>wsa:EndpointReference/wsa:Address</code>
	 * @return
	 */
	public String getAppliesToAddressEpr() {
		if(this.addressValueText != null)
			return this.addressValueText.getNodeValue();
		else 
			return null;
	}
	
	public void addChildElement(Element elem) {
		this.element.appendChild(elem);
	}
	
	/**
	 * Returns the QName of this type
	 * @see org.apache.ws.sandbox.security.trust.message.token.AbstractToken#getToken()
	 */
	protected QName getToken() {
		return TOKEN;
	}

	/**
	 * Populates the attribute elements with given elements
	 * This method will be called with the child elements of the <code>wsa:AppliesTo</code>
	 * @see org.apache.ws.sandbox.security.trust.message.token.AbstractToken#deserializeChildElement(org.w3c.dom.Element)
	 */
	protected void deserializeChildElement(Element elem) throws WSTrustException {
		if(elem.getNodeName().equals(TrustConstants.WSA_PREFIX + ":" + TrustConstants.ENDPOINT_REFERENCE_LN)) {
			NodeList list = elem.getChildNodes();
			for(int i = 0; i < list.getLength(); i++) {
				Node tempNode = list.item(i);
				if(tempNode.getNodeType() == Node.ELEMENT_NODE) { //This MUST be the Address Element
					NodeList tempNodeList = tempNode.getChildNodes();
					for(int j = 0; j < tempNodeList.getLength(); j++) {
						if(tempNodeList.item(i).getNodeType() == Node.TEXT_NODE) {//This MUST be the Address value
							this.addressValueText = (Text)tempNodeList.item(0);
							this.endpointReferenceElement = elem;
							break;
						}
					}
				} else {
					throw new WSTrustException(WSTrustException.INVALID_REQUEST,
							WSTrustException.DESC_EXPECTED_CHILD_ELEM,
							new Object[]{ 
							TrustConstants.WSA_PREFIX, TrustConstants.ADDRESS_LN, 
							TrustConstants.WSA_PREFIX, TrustConstants.ENDPOINT_REFERENCE_LN});
				}
			}
			

			
		} else {
			//If the Passed elemt is not a wsa:EndpointReference element
			throw new WSTrustException(WSTrustException.INVALID_REQUEST,
					WSTrustException.DESC_EXPECTED_CHILD_ELEM,
					new Object[]{ 
					TrustConstants.WSA_PREFIX, TrustConstants.ENDPOINT_REFERENCE_LN,
					TOKEN.getPrefix(), TOKEN.getLocalPart()});
		}
		
	}

	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#deserializeElementText(org.w3c.dom.Text)
	 */
	protected void setElementTextValue(Text textNode) {
		// No processing required here xince everything is handled in the 
		// deserializeChildElement	
	}
}
