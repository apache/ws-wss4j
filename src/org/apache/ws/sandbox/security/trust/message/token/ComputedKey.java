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
import org.w3c.dom.Text;

/**
 * @author Dimuthu Leelarathne. (muthulee@yahoo.com)
 * @author Ruchith Fernando
 */
public class ComputedKey extends AbstractToken {
	
	 public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.COMPUTED_KEY_LN, TrustConstants.WST_PREFIX);
    
	 private Text valueText;
	 
	 /**
	  * Constructor.
	  * <p/>
	  *
	  * @param wssConfig
	  * @param elem
	  */
	 public ComputedKey(Element elem) throws WSTrustException {
	 	super(elem);
	 }

	 /**
	  * Constructor. <p/>
	  * 
	  * @param wssConfig
	  * @param doc
	  */
	 public ComputedKey(Document doc) {
		 super(doc);
	 }

	 /**
	  * Sets the text node
	  *
	  * @param val
	  */
	 public void setComputedKeyValue(String val) {
	 	if(this.valueText != null)
	 		this.element.removeChild(this.valueText);
	 	
	 	this.valueText = element.getOwnerDocument().createTextNode(val);
		this.element.appendChild(this.valueText);
	 }

	 /**
	  * return the value of the text node
	  *
	  * @return
	  */
	 public String getComputedKeyValue() {
	 	if(this.valueText != null)
	 		return this.valueText.getNodeValue();
	 	else
	 		return null;
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
	protected void deserializeChildElement(Element elem) {
		// TODO Auto-generated method stub
		
	}

	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#deserializeElementText(org.w3c.dom.Text)
	 */
	protected void setElementTextValue(Text textNode) {
		// TODO Auto-generated method stub
		
	}

}
