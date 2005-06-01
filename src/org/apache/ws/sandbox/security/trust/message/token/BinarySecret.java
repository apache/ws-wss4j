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
 *
 * @author Dimuthu Leelarathne.(muthulee@yahoo.com)
 * @author Ruchith Fernando
 */
public class BinarySecret extends AbstractToken {
	
    public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.BINARY_SECRET_LN, TrustConstants.WST_PREFIX);
    
    private Text secretText = null;
    
    private String typeAttrValue = null;
    
    /**
     * Constructor.
     * <p/>
     *
     * @param wssConfig
     * @param elem
     */
    public BinarySecret(Element elem) throws WSSecurityException {
    	super(elem);
    } 
					

    /**
     * Constructor.
     * <p/>
     *
     * @param wssConfig
     * @param doc
     */
    public BinarySecret(Document doc) {
    	super(doc);
    }

    /**
     * set the Type.
     * Set one of the three types.
     * @param ref
     */
    public void setTypeAttribute(String type) {
    	if(this.typeAttrValue != null)
    		this.element.removeAttribute(TrustConstants.BINARY_SECRET_TYPE_ATTR);
    	
    	this.typeAttrValue=type;
    	this.element.setAttribute(TrustConstants.BINARY_SECRET_TYPE_ATTR, typeAttrValue);
    }

    /**
     * Returns the type attribute value
     * @return
     */
    public String getTypeAttribute() {
    	return this.typeAttrValue;
    }

    /**
     * Sets the text node
     *
     * @param val
     */
    public void setBinarySecretValue(String val) {
    	if(this.secretText != null)
    		this.element.removeChild(this.secretText);
    	
    	this.secretText = element.getOwnerDocument().createTextNode(val);
        this.element.appendChild(this.secretText);
    }

    /**
	 * return the value of the text node
	 * 
	 * @return
	 */
    public String getBinarySecretValue() {
        if(this.secretText != null)
        	return this.secretText.getNodeValue();
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
}
