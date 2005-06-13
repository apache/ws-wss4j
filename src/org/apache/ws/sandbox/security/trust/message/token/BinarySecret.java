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
 *
 * @author Dimuthu Leelarathne.(muthulee@yahoo.com)
 * @author Ruchith Fernando
 */
public class BinarySecret extends ValueElement {
	
    public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.BINARY_SECRET_LN, TrustConstants.WST_PREFIX);
    
    /**
     * Constructor.
     * <p/>
     *
     * @param wssConfig
     * @param elem
     */
    public BinarySecret(Element elem) throws WSTrustException {
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
    	this.element.setAttribute(TrustConstants.BINARY_SECRET_TYPE_ATTR, type);
    }

    /**
     * Returns the type attribute value
     * @return
     */
    public String getTypeAttribute() {
    	return this.element.getAttribute(TrustConstants.BINARY_SECRET_TYPE_ATTR);
    }
    
	/**
	 * This is provided as an extensibility mechnism to as any attrbute 
	 * @param attribute
	 * @param value
	 */
	public void addAttribute(String attribute, String value) {
		this.element.setAttribute(attribute, value);
	}    
    
	/**
	 * This is to be used to retrieve the value of the 
	 * custom attrbutes added
	 * @param attribute
	 * @return
	 */
	public String getAttributeValue(String attribute) {
		return this.element.getAttribute(attribute);		
	}

	/**
	 * Returns the QName of this type
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#getToken()
	 */
	protected QName getToken() {
		return TOKEN;
	}
}
