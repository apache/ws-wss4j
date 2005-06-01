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
 * @author Malinda
 * @author Ruchith Fernando
 *         Code token
 * @see org.apache.ws.security.trust.message.token.Status
 */
public class Code extends AbstractToken {

	public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.CODE_LN, TrustConstants.WST_PREFIX);
    
    private Text valueText = null;

    /**
     * Constructor for Code
     *
     * @param elem
     * @throws WSSecurityException
     */
    public Code(Element elem) throws WSSecurityException {
        super(elem);
    }

    /**
     * Constructor for Code
     *
     * @param doc
     */
    public Code(Document doc) {
        super(doc);
    }

    /**
     * Constructor for Code
     *
     * @param doc
     * @param value Text to be inserted to Code
     */
    public Code(Document doc, String value) {
    	super(doc);
    	this.valueText = doc.createTextNode(value);
        this.element.appendChild(this.valueText);
    }

    /**
     * Sets the Text node
     *
     * @param val
     */
    public void setValue(String val) {
    	if(this.valueText != null)
    		this.element.removeChild(this.valueText);
    	
    	this.valueText = this.element.getOwnerDocument().createTextNode(val);
    	this.element.appendChild(this.valueText);
    }
    
    /**
     * @return value of the Code element
     */
    public String getValue() {
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

}
