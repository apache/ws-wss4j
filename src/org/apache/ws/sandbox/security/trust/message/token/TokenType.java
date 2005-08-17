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

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.sandbox.security.trust.TrustConstants;
import org.apache.ws.sandbox.security.trust.WSTrustException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;

/**
 * @author Malinda Kaushalye
 * @author Ruchith Fernando
 *         <p/>
 *         TokenType element
 */
public class TokenType extends AbstractToken {
	
    public static final String UNT = "http://schemas.xmlsoap.org/ws/2004/04/security/sc/unt";
    public static final String SCT = "http://schemas.xmlsoap.org/ws/2004/04/security/sc/sct";

    public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.TOKEN_TYPE_LN, TrustConstants.WST_PREFIX);
    
    private Text valueText;

    /**
     * Constructor for TokenType
     *
     * @param elem
     * @throws WSSecurityException
     */
    public TokenType(Element elem) throws WSTrustException {
    	super(elem);
    }

    /**
     * Constructor for TokenType
     *
     * @param doc
     */
    public TokenType(Document doc) {
        super(doc);
    }

    /**
     * Set the TokenType value
     *
     * @param val
     */
    public void setValue(String val) {
        if(this.valueText != null)
        	this.element.removeChild(this.valueText);
        
        this.valueText = element.getOwnerDocument().createTextNode(val);
    	this.element.appendChild(this.valueText);
    }
    
    /**
     * This will return the text node of the element
     *
     * @return
     */
    public String getValue() {
    	if(this.valueText != null)
    		return this.valueText.getNodeValue();
    	else
    		return null;
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
		// TODO Auto-generated method stub
		
	}

	/* (non-Javadoc)
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#deserializeElementText(org.w3c.dom.Text)
	 */
	protected void setElementTextValue(Text textNode) {
		// TODO Auto-generated method stub
		
	}
}
