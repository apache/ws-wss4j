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

/**
 * @author Malinda Kaushalye
 * @author Ruchith Fernando
 */
public class Status extends AbstractToken {
	
    public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.STATUS_LN, TrustConstants.WST_PREFIX);
    
    private Code codeElement = null;
    private Reason reasonElement = null;
    

    /**
     * Constructor for Status
     *
     * @param elem
     * @throws WSSecurityException
     */
    public Status(Element elem) throws WSSecurityException {
    	super(elem);
    }

    /**
     * Constructor for Status
     *
     * @param doc
     */
    public Status(Document doc) {
        super(doc);
    }

    /**
     * Sets the code of the status
     *
     * @param code
     */
    public void setCode(String codeValue) {
    	if(this.codeElement != null) //If there's a value already set, remove that element
    		this.element.removeChild(this.codeElement.getElement());

    	this.codeElement = new Code(this.element.getOwnerDocument());
    	this.codeElement.setValue(codeValue);
    	this.element.appendChild(this.codeElement.getElement());
    }

    /**
     * Gets the code of the status
     *
     * @return
     * @throws WSSecurityException
     */
    public String getCode() {
        if(this.codeElement != null)
        	return this.codeElement.getValue();
        else
        	return null;
    }

    /**
     * Sets the reason of the status
     *
     * @param reason
     */
    public void setReason(String reason) {
        if(this.reasonElement != null)
        	this.element.removeChild(this.reasonElement.getElement());
        
        this.reasonElement = new Reason(this.element.getOwnerDocument());
        this.reasonElement.setValue(reason);
        this.element.appendChild(this.reasonElement.getElement());
    }

    /**
     * Gets the reason of the status
     *
     * @return
     * @throws WSSecurityException
     */
    public String getReason() {
    	if(this.reasonElement != null)
    		return this.reasonElement.getValue();
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
