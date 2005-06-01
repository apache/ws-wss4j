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
 * <p/>WS-Trust Spec - ..."This optional element is
 * used to specify renew semantics for types that support this
 * operation."...
 * 
 * Also can be used request for a token that can be renewed.
 */
public class Renewing extends AbstractToken {
	
    public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.RENEWING_LN, TrustConstants.WST_PREFIX);
    
    //to request a renewable token.
    boolean isAllow = true;
    
    //to indicate that a renewable token is    acceptable if the requested duration exceeds the limit of the issuance service.
    boolean isOK = false;

    /**
     * Constructor for Renewing
     *
     * @param elem
     * @throws WSSecurityException
     */
    public Renewing(Element elem) throws WSSecurityException {
    	super(elem);
    }

    /**
     * Constructor for Renewing
     * @param doc
     */
    public Renewing(Document doc) {
        super(doc);
    }

    /**
     * Constructor for Renewing
     *
     * @param doc
     * @param isOK
     * @param isAllow
     */
    public Renewing(Document doc, boolean isOK, boolean isAllow) {
        super(doc);
        
        this.isAllow = isAllow;
        this.isOK = isOK;
        
        this.element.setAttribute(TrustConstants.RENEWING_ALLOW_ATTR, String.valueOf(this.isAllow));
        this.element.setAttribute(TrustConstants.RENEWING_OK_ATTR, String.valueOf(this.isOK));
    }

    public void setAllow(boolean allow) {
        this.isAllow = allow;
        this.element.setAttribute(TrustConstants.RENEWING_ALLOW_ATTR, String.valueOf(allow));
    }

    public boolean getAllow() {
        return this.isAllow;
    }

    public void setOK(boolean isOK) {
        this.isOK = isOK;
        this.element.setAttribute(TrustConstants.RENEWING_OK_ATTR, String.valueOf(isOK));
    }

    public boolean getOK() {
        return this.isOK;
    }
    
	/**
	 * Returns the QName of this type
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#getToken()
	 */
	protected QName getToken() {
		return TOKEN;
	}
}
