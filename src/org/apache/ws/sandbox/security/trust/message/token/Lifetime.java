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

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;

import javax.xml.namespace.QName;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.trust.TrustConstants;
import org.apache.ws.security.trust.WSTrustException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author Malinda Kaushalye
 * @author Ruchith Fernando
 *         Lifetime token
 */

public class Lifetime extends CompositeElement {
    
    private Created createdElement;
    private Expires expiresElement;

    public static final QName TOKEN = new QName(TrustConstants.WST_NS, TrustConstants.LIFE_TIME_LN, TrustConstants.WST_PREFIX);
    
    /**
     * Constructor for Lifetime
     *
     * @param doc
     * @param created
     * @param expires
     */
    public Lifetime(Document doc, String created, String expires) {
    	super(doc);

    	this.createdElement = new Created(doc);
    	this.createdElement.setValue(created);
    	this.addChild(createdElement);
    	
    	this.expiresElement = new Expires(doc);
    	this.expiresElement.setValue(expires);
    	this.addChild(this.expiresElement);
    }

    /**
     * Constructor for Lifetime
     * Check for created and epires elements
     *
     * @param elem
     * @throws WSSecurityException
     */
    public Lifetime(Element elem) throws WSTrustException {
    	super(elem);
    }

    /**
     * Constructor for Lifetime
     *
     * @param doc
     * @param duration in minutes
     */
    public Lifetime(Document doc, int duration) {
    	super(doc);
    	
        SimpleDateFormat sdtf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdtf.setTimeZone(TimeZone.getTimeZone("GMT"));

        Calendar rightNow = Calendar.getInstance();
        Calendar expires = Calendar.getInstance();
        
        this.createdElement = new Created(doc);
        this.createdElement.setValue(sdtf.format(rightNow.getTime()));
        this.addChild(this.createdElement);
        
        this.expiresElement = new Expires(doc);
        long exp = rightNow.getTimeInMillis() + duration * 1000 * 60;
        expires.setTimeInMillis(exp);
        this.expiresElement.setValue(sdtf.format(expires.getTime()));
        this.addChild(this.expiresElement);
    }
    
    /**
     * Retuns the value of the <code>wsu:Created</code> child element 
     * @return
     */
    public String getCreated() {
    	if(this.createdElement != null)
    		return this.createdElement.getValue();
    	else
    		return null;
    }

    /**
     * Returns the value of the <code>wsu:Expires</code> element
     * @return
     */
    public String getExpires() {
    	if(this.expiresElement!= null)
    		return this.expiresElement.getValue();
    	else
    		return null;
    }

    /**
     * Sets the value of the <code>wsu:Created</code>element
     * @param value
     */
    public void setCreated(String value) {
    	if(this.createdElement != null)
    		this.createdElement.setValue(value);
    	else { 
    		this.createdElement = new Created(this.document);
    		this.createdElement.setValue(value);
    		this.addChild(this.createdElement);
    	}
    }

    /**
     * Sets the value of the <code>wsu:Expires</code> element
     * @param value
     */
    public void setExpires(String value) {
    	if(this.expiresElement != null)
    		this.expiresElement.setValue(value);
    	else { 
    		this.expiresElement = new Expires(this.document);
    		this.expiresElement.setValue(value);
    		this.addChild(this.expiresElement);
    	}
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
	protected void deserializeChildElement(Element elem) throws WSTrustException {
		  QName el =  new QName(elem.getNamespaceURI(), elem.getLocalName());
	        
	        if(el.equals(Created.TOKEN)) {
	        	this.createdElement = new Created(elem);
	        } else if(el.equals(Expires.TOKEN)) {
	        	this.expiresElement = new Expires(elem);
	        } else {
	        	throw new WSTrustException(WSTrustException.INVALID_REQUEST,
	        			WSTrustException.DESC_INCORRECT_CHILD_ELEM,
						new Object[] {
	        			TOKEN.getPrefix(),TOKEN.getLocalPart(),
						el.getNamespaceURI(),el.getLocalPart()});
	        }
	}

}
