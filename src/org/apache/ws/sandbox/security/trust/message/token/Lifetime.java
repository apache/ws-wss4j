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
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author Malinda Kaushalye
 * @author Ruchith Fernando
 *         Lifetime token
 */

public class Lifetime extends AbstractToken {

    public Element created;
    public Element expires;

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
        this.created = doc.createElementNS(TrustConstants.WST_NS, "wst:" + TrustConstants.CREATED_LN);
        this.expires = doc.createElementNS(TrustConstants.WST_NS, "wst:" + TrustConstants.EXPIRES_LN);

        this.created.appendChild(doc.createTextNode(created));
        this.expires.appendChild(doc.createTextNode(expires));
        this.element.appendChild(this.created);
        this.element.appendChild(this.expires);
    }

    /**
     * Constructor for Lifetime
     * Check for created and epires elements
     *
     * @param elem
     * @throws WSSecurityException
     */
    public Lifetime(Element elem) throws WSSecurityException {
    	super(elem);

        this.created =
                (Element) WSSecurityUtil.getDirectChild(elem,
                        TrustConstants.CREATED_LN,
                        TrustConstants.WST_NS);
        this.expires =
                (Element) WSSecurityUtil.getDirectChild(elem,
                        TrustConstants.EXPIRES_LN,
                        TrustConstants.WST_NS);

    }

    /**
     * Constructor for Lifetime
     *
     * @param doc
     * @param duration in minutes
     */
    //new

    public Lifetime(Document doc, int duration) {
    	super(doc);
    	
        SimpleDateFormat sdtf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        sdtf.setTimeZone(TimeZone.getTimeZone("GMT"));
        Calendar rightNow = Calendar.getInstance();
        Calendar expires = Calendar.getInstance();
        this.created = doc.createElementNS(TrustConstants.WST_NS, TrustConstants.WST_PREFIX + ":" + TrustConstants.CREATED_LN);
        WSSecurityUtil.setNamespace(this.created, TOKEN.getNamespaceURI(), TrustConstants.WST_PREFIX);
        this.expires = doc.createElementNS(TrustConstants.WST_NS, TrustConstants.WST_PREFIX + ":" + TrustConstants.EXPIRES_LN);
        WSSecurityUtil.setNamespace(this.expires, TOKEN.getNamespaceURI(), TrustConstants.WST_PREFIX);
        this.created.appendChild(doc.createTextNode(sdtf.format(rightNow.getTime())));

        long exp = rightNow.getTimeInMillis() + duration * 1000 * 60;
        expires.setTimeInMillis(exp);

        this.expires.appendChild(doc.createTextNode(sdtf.format(expires.getTime())));
        this.element.appendChild(this.created);
        this.element.appendChild(this.expires);

    }

    /**
     * @return
     */
    public Element getCreated() {
        return created;
    }

    /**
     * @return
     */
    public Element getExpires() {
        return expires;
    }

    /**
     * @param element
     */
    public void setCreated(Element element) {
        created = element;
    }


    /**
     * @param element
     */
    public void setExpires(Element element) {
        expires = element;
    }
    
	/**
	 * Returns the QName of this type
	 * @see org.apache.ws.security.trust.message.token.AbstractToken#getToken()
	 */
	protected QName getToken() {
		return TOKEN;
	}
}
