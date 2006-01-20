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

package org.apache.ws.sandbox.security.trust2;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.message.token.Timestamp;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;

import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

/**
 * @author ddelvecc
 *         <p/>
 *         For indicating the <Lifetime> associated with a token request or response.
 *         This usually includes wsu:Created and wsu:Expires elements
 */
public class Lifetime extends Timestamp {

    /**
     * @param element
     * @throws org.apache.ws.security.WSSecurityException
     *
     */
    public Lifetime(WSSConfig wssConfig, Document doc, Element element) throws WSSecurityException {
        super(element);
        this.element = copyElement(doc, element);
    }

    /**
     * @param doc      The XML document to be used for element creation
     * @param duration Indicates how many seconds in the future this Lifetime Expires
     */
    public Lifetime(WSSConfig wssConfig, Document doc, int duration) {
        super(wssConfig.isPrecisionInMilliSeconds(), doc, duration);
        element = changeElementName(element, TrustConstants.WST_NS, TrustConstants.WST_PREFIX + TrustConstants.LIFETIME);
    }

    /**
     * Constructs a <code>Lifetime</code> object according
     * to the defined parameters.
     * <p/>
     *
     * @param doc     The SOAP envelope as <code>Document</code>
     * @param created The creation time for this lifetime
     * @param expires When this lifetime expires
     */
    public Lifetime(WSSConfig wssConfig, Document doc, Date created, Date expires) {
        super(wssConfig.isPrecisionInMilliSeconds(), doc, 0);

        element = doc.createElementNS(TrustConstants.WST_NS, TrustConstants.WST_PREFIX + TrustConstants.LIFETIME);
        WSSecurityUtil.setNamespace(element, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);

        SimpleDateFormat zulu = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        zulu.setTimeZone(TimeZone.getTimeZone("GMT"));
        Calendar rightNow = Calendar.getInstance();
        if (created == null)
            created = rightNow.getTime();

        Element elementCreated = doc.createElementNS(WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN);
        WSSecurityUtil.setNamespace(elementCreated, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
        elementCreated.appendChild(doc.createTextNode(zulu.format(created)));
        element.appendChild(elementCreated);

        if (expires == null)
            expires = created;

        Element elementExpires = doc.createElementNS(WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN);
        WSSecurityUtil.setNamespace(elementExpires, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
        elementExpires.appendChild(doc.createTextNode(zulu.format(expires)));
        element.appendChild(elementExpires);

        this.created = Calendar.getInstance();
        this.expires = Calendar.getInstance();
        this.created.setTime(created);
        this.expires.setTime(expires);
    }

    public Element getElement(Document doc) {
        return copyElement(doc, element);
    }

    protected Element copyElement(Document doc, Element oldElement) {
        // Make a copy of the element subtree suitable for inserting into doc
        return (Element) doc.importNode(oldElement, true);
    }

    protected Element changeElementName(Document doc, Element oldElement, String newNamespace, String newQualName) {
        // Create an element with the new name
        Element element2 = doc.createElementNS(newNamespace, newQualName);
    
        // Copy the attributes to the new element
        NamedNodeMap attrs = oldElement.getAttributes();
        for (int i = 0; i < attrs.getLength(); i++) {
            Attr attr2 = (Attr) doc.importNode(attrs.item(i), true);
            element2.getAttributes().setNamedItem(attr2);
        }
    
        // Move all the children
        while (oldElement.hasChildNodes()) {
            element2.appendChild(oldElement.getFirstChild());
        }

        return element2;
    }

    protected Element changeElementName(Element oldElement, String newNamespace, String newQualName) {
        return changeElementName(oldElement.getOwnerDocument(), oldElement, newNamespace, newQualName);
    }
}
