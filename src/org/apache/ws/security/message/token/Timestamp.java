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

package org.apache.ws.security.message.token;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.TimeZone;
import java.util.Date;
import java.util.Vector;

/**
 * Timestamp according to SOAP Message Security 1.0,
 * chapter 10 / appendix A.2
 * <p/>
 *
 * @author Christof Soehngen (christof.soehngen@syracom.de)
 */
public class Timestamp {

    protected Element element = null;
    protected Element elementCreated = null;
    protected Element elementExpires = null;
    protected Vector customElements = null;

    protected Calendar created;
    protected Calendar expires;

    /**
     * Constructs a <code>Timestamp</code> object and parses the
     * <code>wsu:Timestamp</code> element to initialize it.
     *
     * @param elem the <code>wsu:Timestamp</code> element that
     *             contains the timestamp data
     */
    public Timestamp(WSSConfig wssConfig, Element element) throws WSSecurityException {

        customElements = new Vector();

        String strCreated = "";
        String strExpires = "";

        created = Calendar.getInstance();
        expires = Calendar.getInstance();

        for (Node currentChild = element.getFirstChild();
             currentChild != null;
             currentChild = currentChild.getNextSibling()) {
            if (currentChild instanceof Element) {
                if (WSConstants.CREATED_LN.equals(currentChild.getLocalName()) &&
                        wssConfig.getWsuNS().equals(currentChild.getNamespaceURI())) {
                    strCreated = ((Text) ((Element) currentChild).getFirstChild()).getData();
                } else if (WSConstants.EXPIRES_LN.equals(currentChild.getLocalName()) &&
                        wssConfig.getWsuNS().equals(currentChild.getNamespaceURI())) {
                    strExpires = ((Text) ((Element) currentChild).getFirstChild()).getData();
                } else {
                    customElements.add((Element) currentChild);
                }
            }
        }

        SimpleDateFormat zulu = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        zulu.setTimeZone(TimeZone.getTimeZone("UTC"));

        try {
            created.setTime(zulu.parse(strCreated));
            expires.setTime(zulu.parse(strExpires));
        } catch (ParseException e) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY,
                    "invalidTimestamp",
                    null, e);
        }
    }

    /**
     * Constructs a <code>Timestamp</code> object according
     * to the defined parameters.
     * <p/>
     *
     * @param doc the SOAP envelope as <code>Document</code>
     * @param ttl the time to live (validity of the security semantics) in seconds
     */
    public Timestamp(WSSConfig wssConfig, Document doc, int ttl) {

        customElements = new Vector();

        element =
                doc.createElementNS(wssConfig.getWsuNS(),
                        WSConstants.WSU_PREFIX
                + ":"
                + WSConstants.TIMESTAMP_TOKEN_LN);
        WSSecurityUtil.setNamespace(element,
                wssConfig.getWsuNS(),
                WSConstants.WSU_PREFIX);

        SimpleDateFormat zulu = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        zulu.setTimeZone(TimeZone.getTimeZone("UTC"));
        Calendar rightNow = Calendar.getInstance();

        elementCreated =
                doc.createElementNS(wssConfig.getWsuNS(),
                        WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN);
        WSSecurityUtil.setNamespace(elementCreated,
                wssConfig.getWsuNS(),
                WSConstants.WSU_PREFIX);
        elementCreated.appendChild(doc.createTextNode(zulu.format(rightNow.getTime())));
        element.appendChild(elementCreated);
        if (ttl != 0) {
            long currentTime = rightNow.getTime().getTime();
            currentTime += ttl * 1000;
            rightNow.setTime(new Date(currentTime));

            elementExpires =
                    doc.createElementNS(wssConfig.getWsuNS(),
                            WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN);
            WSSecurityUtil.setNamespace(elementExpires,
                    wssConfig.getWsuNS(),
                    WSConstants.WSU_PREFIX);
            elementExpires.appendChild(doc.createTextNode(zulu.format(rightNow.getTime())));
            element.appendChild(elementExpires);
        }
    }

    /**
     * Returns the dom element of this <code>Timestamp</code> object.
     *
     * @return the <code>wsse:UsernameToken</code> element
     */
    public Element getElement() {
        return this.element;
    }

    /**
     * Returns the string representation of the token.
     *
     * @return a XML string representation
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }

    /**
     * Get the time of creation.
     * <p/>
     *
     * @return
     */
    public Calendar getCreated() {
        return created;
    }

    /**
     * Get the time of expiration.
     * <p/>
     *
     * @return
     */
    public Calendar getExpires() {
        return expires;
    }

    /**
     * Creates and adds a custom element to this Timestamp
     */
    public void addCustomElement(Document doc, Element customElement) {
        customElements.add(customElement);
        element.appendChild(customElement);
    }

    /**
     * Get the the custom elements from this Timestamp
     *
     * @return the vector containing the custom elements.
     */
    public Vector getCustomElements() {
        return this.customElements;
    }
}
