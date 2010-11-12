/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ws.security.message.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.util.XmlSchemaDateFormat;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.text.DateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.Vector;

/**
 * Timestamp according to SOAP Message Security 1.0,
 * chapter 10 / appendix A.2
 *
 * @author Christof Soehngen (christof.soehngen@syracom.de)
 */
public class Timestamp {
    
    private final static Log LOG = LogFactory.getLog(Timestamp.class.getName());

    protected Element element = null;
    protected List<Element> customElements = null;
    protected Date createdDate;
    protected Date expiresDate;
    
    /**
     * Constructs a <code>Timestamp</code> object and parses the
     * <code>wsu:Timestamp</code> element to initialize it.
     *
     * @param timestampElement the <code>wsu:Timestamp</code> element that
     *        contains the timestamp data
     */
    public Timestamp(Element timestampElement) throws WSSecurityException {

        element = timestampElement;
        customElements = new Vector<Element>();

        String strCreated = null;
        String strExpires = null;

        for (Node currentChild = element.getFirstChild();
             currentChild != null;
             currentChild = currentChild.getNextSibling()
         ) {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()) {
                Element currentChildElement = (Element) currentChild;
                if (WSConstants.CREATED_LN.equals(currentChild.getLocalName()) &&
                        WSConstants.WSU_NS.equals(currentChild.getNamespaceURI())) {
                    if (strCreated == null) {
                        strCreated = ((Text)currentChildElement.getFirstChild()).getData();
                    } else {
                        throw new WSSecurityException(
                            WSSecurityException.INVALID_SECURITY, "invalidTimestamp"
                        );
                    }
                } else if (WSConstants.EXPIRES_LN.equals(currentChild.getLocalName()) &&
                        WSConstants.WSU_NS.equals(currentChild.getNamespaceURI())) {
                    if (strExpires == null) {
                        strExpires = ((Text)currentChildElement.getFirstChild()).getData();
                    } else {
                        throw new WSSecurityException(
                            WSSecurityException.INVALID_SECURITY, "invalidTimestamp"
                        );                        
                    }
                } else {
                    customElements.add(currentChildElement);
                }
            }
        }

        DateFormat zulu = new XmlSchemaDateFormat();
        try {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Current time: " + zulu.format(Calendar.getInstance().getTime()));
            }
            if (strCreated != null) {
                createdDate = zulu.parse(strCreated);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Timestamp created: " + zulu.format(createdDate));
                }
            }
            if (strExpires != null) {
                expiresDate = zulu.parse(strExpires);
                if (LOG.isDebugEnabled()) {
                    LOG.debug("Timestamp expires: " + zulu.format(expiresDate));
                }
            }
        } catch (ParseException e) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "invalidTimestamp", null, e
            );
        }
    }


    /**
     * Constructs a <code>Timestamp</code> object according
     * to the defined parameters.
     *
     * @param doc the SOAP envelope as <code>Document</code>
     * @param ttl the time to live (validity of the security semantics) in seconds
     */
    public Timestamp(boolean milliseconds, Document doc, int ttl) {

        customElements = new Vector<Element>();
        element = 
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        DateFormat zulu = null;
        if (milliseconds) {
            zulu = new XmlSchemaDateFormat();
        } else {
            zulu = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            zulu.setTimeZone(TimeZone.getTimeZone("UTC"));
        }
        Calendar calendar = getCurrentTime();

        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        createdDate = calendar.getTime();
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        element.appendChild(elementCreated);
        if (ttl != 0) {
            long currentTime = calendar.getTimeInMillis();
            currentTime += ttl * 1000;
            calendar.setTimeInMillis(currentTime);
            expiresDate = calendar.getTime();

            Element elementExpires =
                doc.createElementNS(
                    WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.EXPIRES_LN
                );
            elementExpires.appendChild(doc.createTextNode(zulu.format(expiresDate)));
            element.appendChild(elementExpires);
        }
    }
    
    /**
     * Add the WSU Namespace to this T. The namespace is not added by default for
     * efficiency purposes.
     */
    public void addWSUNamespace() {
        WSSecurityUtil.setNamespace(element, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
    }

    /**
     * Get the current time
     * 
     * @return calendar the current time
     */
    protected Calendar getCurrentTime() {
        return Calendar.getInstance();
    }
    
    /**
     * Returns the dom element of this <code>Timestamp</code> object.
     *
     * @return the <code>wsse:UsernameToken</code> element
     */
    public Element getElement() {
        return element;
    }

    /**
     * Returns the string representation of the token.
     *
     * @return a XML string representation
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) element);
    }

    /**
     * Get the time of creation.
     *
     * @return the "created" time
     */
    public Date getCreated() {
        return createdDate;
    }

    /**
     * Get the time of expiration.
     *
     * @return the "expires" time
     */
    public Date getExpires() {
        return expiresDate;
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
     * @return the list containing the custom elements.
     */
    public List<Element> getCustomElements() {
        return customElements;
    }
    
    /**
     * Set wsu:Id attribute of this timestamp
     * @param id
     */
    public void setID(String id) {
        element.setAttributeNS(WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":Id", id);
    }
    
    /**
     * @return the value of the wsu:Id attribute
     */
    public String getID() {
        return element.getAttributeNS(WSConstants.WSU_NS, "Id");
    }
    
    /**
     * Return true if the current Timestamp is expired, meaning if the "Expires" value
     * is before the current time. It returns false if there is no Expires value.
     */
    public boolean isExpired() {
        if (expiresDate != null) {
            Calendar rightNow = Calendar.getInstance();
            return expiresDate.before(rightNow.getTime());
        }
        return false;
    }
    
    
    /**
     * Return true if the "Created" value is before the current time minus the timeToLive
     * argument.
     * 
     * @param timeToLive
     *            the limit on the receivers' side, that the timestamp is validated against
     * @return true if the timestamp is before (now-timeToLive), false otherwise
     */
    public boolean verifyCreated(
        int timeToLive
    ) {
        // Calculate the time that is allowed for the message to travel
        Calendar validCreation = Calendar.getInstance();
        long currentTime = validCreation.getTime().getTime();
        currentTime -= timeToLive * 1000;
        validCreation.setTime(new Date(currentTime));

        // Validate the time it took the message to travel
        if (createdDate != null && createdDate.before(validCreation.getTime())) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Validation of Timestamp: The message was created too long ago");
            }
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Validation of Timestamp: Everything is ok");
        }
        return true;
    }

    
}
