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

package org.apache.wss4j.dom.message.token;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.XMLGregorianCalendar;

import org.apache.wss4j.common.bsp.BSPEnforcer;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.common.util.DateUtil;
import org.apache.wss4j.common.util.WSCurrentTimeSource;
import org.apache.wss4j.common.util.WSTimeSource;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.util.XmlSchemaDateFormat;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

/**
 * Timestamp according to SOAP Message Security 1.0,
 * chapter 10 / appendix A.2
 */
public class Timestamp {

    private Element element;
    private Date createdDate;
    private Date expiresDate;

    /**
     * Constructs a <code>Timestamp</code> object and parses the
     * <code>wsu:Timestamp</code> element to initialize it.
     *
     * @param timestampElement the <code>wsu:Timestamp</code> element that
     *        contains the timestamp data
     * @param bspEnforcer a BSPEnforcer instance to enforce BSP rules
     */
    public Timestamp(Element timestampElement, BSPEnforcer bspEnforcer) throws WSSecurityException {

        element = timestampElement;

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
                        String valueType = currentChildElement.getAttributeNS(null, "ValueType");
                        if (valueType != null && !"".equals(valueType)) {
                            // We can't have a ValueType attribute as per the BSP spec
                            bspEnforcer.handleBSPRule(BSPRule.R3225);
                        }
                        strCreated = ((Text)currentChildElement.getFirstChild()).getData();
                    } else {
                        // Test for multiple Created elements
                        bspEnforcer.handleBSPRule(BSPRule.R3203);
                    }
                } else if (WSConstants.EXPIRES_LN.equals(currentChild.getLocalName()) &&
                        WSConstants.WSU_NS.equals(currentChild.getNamespaceURI())) {
                    if (strCreated == null) {
                        // Created must appear before Expires
                        bspEnforcer.handleBSPRule(BSPRule.R3221);
                    }
                    if (strExpires != null ) {
                        // We can't have multiple Expires elements
                        bspEnforcer.handleBSPRule(BSPRule.R3224);
                    } else {
                        String valueType = currentChildElement.getAttributeNS(null, "ValueType");
                        if (valueType != null && !"".equals(valueType)) {
                            // We can't have a ValueType attribute as per the BSP spec
                            bspEnforcer.handleBSPRule(BSPRule.R3226);
                        }
                        strExpires = ((Text)currentChildElement.getFirstChild()).getData();
                    }
                } else {
                    bspEnforcer.handleBSPRule(BSPRule.R3222);
                }
            }
        }

        // We must have a Created element
        if (strCreated == null) {
            bspEnforcer.handleBSPRule(BSPRule.R3203);
        }

        // Parse the dates
        if (strCreated != null) {
            XMLGregorianCalendar createdCalendar = null;
            try {
                createdCalendar =
                    WSSConfig.datatypeFactory.newXMLGregorianCalendar(strCreated);
            } catch (IllegalArgumentException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }

            if (createdCalendar.getFractionalSecond() != null
                && createdCalendar.getFractionalSecond().scale() > 3) {
                bspEnforcer.handleBSPRule(BSPRule.R3220);
            }
            if (createdCalendar.getSecond() > 59) {
                bspEnforcer.handleBSPRule(BSPRule.R3213);
            }
            if (createdCalendar.getTimezone() == DatatypeConstants.FIELD_UNDEFINED) {
                bspEnforcer.handleBSPRule(BSPRule.R3217);
            }
            createdDate = createdCalendar.toGregorianCalendar().getTime();
        }

        if (strExpires != null) {
            XMLGregorianCalendar expiresCalendar = null;
            try {
                expiresCalendar =
                    WSSConfig.datatypeFactory.newXMLGregorianCalendar(strExpires);
            } catch (IllegalArgumentException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }

            if (expiresCalendar.getFractionalSecond() != null
                && expiresCalendar.getFractionalSecond().scale() > 3) {
                bspEnforcer.handleBSPRule(BSPRule.R3229);
            }
            if (expiresCalendar.getSecond() > 59) {
                bspEnforcer.handleBSPRule(BSPRule.R3215);
            }
            if (expiresCalendar.getTimezone() == DatatypeConstants.FIELD_UNDEFINED) {
                bspEnforcer.handleBSPRule(BSPRule.R3223);
            }
            expiresDate = expiresCalendar.toGregorianCalendar().getTime();
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
        this(milliseconds, doc, new WSCurrentTimeSource(), ttl);
    }

    /**
     * Constructs a <code>Timestamp</code> object according
     * to the defined parameters.
     *
     * @param doc the SOAP envelope as <code>Document</code>
     * @param ttl the time to live (validity of the security semantics) in seconds
     */
    public Timestamp(boolean milliseconds, Document doc, WSTimeSource timeSource, int ttl) {

        element =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.TIMESTAMP_TOKEN_LN
            );

        DateFormat zulu = null;
        if (milliseconds) {
            zulu = new XmlSchemaDateFormat();
        } else {
            zulu = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ENGLISH);
            zulu.setTimeZone(TimeZone.getTimeZone("UTC"));
        }
        Element elementCreated =
            doc.createElementNS(
                WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":" + WSConstants.CREATED_LN
            );
        createdDate = timeSource.now();
        elementCreated.appendChild(doc.createTextNode(zulu.format(createdDate)));
        element.appendChild(elementCreated);
        if (ttl != 0) {
            expiresDate = timeSource.now();
            expiresDate.setTime(createdDate.getTime() + (long)ttl * 1000L);

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
        XMLUtils.setNamespace(element, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
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
        return DOM2Writer.nodeToString(element);
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
            Date rightNow = new Date();
            return expiresDate.before(rightNow);
        }
        return false;
    }


    /**
     * Return true if the "Created" value is before the current time minus the timeToLive
     * argument, and if the Created value is not "in the future".
     *
     * @param timeToLive the value in seconds for the validity of the Created time
     * @param futureTimeToLive the value in seconds for the future validity of the Created time
     * @return true if the timestamp is before (now-timeToLive), false otherwise
     */
    public boolean verifyCreated(
        int timeToLive,
        int futureTimeToLive
    ) {
        return DateUtil.verifyCreated(createdDate, timeToLive, futureTimeToLive);
    }


    @Override
    public int hashCode() {
        int result = 17;
        if (createdDate != null) {
            result = 31 * result + createdDate.hashCode();
        }
        if (expiresDate != null) {
            result = 31 * result + expiresDate.hashCode();
        }
        return result;
    }

    @Override
    public boolean equals(Object object) {
        if (!(object instanceof Timestamp)) {
            return false;
        }
        Timestamp timestamp = (Timestamp)object;
        if (!compare(timestamp.getCreated(), getCreated())) {
            return false;
        }
        if (!compare(timestamp.getExpires(), getExpires())) {
            return false;
        }
        return true;
    }

    private boolean compare(Date item1, Date item2) {
        if (item1 == null && item2 != null) {
            return false;
        } else if (item1 != null && !item1.equals(item2)) {
            return false;
        }
        return true;
    }

}
