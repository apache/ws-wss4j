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
package org.swssf.wss.impl.processor.input;

import org.swssf.binding.wsu10.TimestampType;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.ext.WSSecurityContext;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.securityEvent.TimestampSecurityEvent;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.XMLStreamConstants;
import java.util.Calendar;
import java.util.Deque;
import java.util.GregorianCalendar;
import java.util.Iterator;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class TimestampInputHandler extends AbstractInputSecurityHeaderHandler {

    //Chapter 10 Security Timestamps: ...may only be present at most once per header (that is, per SOAP actor/role)
    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLSecEvent> eventQueue, Integer index) throws XMLSecurityException {

        final WSSSecurityProperties wssSecurityProperties = (WSSSecurityProperties) securityProperties;

        Boolean alreadyProcessed = inputProcessorChain.getSecurityContext().<Boolean>get(WSSConstants.TIMESTAMP_PROCESSED);
        if (Boolean.TRUE.equals(alreadyProcessed)) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "invalidTimestamp",
                    "Message contains two or more timestamps");
        }
        inputProcessorChain.getSecurityContext().put(WSSConstants.TIMESTAMP_PROCESSED, Boolean.TRUE);

        @SuppressWarnings("unchecked")
        final TimestampType timestampType =
                ((JAXBElement<TimestampType>) parseStructure(eventQueue, index, securityProperties)).getValue();

        checkBSPCompliance(inputProcessorChain, timestampType, eventQueue, index);

        if (timestampType.getCreated() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "missingCreated");
        }

        try {
            // Validate whether the security semantics have expired
            //created and expires is optional per spec. But we enforce the created element in the validation
            Calendar crea = null;
            if (timestampType.getCreated() != null) {
                XMLGregorianCalendar created;
                try {
                    created = WSSConstants.datatypeFactory.newXMLGregorianCalendar(timestampType.getCreated().getValue());
                } catch (IllegalArgumentException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
                }
                logger.debug("Timestamp created: " + created);
                crea = created.toGregorianCalendar();
            }

            Calendar exp = null;
            if (timestampType.getExpires() != null) {
                XMLGregorianCalendar expires;
                try {
                    expires = WSSConstants.datatypeFactory.newXMLGregorianCalendar(timestampType.getExpires().getValue());
                } catch (IllegalArgumentException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
                }
                logger.debug("Timestamp expires: " + expires);
                exp = expires.toGregorianCalendar();
            }

            Calendar rightNow = Calendar.getInstance();
            Calendar ttl = Calendar.getInstance();
            ttl.add(Calendar.SECOND, -wssSecurityProperties.getTimestampTTL());

            if (exp != null && wssSecurityProperties.isStrictTimestampCheck() && exp.before(rightNow)) {
                logger.debug("Time now: " + WSSConstants.datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar()).toXMLFormat());
                throw new WSSecurityException(WSSecurityException.ErrorCode.MESSAGE_EXPIRED, "invalidTimestamp",
                        "The security semantics of the message have expired");
            }

            if (crea != null && wssSecurityProperties.isStrictTimestampCheck() && crea.before(ttl)) {
                logger.debug("Time now: " + WSSConstants.datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar()).toXMLFormat());
                throw new WSSecurityException(WSSecurityException.ErrorCode.MESSAGE_EXPIRED, "invalidTimestamp",
                        "The security semantics of the message have expired");
            }

            if (crea != null && crea.after(rightNow)) {
                logger.debug("Time now: " + WSSConstants.datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar()).toXMLFormat());
                throw new WSSecurityException(WSSecurityException.ErrorCode.MESSAGE_EXPIRED, "invalidTimestamp",
                        "The security semantics of the message is invalid");
            }

            TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent();
            timestampSecurityEvent.setCreated(crea);
            timestampSecurityEvent.setExpires(exp);
            ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(timestampSecurityEvent);
            inputProcessorChain.getSecurityContext().put(WSSConstants.PROP_TIMESTAMP_SECURITYEVENT, timestampSecurityEvent);

        } catch (IllegalArgumentException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
    }

    private void checkBSPCompliance(InputProcessorChain inputProcessorChain, TimestampType timestampType,
                                    Deque<XMLSecEvent> eventDeque, int index) throws WSSecurityException {
        final WSSecurityContext securityContext = (WSSecurityContext) inputProcessorChain.getSecurityContext();
        if (timestampType.getCreated() == null) {
            securityContext.handleBSPRule(WSSConstants.BSPRule.R3203);
        }

        Iterator<XMLSecEvent> xmlSecEventIterator = eventDeque.descendingIterator();
        int curIdx = 0;
        //forward to first timestamp child element
        while (curIdx++ <= index) {
            xmlSecEventIterator.next();
        }
        int createdIndex = -1;
        int expiresIndex = -1;
        while (xmlSecEventIterator.hasNext()) {
            XMLSecEvent xmlSecEvent = xmlSecEventIterator.next();
            if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
                if (xmlSecEvent.asStartElement().getName().equals(WSSConstants.TAG_wsu_Created)) {
                    if (createdIndex != -1) {
                        securityContext.handleBSPRule(WSSConstants.BSPRule.R3203);
                    }
                    if (expiresIndex != -1) {
                        securityContext.handleBSPRule(WSSConstants.BSPRule.R3221);
                    }
                    createdIndex = curIdx;
                } else if (xmlSecEvent.asStartElement().getName().equals(WSSConstants.TAG_wsu_Expires)) {
                    if (expiresIndex != -1) {
                        securityContext.handleBSPRule(WSSConstants.BSPRule.R3224);
                    }
                    if (createdIndex == -1) {
                        securityContext.handleBSPRule(WSSConstants.BSPRule.R3221);
                    }
                    expiresIndex = curIdx;
                } else {
                    securityContext.handleBSPRule(WSSConstants.BSPRule.R3222);
                }
            }
            curIdx++;
        }

        if (timestampType.getCreated() != null) {
            XMLGregorianCalendar createdCalendar;
            try {
                createdCalendar = WSSConstants.datatypeFactory.newXMLGregorianCalendar(timestampType.getCreated().getValue());
            } catch (IllegalArgumentException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }
            if (createdCalendar.getFractionalSecond().scale() > 3) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R3220);
            }
            if (createdCalendar.getSecond() > 59) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R3213);
            }
            String valueType = XMLSecurityUtils.getQNameAttribute(timestampType.getCreated().getOtherAttributes(), WSSConstants.ATT_NULL_ValueType);
            if (valueType != null) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R3225);
            }
            if (createdCalendar.getTimezone() == DatatypeConstants.FIELD_UNDEFINED) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R3217);
            }
        }
        if (timestampType.getExpires() != null) {
            XMLGregorianCalendar expiresCalendar;
            try {
                expiresCalendar = WSSConstants.datatypeFactory.newXMLGregorianCalendar(timestampType.getExpires().getValue());
            } catch (IllegalArgumentException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }
            if (expiresCalendar.getFractionalSecond().scale() > 3) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R3229);
            }
            if (expiresCalendar.getSecond() > 59) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R3215);
            }
            String valueType = XMLSecurityUtils.getQNameAttribute(timestampType.getExpires().getOtherAttributes(), WSSConstants.ATT_NULL_ValueType);
            if (valueType != null) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R3226);
            }
            if (expiresCalendar.getTimezone() == DatatypeConstants.FIELD_UNDEFINED) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R3223);
            }
        }
    }

    /*
    <wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="Timestamp-1106985890">
        <wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2009-11-18T10:11:28.358Z</wsu:Created>
        <wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2009-11-18T10:26:28.358Z</wsu:Expires>
    </wsu:Timestamp>
     */
}
