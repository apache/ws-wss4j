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
package org.apache.wss4j.stax.impl.processor.input;

import org.apache.wss4j.binding.wsu10.TimestampType;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityEvent.TimestampSecurityEvent;
import org.apache.wss4j.stax.validate.TimestampValidator;
import org.apache.wss4j.stax.validate.TimestampValidatorImpl;
import org.apache.wss4j.stax.validate.TokenContext;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractInputSecurityHeaderHandler;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.util.IDGenerator;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.DatatypeConstants;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;

import java.util.Deque;
import java.util.List;

public class TimestampInputHandler extends AbstractInputSecurityHeaderHandler {

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLSecEvent> eventQueue, Integer index) throws XMLSecurityException {

        final WSSSecurityProperties wssSecurityProperties = (WSSSecurityProperties) securityProperties;
        final WSInboundSecurityContext wssecurityContextInbound = (WSInboundSecurityContext) inputProcessorChain.getSecurityContext();

        //Chapter 10 Security Timestamps: ...may only be present at most once per header (that is, per SOAP actor/role)
        Boolean alreadyProcessed = wssecurityContextInbound.<Boolean>get(WSSConstants.TIMESTAMP_PROCESSED);
        if (Boolean.TRUE.equals(alreadyProcessed)) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "invalidTimestamp",
                                          new Object[] {"Message contains two or more timestamps"});
        }
        wssecurityContextInbound.put(WSSConstants.TIMESTAMP_PROCESSED, Boolean.TRUE);

        @SuppressWarnings("unchecked")
        final TimestampType timestampType =
                ((JAXBElement<TimestampType>) parseStructure(eventQueue, index, securityProperties)).getValue();

        final List<XMLSecEvent> xmlSecEvents = getResponsibleXMLSecEvents(eventQueue, index);
        List<QName> elementPath = getElementPath(eventQueue);

        checkBSPCompliance(inputProcessorChain, timestampType, xmlSecEvents);

        if (timestampType.getId() == null) {
            timestampType.setId(IDGenerator.generateID(null));
        }

        TimestampValidator timestampValidator = wssSecurityProperties.getValidator(WSSConstants.TAG_wsu_Timestamp);
        if (timestampValidator == null) {
            timestampValidator = new TimestampValidatorImpl();
        }
        TokenContext tokenContext = new TokenContext(wssSecurityProperties, wssecurityContextInbound, xmlSecEvents, elementPath);
        timestampValidator.validate(timestampType, tokenContext);

        TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent();
        if (timestampType.getCreated() != null) {
            try {
                timestampSecurityEvent.setCreated(
                        timestampType.getCreated().getAsXMLGregorianCalendar().toGregorianCalendar());
            } catch (IllegalArgumentException e) { //NOPMD
                //ignore
            }
        }
        if (timestampType.getExpires() != null) {
            try {
                timestampSecurityEvent.setExpires(
                        timestampType.getExpires().getAsXMLGregorianCalendar().toGregorianCalendar());
            } catch (IllegalArgumentException e) { //NOPMD
                //ignore
            }
        }
        timestampSecurityEvent.setCorrelationID(timestampType.getId());
        wssecurityContextInbound.registerSecurityEvent(timestampSecurityEvent);
        wssecurityContextInbound.put(WSSConstants.PROP_TIMESTAMP_SECURITYEVENT, timestampSecurityEvent);
    }

    private void checkBSPCompliance(InputProcessorChain inputProcessorChain, TimestampType timestampType,
                                    List<XMLSecEvent> xmlSecEvents) throws WSSecurityException {
        final WSInboundSecurityContext securityContext = (WSInboundSecurityContext) inputProcessorChain.getSecurityContext();
        if (timestampType.getCreated() == null) {
            securityContext.handleBSPRule(BSPRule.R3203);
        }

        int createdIndex = -1;
        int expiresIndex = -1;
        for (int i = 0; i < xmlSecEvents.size(); i++) {
            XMLSecEvent xmlSecEvent = xmlSecEvents.get(i);
            if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
                QName name = xmlSecEvent.asStartElement().getName();

                if (name.equals(WSSConstants.TAG_wsu_Timestamp)) {
                    continue;
                } else if (name.equals(WSSConstants.TAG_wsu_Created)) {
                    if (createdIndex != -1) {
                        securityContext.handleBSPRule(BSPRule.R3203);
                    }
                    if (expiresIndex != -1) {
                        securityContext.handleBSPRule(BSPRule.R3221);
                    }
                    createdIndex = i;
                } else if (name.equals(WSSConstants.TAG_wsu_Expires)) {
                    if (expiresIndex != -1) {
                        securityContext.handleBSPRule(BSPRule.R3224);
                    }
                    if (createdIndex == -1) {
                        securityContext.handleBSPRule(BSPRule.R3221);
                    }
                    expiresIndex = i;
                } else {
                    securityContext.handleBSPRule(BSPRule.R3222);
                }
            }
        }

        if (timestampType.getCreated() != null) {
            XMLGregorianCalendar createdCalendar;
            try {
                createdCalendar = timestampType.getCreated().getAsXMLGregorianCalendar();
            } catch (IllegalArgumentException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }
            if (createdCalendar.getFractionalSecond() != null
                && createdCalendar.getFractionalSecond().scale() > 3) {
                securityContext.handleBSPRule(BSPRule.R3220);
            }
            if (createdCalendar.getSecond() > 59) {
                securityContext.handleBSPRule(BSPRule.R3213);
            }
            String valueType = XMLSecurityUtils.getQNameAttribute(timestampType.getCreated().getOtherAttributes(), WSSConstants.ATT_NULL_ValueType);
            if (valueType != null) {
                securityContext.handleBSPRule(BSPRule.R3225);
            }
            if (createdCalendar.getTimezone() == DatatypeConstants.FIELD_UNDEFINED) {
                securityContext.handleBSPRule(BSPRule.R3217);
            }
        } else {
            securityContext.handleBSPRule(BSPRule.R3203);
        }

        if (timestampType.getExpires() != null) {
            XMLGregorianCalendar expiresCalendar;
            try {
                expiresCalendar = timestampType.getExpires().getAsXMLGregorianCalendar();
            } catch (IllegalArgumentException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }
            if (expiresCalendar.getFractionalSecond() != null
                && expiresCalendar.getFractionalSecond().scale() > 3) {
                securityContext.handleBSPRule(BSPRule.R3229);
            }
            if (expiresCalendar.getSecond() > 59) {
                securityContext.handleBSPRule(BSPRule.R3215);
            }
            String valueType = XMLSecurityUtils.getQNameAttribute(timestampType.getExpires().getOtherAttributes(), WSSConstants.ATT_NULL_ValueType);
            if (valueType != null) {
                securityContext.handleBSPRule(BSPRule.R3226);
            }
            if (expiresCalendar.getTimezone() == DatatypeConstants.FIELD_UNDEFINED) {
                securityContext.handleBSPRule(BSPRule.R3223);
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
