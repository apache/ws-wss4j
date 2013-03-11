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

import org.apache.jcs.JCS;
import org.apache.jcs.access.exception.CacheException;
import org.apache.jcs.engine.ElementAttributes;
import org.apache.wss4j.binding.wss10.EncodedString;
import org.apache.wss4j.binding.wss10.PasswordString;
import org.apache.wss4j.binding.wss10.UsernameTokenType;
import org.apache.wss4j.binding.wsu10.AttributedDateTime;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.DateUtil;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.ext.WSSecurityContext;
import org.apache.wss4j.stax.securityEvent.UsernameTokenSecurityEvent;
import org.apache.wss4j.stax.validate.TokenContext;
import org.apache.wss4j.stax.validate.UsernameTokenValidator;
import org.apache.wss4j.stax.validate.UsernameTokenValidatorImpl;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.util.IDGenerator;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;

import java.util.Date;
import java.util.Deque;
import java.util.List;

/**
 * Processor for the UsernameToken XML Structure
 */
public class UsernameTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    private static final String cacheRegionName = "usernameToken";
    private static final JCS cache;

    static {
        try {
            cache = JCS.getInstance(cacheRegionName);
        } catch (CacheException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLSecEvent> eventQueue, Integer index) throws XMLSecurityException {

        @SuppressWarnings("unchecked")
        final UsernameTokenType usernameTokenType =
                ((JAXBElement<UsernameTokenType>) parseStructure(eventQueue, index, securityProperties)).getValue();

        final List<XMLSecEvent> xmlSecEvents = getResponsibleXMLSecEvents(eventQueue, index);

        checkBSPCompliance(inputProcessorChain, usernameTokenType, xmlSecEvents);

        if (usernameTokenType.getId() == null) {
            usernameTokenType.setId(IDGenerator.generateID(null));
        }

        final EncodedString encodedNonce =
                XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse_Nonce);
        if (encodedNonce != null) {
            String nonce = encodedNonce.getValue();
            /*
                It is RECOMMENDED that used nonces be cached for a period at least as long as
                the timestamp freshness limitation period, above, and that UsernameToken with
                nonces that have already been used (and are thus in the cache) be rejected
            */
            if (cache.get(nonce) != null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
            ElementAttributes elementAttributes = new ElementAttributes();
            elementAttributes.setMaxLifeSeconds(300);
            try {
                cache.put(nonce, nonce, elementAttributes);
            } catch (CacheException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }
        }

        final WSSecurityContext wsSecurityContext = (WSSecurityContext) inputProcessorChain.getSecurityContext();
        final WSSSecurityProperties wssSecurityProperties = (WSSSecurityProperties) securityProperties;
        final List<QName> elementPath = getElementPath(eventQueue);
        
        // Verify Created
        verifyCreated(wssSecurityProperties, usernameTokenType);
        
        final TokenContext tokenContext = new TokenContext(wssSecurityProperties, wsSecurityContext, xmlSecEvents, elementPath);

        UsernameTokenValidator usernameTokenValidator =
                wssSecurityProperties.getValidator(WSSConstants.TAG_wsse_UsernameToken);
        if (usernameTokenValidator == null) {
            usernameTokenValidator = new UsernameTokenValidatorImpl();
        }
        final SecurityToken usernameSecurityToken =
                usernameTokenValidator.validate(usernameTokenType, tokenContext);

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            @SuppressWarnings("unchecked")
            @Override
            public SecurityToken getSecurityToken() throws XMLSecurityException {
                return usernameSecurityToken;
            }

            @Override
            public String getId() {
                return usernameTokenType.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(usernameTokenType.getId(), securityTokenProvider);

        PasswordString passwordType = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse_Password);
        WSSConstants.UsernameTokenPasswordType usernameTokenPasswordType = WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE;
        if (passwordType != null && passwordType.getType() != null) {
            usernameTokenPasswordType = WSSConstants.UsernameTokenPasswordType.getUsernameTokenPasswordType(passwordType.getType());
        }

        //fire a tokenSecurityEvent
        UsernameTokenSecurityEvent usernameTokenSecurityEvent = new UsernameTokenSecurityEvent();
        usernameTokenSecurityEvent.setUsernameTokenPasswordType(usernameTokenPasswordType);
        usernameTokenSecurityEvent.setSecurityToken((SecurityToken) securityTokenProvider.getSecurityToken());
        usernameTokenSecurityEvent.setUsernameTokenProfile(WSSConstants.NS_USERNAMETOKEN_PROFILE11);
        usernameTokenSecurityEvent.setCorrelationID(usernameTokenType.getId());
        inputProcessorChain.getSecurityContext().registerSecurityEvent(usernameTokenSecurityEvent);
    }

    private void checkBSPCompliance(InputProcessorChain inputProcessorChain, UsernameTokenType usernameTokenType,
                                    List<XMLSecEvent> xmlSecEvents) throws WSSecurityException {

        final WSSecurityContext securityContext = (WSSecurityContext) inputProcessorChain.getSecurityContext();
        if (usernameTokenType.getAny() == null) {
            securityContext.handleBSPRule(BSPRule.R3031);
        }

        int passwordIndex = -1;
        int createdIndex = -1;
        int nonceIndex = -1;
        for (int i = 0; i < xmlSecEvents.size(); i++) {
            XMLSecEvent xmlSecEvent = xmlSecEvents.get(i);
            if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
                if (xmlSecEvent.asStartElement().getName().equals(WSSConstants.TAG_wsse_UsernameToken)) {
                    continue;
                } else if (xmlSecEvent.asStartElement().getName().equals(WSSConstants.TAG_wsse_Password)) {
                    if (passwordIndex != -1) {
                        securityContext.handleBSPRule(BSPRule.R4222);
                    }
                    passwordIndex = i;
                } else if (xmlSecEvent.asStartElement().getName().equals(WSSConstants.TAG_wsu_Created)) {
                    if (createdIndex != -1) {
                        securityContext.handleBSPRule(BSPRule.R4223);
                    }
                    createdIndex = i;
                } else if (xmlSecEvent.asStartElement().getName().equals(WSSConstants.TAG_wsse_Nonce)) {
                    if (nonceIndex != -1) {
                        securityContext.handleBSPRule(BSPRule.R4225);
                    }
                    nonceIndex = i;
                }
            }
        }

        PasswordString passwordType =
                XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse_Password);
        if (passwordType != null && passwordType.getType() == null) {
            securityContext.handleBSPRule(BSPRule.R4201);
        }

        EncodedString encodedNonce =
                XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse_Nonce);
        if (encodedNonce != null) {
            if (encodedNonce.getEncodingType() == null) {
                securityContext.handleBSPRule(BSPRule.R4220);
            } else if (!WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(encodedNonce.getEncodingType())) {
                securityContext.handleBSPRule(BSPRule.R4221);
            }
        }

    }
    
    private void verifyCreated(
        WSSSecurityProperties wssSecurityProperties,
        UsernameTokenType usernameTokenType
    ) throws WSSecurityException {
        // Verify Created
        int ttl = wssSecurityProperties.getUtTTL();
        int futureTTL = wssSecurityProperties.getUtFutureTTL();
        
        final AttributedDateTime attributedDateTimeCreated =
            XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsu_Created);
        
        if (attributedDateTimeCreated != null) {
            // Parse the Date
            XMLGregorianCalendar created;
            try {
                created = WSSConstants.datatypeFactory.newXMLGregorianCalendar(attributedDateTimeCreated.getValue());
            } catch (IllegalArgumentException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }
            Date createdDate = created.toGregorianCalendar().getTime();
            
            // Validate whether the security semantics have expired
            if (!DateUtil.verifyCreated(createdDate, ttl, futureTTL)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.MESSAGE_EXPIRED);
            }
        }
    }
}
