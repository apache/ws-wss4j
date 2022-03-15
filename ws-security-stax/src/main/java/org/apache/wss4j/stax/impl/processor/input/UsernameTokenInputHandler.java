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

import org.apache.wss4j.binding.wss10.EncodedString;
import org.apache.wss4j.binding.wss10.PasswordString;
import org.apache.wss4j.binding.wss10.UsernameTokenType;
import org.apache.wss4j.binding.wsu10.AttributedDateTime;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.cache.ReplayCache;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.DateUtil;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityToken.UsernameSecurityToken;
import org.apache.wss4j.stax.securityEvent.UsernameTokenSecurityEvent;
import org.apache.wss4j.stax.validate.TokenContext;
import org.apache.wss4j.stax.validate.UsernameTokenValidator;
import org.apache.wss4j.stax.validate.UsernameTokenValidatorImpl;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

import jakarta.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;
import java.util.Deque;
import java.util.List;

/**
 * Processor for the UsernameToken XML Structure
 */
public class UsernameTokenInputHandler extends AbstractInputSecurityHeaderHandler {

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

        // Verify Created
        final WSSSecurityProperties wssSecurityProperties = (WSSSecurityProperties) securityProperties;
        Instant created = verifyCreated(wssSecurityProperties, usernameTokenType);

        ReplayCache replayCache = wssSecurityProperties.getNonceReplayCache();
        final EncodedString encodedNonce =
                XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_WSSE_NONCE);
        if (encodedNonce != null && replayCache != null) {
            // Check for replay attacks
            String nonce = encodedNonce.getValue();
            if (replayCache.contains(nonce)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }

            // If no Created, then just cache for the default time
            // Otherwise, cache for the configured TTL of the UsernameToken Created time, as any
            // older token will just get rejected anyway
            int utTTL = wssSecurityProperties.getUtTTL();
            if (created == null || utTTL <= 0) {
                replayCache.add(nonce);
            } else {
                replayCache.add(nonce, Instant.now().plusSeconds(utTTL));
            }
        }

        final WSInboundSecurityContext wsInboundSecurityContext =
            (WSInboundSecurityContext) inputProcessorChain.getSecurityContext();
        final List<QName> elementPath = getElementPath(eventQueue);

        final TokenContext tokenContext =
            new TokenContext(wssSecurityProperties, wsInboundSecurityContext, xmlSecEvents, elementPath);

        UsernameTokenValidator usernameTokenValidator =
                wssSecurityProperties.getValidator(WSSConstants.TAG_WSSE_USERNAME_TOKEN);
        if (usernameTokenValidator == null) {
            usernameTokenValidator = new UsernameTokenValidatorImpl();
        }
        final UsernameSecurityToken usernameSecurityToken =
                usernameTokenValidator.validate(usernameTokenType, tokenContext);

        SecurityTokenProvider<InboundSecurityToken> securityTokenProvider =
                new SecurityTokenProvider<InboundSecurityToken>() {

            @Override
            public InboundSecurityToken getSecurityToken() throws XMLSecurityException {
                return (InboundSecurityToken)usernameSecurityToken;
            }

            @Override
            public String getId() {
                return usernameTokenType.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(usernameTokenType.getId(), securityTokenProvider);

        //fire a tokenSecurityEvent
        UsernameTokenSecurityEvent usernameTokenSecurityEvent = new UsernameTokenSecurityEvent();
        usernameTokenSecurityEvent.setSecurityToken((UsernameSecurityToken)securityTokenProvider.getSecurityToken());
        // usernameTokenSecurityEvent.setUsernameTokenProfile(WSSConstants.NS_USERNAMETOKEN_PROFILE11);
        usernameTokenSecurityEvent.setCorrelationID(usernameTokenType.getId());
        inputProcessorChain.getSecurityContext().registerSecurityEvent(usernameTokenSecurityEvent);
    }

    private void checkBSPCompliance(InputProcessorChain inputProcessorChain, UsernameTokenType usernameTokenType,
                                    List<XMLSecEvent> xmlSecEvents) throws WSSecurityException {

        final WSInboundSecurityContext securityContext = (WSInboundSecurityContext) inputProcessorChain.getSecurityContext();
        if (usernameTokenType.getAny() == null) {
            securityContext.handleBSPRule(BSPRule.R3031);
        }

        int passwordIndex = -1;
        int createdIndex = -1;
        int nonceIndex = -1;
        for (int i = 0; i < xmlSecEvents.size(); i++) {
            XMLSecEvent xmlSecEvent = xmlSecEvents.get(i);
            if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
                if (xmlSecEvent.asStartElement().getName().equals(WSSConstants.TAG_WSSE_USERNAME_TOKEN)) {
                    continue;
                } else if (xmlSecEvent.asStartElement().getName().equals(WSSConstants.TAG_WSSE_PASSWORD)) {
                    if (passwordIndex != -1) {
                        securityContext.handleBSPRule(BSPRule.R4222);
                    }
                    passwordIndex = i;
                } else if (xmlSecEvent.asStartElement().getName().equals(WSSConstants.TAG_WSU_CREATED)) {
                    if (createdIndex != -1) {
                        securityContext.handleBSPRule(BSPRule.R4223);
                    }
                    createdIndex = i;
                } else if (xmlSecEvent.asStartElement().getName().equals(WSSConstants.TAG_WSSE_NONCE)) {
                    if (nonceIndex != -1) {
                        securityContext.handleBSPRule(BSPRule.R4225);
                    }
                    nonceIndex = i;
                }
            }
        }

        PasswordString passwordType =
                XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_WSSE_PASSWORD);
        if (passwordType != null && passwordType.getType() == null) {
            securityContext.handleBSPRule(BSPRule.R4201);
        }

        EncodedString encodedNonce =
                XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_WSSE_NONCE);
        if (encodedNonce != null) {
            if (encodedNonce.getEncodingType() == null) {
                securityContext.handleBSPRule(BSPRule.R4220);
            } else if (!WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(encodedNonce.getEncodingType())) {
                securityContext.handleBSPRule(BSPRule.R4221);
            }
        }

    }

    private Instant verifyCreated(
        WSSSecurityProperties wssSecurityProperties,
        UsernameTokenType usernameTokenType
    ) throws WSSecurityException {
        // Verify Created
        int ttl = wssSecurityProperties.getUtTTL();
        int futureTTL = wssSecurityProperties.getUtFutureTTL();

        final AttributedDateTime attributedDateTimeCreated =
            XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_WSU_CREATED);

        if (attributedDateTimeCreated != null) {
            // Parse the Date
            ZonedDateTime created;
            try {
                created = ZonedDateTime.parse(attributedDateTimeCreated.getValue());
            } catch (DateTimeParseException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
            }

            // Validate whether the security semantics have expired
            if (!DateUtil.verifyCreated(created.toInstant(), ttl, futureTTL)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.MESSAGE_EXPIRED);
            }
            return created.toInstant();
        }
        return null;
    }
}
