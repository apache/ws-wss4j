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
package org.apache.ws.security.stax.impl.processor.input;

import org.apache.commons.codec.binary.Base64;
import org.apache.jcs.JCS;
import org.apache.jcs.access.exception.CacheException;
import org.apache.jcs.engine.ElementAttributes;
import org.apache.ws.security.binding.wss10.AttributedString;
import org.apache.ws.security.binding.wss10.EncodedString;
import org.apache.ws.security.binding.wss10.PasswordString;
import org.apache.ws.security.binding.wss10.UsernameTokenType;
import org.apache.ws.security.binding.wsu10.AttributedDateTime;
import org.apache.ws.security.common.ext.WSPasswordCallback;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.stax.ext.*;
import org.apache.ws.security.stax.impl.securityToken.SecurityTokenFactoryImpl;
import org.apache.ws.security.stax.securityEvent.UsernameTokenSecurityEvent;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.util.IDGenerator;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import java.util.*;

/**
 * Processor for the UsernameToken XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
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

        checkBSPCompliance(inputProcessorChain, usernameTokenType, eventQueue, index);

        if (usernameTokenType.getId() == null) {
            usernameTokenType.setId(IDGenerator.generateID(null));
        }

        // If the UsernameToken is to be used for key derivation, the (1.1)
        // spec says that it cannot contain a password, and it must contain
        // an Iteration element
        final byte[] salt = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse11_Salt);
        PasswordString passwordType = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse_Password);
        final Long iteration = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse11_Iteration);
        if (salt != null && (passwordType != null || iteration == null)) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "badTokenType01");
        }
        
        boolean handleCustomPasswordTypes = false;
        handleCustomPasswordTypes = ((WSSSecurityProperties)securityProperties).getHandleCustomPasswordTypes();
        
        final byte[] nonceVal;
        final String created;

        WSSConstants.UsernameTokenPasswordType usernameTokenPasswordType = WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE;
        if (passwordType != null && passwordType.getType() != null) {
            usernameTokenPasswordType = WSSConstants.UsernameTokenPasswordType.getUsernameTokenPasswordType(passwordType.getType());
        }

        final AttributedString username = usernameTokenType.getUsername();
        if (username == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "badTokenType01");
        }
        final EncodedString encodedNonce = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse_Nonce);
        final AttributedDateTime attributedDateTimeCreated = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsu_Created);

        // TODO revisit this once we add in Validators
        if (usernameTokenPasswordType == WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST) {
            if (encodedNonce == null || attributedDateTimeCreated == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "badTokenType01");
            }

            if (!WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(encodedNonce.getEncodingType())) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN, "badTokenType01");
            }
            String nonce = encodedNonce.getValue();
            nonceVal = Base64.decodeBase64(nonce);
            created = attributedDateTimeCreated.getValue();

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
                cache.put(nonce, created, elementAttributes);
            } catch (CacheException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
            }

            XMLGregorianCalendar xmlGregorianCalendar;
            try {
                xmlGregorianCalendar = WSSConstants.datatypeFactory.newXMLGregorianCalendar(created);
            } catch (IllegalArgumentException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN);
            }
            GregorianCalendar createdCal = xmlGregorianCalendar.toGregorianCalendar();
            GregorianCalendar now = new GregorianCalendar();
            if (createdCal.after(now)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
            now.add(Calendar.MINUTE, 5);
            if (createdCal.after(now)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }

            WSPasswordCallback pwCb = new WSPasswordCallback(username.getValue(),
                    null,
                    passwordType.getType(),
                    WSPasswordCallback.Usage.USERNAME_TOKEN);
            try {
                WSSUtils.doPasswordCallback(securityProperties.getCallbackHandler(), pwCb);
            } catch (WSSecurityException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
            }

            if (pwCb.getPassword() == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }

            String passDigest = WSSUtils.doPasswordDigest(nonceVal, created, pwCb.getPassword());
            if (!passwordType.getValue().equals(passDigest)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
            passwordType.setValue(pwCb.getPassword());
        } else if ((usernameTokenPasswordType == WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT)
            || (passwordType != null && passwordType.getValue() != null 
                && usernameTokenPasswordType == WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE)) {
            nonceVal = null;
            created = null;
            WSPasswordCallback pwCb = new WSPasswordCallback(username.getValue(),
                    null,
                    passwordType.getType(),
                    WSPasswordCallback.Usage.USERNAME_TOKEN);
            try {
                WSSUtils.doPasswordCallback(securityProperties.getCallbackHandler(), pwCb);
            } catch (WSSecurityException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
            }

            if (pwCb.getPassword() == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }

            if (!passwordType.getValue().equals(pwCb.getPassword())) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
            passwordType.setValue(pwCb.getPassword());
        } else if (passwordType != null && passwordType.getValue() != null && usernameTokenPasswordType == null) { 
            if (!handleCustomPasswordTypes) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
            nonceVal = null;
            created = null;
            WSPasswordCallback pwCb = new WSPasswordCallback(username.getValue(),
                    null,
                    passwordType.getType(),
                    WSPasswordCallback.Usage.USERNAME_TOKEN);
            try {
                WSSUtils.doPasswordCallback(securityProperties.getCallbackHandler(), pwCb);
            } catch (WSSecurityException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
            }

            if (pwCb.getPassword() == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }

            if (!passwordType.getValue().equals(pwCb.getPassword())) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
            passwordType.setValue(pwCb.getPassword());
        } else {
            nonceVal = null;
            created = null;
        }

        final String password;
        if (passwordType != null) {
            password = passwordType.getValue();
        } else {
            password = null;
        }

        final List<QName> elementPath = getElementPath(eventQueue);
        final XMLSecEvent responsibleStartXMLEvent = getResponsibleStartXMLEvent(eventQueue, index);

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private SecurityToken securityToken = null;

            public SecurityToken getSecurityToken() throws WSSecurityException {
                if (this.securityToken != null) {
                    return this.securityToken;
                }
                this.securityToken = SecurityTokenFactoryImpl.getSecurityToken(username.getValue(), password,
                        created, nonceVal, salt, iteration, (WSSecurityContext) inputProcessorChain.getSecurityContext(),
                        usernameTokenType.getId());
                this.securityToken.setElementPath(elementPath);
                this.securityToken.setXMLSecEvent(responsibleStartXMLEvent);
                return this.securityToken;
            }

            public String getId() {
                return usernameTokenType.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(usernameTokenType.getId(), securityTokenProvider);

        //fire a tokenSecurityEvent
        UsernameTokenSecurityEvent usernameTokenSecurityEvent = new UsernameTokenSecurityEvent();
        usernameTokenSecurityEvent.setUsernameTokenPasswordType(usernameTokenPasswordType);
        usernameTokenSecurityEvent.setSecurityToken(securityTokenProvider.getSecurityToken());
        usernameTokenSecurityEvent.setUsernameTokenProfile(WSSConstants.NS_USERNAMETOKEN_PROFILE11);
        ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(usernameTokenSecurityEvent);
    }

    private void checkBSPCompliance(InputProcessorChain inputProcessorChain, UsernameTokenType usernameTokenType,
                                    Deque<XMLSecEvent> eventDeque, int index) throws WSSecurityException {

        final WSSecurityContext securityContext = (WSSecurityContext) inputProcessorChain.getSecurityContext();
        if (usernameTokenType.getAny() == null) {
            securityContext.handleBSPRule(WSSConstants.BSPRule.R3031);
        }

        Iterator<XMLSecEvent> xmlSecEventIterator = eventDeque.descendingIterator();
        int curIdx = 0;
        //forward to first Usernametoken child element
        while (curIdx++ <= index) {
            xmlSecEventIterator.next();
        }
        int passwordIndex = -1;
        int createdIndex = -1;
        int nonceIndex = -1;
        while (xmlSecEventIterator.hasNext()) {
            XMLSecEvent xmlSecEvent = xmlSecEventIterator.next();
            if (xmlSecEvent.getEventType() == XMLStreamConstants.START_ELEMENT) {
                if (xmlSecEvent.asStartElement().getName().equals(WSSConstants.TAG_wsse_Password)) {
                    if (passwordIndex != -1) {
                        securityContext.handleBSPRule(WSSConstants.BSPRule.R4222);
                    }
                    passwordIndex = curIdx;
                } else if (xmlSecEvent.asStartElement().getName().equals(WSSConstants.TAG_wsu_Created)) {
                    if (createdIndex != -1) {
                        securityContext.handleBSPRule(WSSConstants.BSPRule.R4223);
                    }
                    createdIndex = curIdx;
                } else if (xmlSecEvent.asStartElement().getName().equals(WSSConstants.TAG_wsse_Nonce)) {
                    if (nonceIndex != -1) {
                        securityContext.handleBSPRule(WSSConstants.BSPRule.R4225);
                    }
                    nonceIndex = curIdx;
                }
            }
            curIdx++;
        }

        PasswordString passwordType = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse_Password);
        if (passwordType != null) {
            if (passwordType.getType() == null) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R4201);
            }
        }

        EncodedString encodedNonce = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse_Nonce);
        if (encodedNonce != null) {
            if (encodedNonce.getEncodingType() == null) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R4220);
            } else if (!WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(encodedNonce.getEncodingType())) {
                securityContext.handleBSPRule(WSSConstants.BSPRule.R4221);
            }
        }

    }
}
