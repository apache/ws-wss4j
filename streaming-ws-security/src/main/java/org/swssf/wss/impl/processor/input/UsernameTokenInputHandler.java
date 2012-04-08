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

import org.apache.commons.codec.binary.Base64;
import org.apache.jcs.JCS;
import org.apache.jcs.access.exception.CacheException;
import org.apache.jcs.engine.ElementAttributes;
import org.swssf.binding.wss10.AttributedString;
import org.swssf.binding.wss10.EncodedString;
import org.swssf.binding.wss10.PasswordString;
import org.swssf.binding.wss10.UsernameTokenType;
import org.swssf.binding.wsu10.AttributedDateTime;
import org.swssf.wss.ext.*;
import org.swssf.wss.impl.securityToken.SecurityTokenFactoryImpl;
import org.swssf.wss.securityEvent.UsernameTokenSecurityEvent;
import org.swssf.xmlsec.ext.*;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.events.XMLEvent;
import java.util.*;

/**
 * Processor for the UsernameToken XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class UsernameTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    private static final String cacheRegionName = "usernameToken";
    private static JCS cache;
    private static final DatatypeFactory datatypeFactory;

    static {
        try {
            cache = JCS.getInstance(cacheRegionName);
            datatypeFactory = DatatypeFactory.newInstance();
        } catch (CacheException e) {
            throw new RuntimeException(e);
        } catch (DatatypeConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLEvent> eventQueue, Integer index) throws XMLSecurityException {

        final UsernameTokenType usernameTokenType = ((JAXBElement<UsernameTokenType>) parseStructure(eventQueue, index)).getValue();

        checkBSPCompliance(inputProcessorChain, usernameTokenType, eventQueue, index);

        if (usernameTokenType.getId() == null) {
            usernameTokenType.setId(UUID.randomUUID().toString());
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
                xmlGregorianCalendar = datatypeFactory.newXMLGregorianCalendar(created);
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
        } else {
            nonceVal = null;
            created = null;
            WSPasswordCallback pwCb;
            if (passwordType == null) {
                passwordType = new PasswordString();
                pwCb = new WSPasswordCallback(username.getValue(),
                        null,
                        null,
                        WSPasswordCallback.Usage.USERNAME_TOKEN_UNKNOWN);
            } else {
                pwCb = new WSPasswordCallback(username.getValue(),
                        passwordType.getValue(),
                        passwordType.getType(),
                        WSPasswordCallback.Usage.USERNAME_TOKEN_UNKNOWN);
            }
            try {
                WSSUtils.doPasswordCallback(securityProperties.getCallbackHandler(), pwCb);
            } catch (WSSecurityException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
            }
            passwordType.setValue(pwCb.getPassword());
        }

        final String password = passwordType.getValue();

        final List<QName> elementPath = getElementPath(inputProcessorChain.getDocumentContext(), eventQueue);
        final XMLEvent responsibleStartXMLEvent = getResponsibleStartXMLEvent(eventQueue, index);

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private WSSecurityToken securityToken = null;

            public SecurityToken getSecurityToken() throws WSSecurityException {
                if (this.securityToken != null) {
                    return this.securityToken;
                }
                this.securityToken = SecurityTokenFactoryImpl.getSecurityToken(username.getValue(), password,
                        created, nonceVal, salt, iteration, (WSSecurityContext) inputProcessorChain.getSecurityContext(), usernameTokenType.getId());
                this.securityToken.setElementPath(elementPath);
                this.securityToken.setXMLEvent(responsibleStartXMLEvent);
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
                                    Deque<XMLEvent> eventDeque, int index) throws WSSecurityException {

        if (usernameTokenType.getAny() == null) {
            ((WSSecurityContext) inputProcessorChain.getSecurityContext()).handleBSPRule(WSSConstants.BSPRule.R3031);
        }

        Iterator<XMLEvent> xmlEventIterator = eventDeque.descendingIterator();
        int curIdx = 0;
        //forward to first Usernametoken child element
        while (curIdx++ <= index) {
            xmlEventIterator.next();
        }
        int passwordIndex = -1;
        int createdIndex = -1;
        int nonceIndex = -1;
        while (xmlEventIterator.hasNext()) {
            XMLEvent xmlEvent = xmlEventIterator.next();
            if (xmlEvent.isStartElement()) {
                if (xmlEvent.asStartElement().getName().equals(WSSConstants.TAG_wsse_Password)) {
                    if (passwordIndex != -1) {
                        ((WSSecurityContext) inputProcessorChain.getSecurityContext()).handleBSPRule(WSSConstants.BSPRule.R4222);
                    }
                    passwordIndex = curIdx;
                } else if (xmlEvent.asStartElement().getName().equals(WSSConstants.TAG_wsu_Created)) {
                    if (createdIndex != -1) {
                        ((WSSecurityContext) inputProcessorChain.getSecurityContext()).handleBSPRule(WSSConstants.BSPRule.R4223);
                    }
                    createdIndex = curIdx;
                } else if (xmlEvent.asStartElement().getName().equals(WSSConstants.TAG_wsse_Nonce)) {
                    if (nonceIndex != -1) {
                        ((WSSecurityContext) inputProcessorChain.getSecurityContext()).handleBSPRule(WSSConstants.BSPRule.R4225);
                    }
                    nonceIndex = curIdx;
                }
            }
            curIdx++;
        }

        PasswordString passwordType = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse_Password);
        if (passwordType != null) {
            if (passwordType.getType() == null) {
                ((WSSecurityContext) inputProcessorChain.getSecurityContext()).handleBSPRule(WSSConstants.BSPRule.R4201);
            }
        }

        EncodedString encodedNonce = XMLSecurityUtils.getQNameType(usernameTokenType.getAny(), WSSConstants.TAG_wsse_Nonce);
        if (encodedNonce != null) {
            if (encodedNonce.getEncodingType() == null) {
                ((WSSecurityContext) inputProcessorChain.getSecurityContext()).handleBSPRule(WSSConstants.BSPRule.R4220);
            } else if (!WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING.equals(encodedNonce.getEncodingType())) {
                ((WSSecurityContext) inputProcessorChain.getSecurityContext()).handleBSPRule(WSSConstants.BSPRule.R4221);
            }
        }

    }
}
