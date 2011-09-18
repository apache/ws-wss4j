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
package org.swssf.impl.processor.input;

import org.apache.commons.codec.binary.Base64;
import org.apache.jcs.JCS;
import org.apache.jcs.access.exception.CacheException;
import org.apache.jcs.engine.ElementAttributes;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.UsernameTokenType;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.securityToken.SecurityTokenFactory;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.UsernameTokenSecurityEvent;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.events.StartElement;
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

    static {
        try {
            cache = JCS.getInstance(cacheRegionName);
        } catch (CacheException e) {
            throw new RuntimeException(e);
        }
    }

    public UsernameTokenInputHandler(final InputProcessorChain inputProcessorChain, final SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException {

        final UsernameTokenType usernameTokenType = (UsernameTokenType) parseStructure(eventQueue, index);
        if (usernameTokenType.getId() == null) {
            usernameTokenType.setId(UUID.randomUUID().toString());
        }

        // If the UsernameToken is to be used for key derivation, the (1.1)
        // spec says that it cannot contain a password, and it must contain
        // an Iteration element
        if (usernameTokenType.getSalt() != null && (usernameTokenType.getPassword() != null || usernameTokenType.getIteration() == null)) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "badTokenType01");
        }

        Integer iteration = null;
        if (usernameTokenType.getIteration() != null) {
            iteration = Integer.parseInt(usernameTokenType.getIteration());
        }

        GregorianCalendar createdCal = null;
        byte[] nonceVal = null;

        Constants.UsernameTokenPasswordType usernameTokenPasswordType = Constants.UsernameTokenPasswordType.PASSWORD_NONE;
        if (usernameTokenType.getPasswordType() != null) {
            usernameTokenPasswordType = Constants.UsernameTokenPasswordType.getUsernameTokenPasswordType(usernameTokenType.getPasswordType());
        }

        final String username = usernameTokenType.getUsername();
        if (usernameTokenPasswordType == Constants.UsernameTokenPasswordType.PASSWORD_DIGEST) {
            final String nonce = usernameTokenType.getNonce();
            if (nonce == null || usernameTokenType.getCreated() == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "badTokenType01");
            }

            /*
                It is RECOMMENDED that used nonces be cached for a period at least as long as
                the timestamp freshness limitation period, above, and that UsernameToken with
                nonces that have already been used (and are thus in the cache) be rejected
            */
            final String cacheKey = nonce;
            if (cache.get(cacheKey) != null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
            ElementAttributes elementAttributes = new ElementAttributes();
            elementAttributes.setMaxLifeSeconds(300);
            try {
                cache.put(cacheKey, usernameTokenType.getCreated(), elementAttributes);
            } catch (CacheException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
            }

            DatatypeFactory datatypeFactory = null;
            try {
                datatypeFactory = DatatypeFactory.newInstance();
            } catch (DatatypeConfigurationException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
            }
            XMLGregorianCalendar xmlGregorianCalendar = datatypeFactory.newXMLGregorianCalendar(usernameTokenType.getCreated());
            createdCal = xmlGregorianCalendar.toGregorianCalendar();
            GregorianCalendar now = new GregorianCalendar();
            if (createdCal.after(now)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
            now.add(Calendar.MINUTE, 5);
            if (createdCal.after(now)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }

            WSPasswordCallback pwCb = new WSPasswordCallback(username,
                    null,
                    usernameTokenType.getPasswordType(),
                    WSPasswordCallback.Usage.USERNAME_TOKEN);
            try {
                Utils.doPasswordCallback(securityProperties.getCallbackHandler(), pwCb);
            } catch (WSSecurityException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
            }

            if (pwCb.getPassword() == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }

            nonceVal = Base64.decodeBase64(nonce);

            String passDigest = Utils.doPasswordDigest(nonceVal, usernameTokenType.getCreated(), pwCb.getPassword());
            if (!usernameTokenType.getPassword().equals(passDigest)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
            }
            usernameTokenType.setPassword(pwCb.getPassword());
        } else {
            WSPasswordCallback pwCb = new WSPasswordCallback(username,
                    usernameTokenType.getPassword(),
                    usernameTokenType.getPasswordType(),
                    WSPasswordCallback.Usage.USERNAME_TOKEN_UNKNOWN);
            try {
                Utils.doPasswordCallback(securityProperties.getCallbackHandler(), pwCb);
            } catch (WSSecurityException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
            }
            usernameTokenType.setPassword(pwCb.getPassword());
        }

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private Map<Crypto, SecurityToken> securityTokens = new HashMap<Crypto, SecurityToken>();

            public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                SecurityToken securityToken = securityTokens.get(crypto);
                if (securityToken != null) {
                    return securityToken;
                }
                securityToken = SecurityTokenFactory.newInstance().getSecurityToken(
                        usernameTokenType, inputProcessorChain.getSecurityContext(), null);
                securityTokens.put(crypto, securityToken);
                return securityToken;
            }

            public String getId() {
                return usernameTokenType.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(usernameTokenType.getId(), securityTokenProvider);

        UsernameTokenSecurityEvent usernameTokenSecurityEvent = new UsernameTokenSecurityEvent(SecurityEvent.Event.UsernameToken);
        usernameTokenSecurityEvent.setUsernameTokenPasswordType(usernameTokenPasswordType);
        usernameTokenSecurityEvent.setSecurityToken(securityTokenProvider.getSecurityToken(null));
        usernameTokenSecurityEvent.setUsernameTokenProfile(Constants.NS_USERNAMETOKEN_PROFILE11);
        inputProcessorChain.getSecurityContext().registerSecurityEvent(usernameTokenSecurityEvent);
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new UsernameTokenType(startElement);
    }
}
