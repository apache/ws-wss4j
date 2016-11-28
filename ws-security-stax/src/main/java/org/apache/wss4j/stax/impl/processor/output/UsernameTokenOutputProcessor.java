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
package org.apache.wss4j.stax.impl.processor.output;

import org.apache.commons.codec.binary.Base64;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.impl.securityToken.OutboundUsernameSecurityToken;
import org.apache.wss4j.stax.utils.WSSUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecAttribute;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityToken.OutboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import java.util.ArrayList;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.TimeZone;

public class UsernameTokenOutputProcessor extends AbstractOutputProcessor {

    public UsernameTokenOutputProcessor() throws XMLSecurityException {
        super();
        addAfterProcessor(TimestampOutputProcessor.class.getName());
        addBeforeProcessor(WSSSignatureOutputProcessor.class.getName());
        addBeforeProcessor(EncryptOutputProcessor.class.getName());
    }

    @Override
    public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain) 
        throws XMLStreamException, XMLSecurityException {

        try {
            CallbackHandler callbackHandler = ((WSSSecurityProperties)getSecurityProperties()).getCallbackHandler();
            WSSConstants.UsernameTokenPasswordType usernameTokenPasswordType = 
                ((WSSSecurityProperties) getSecurityProperties()).getUsernameTokenPasswordType();

            if (callbackHandler == null
                && WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE != usernameTokenPasswordType) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noCallback");
            }

            String password = null;
            if (callbackHandler != null) {
                WSPasswordCallback pwCb =
                    new WSPasswordCallback(((WSSSecurityProperties) getSecurityProperties()).getTokenUser(),
                                           WSPasswordCallback.USERNAME_TOKEN);
                WSSUtils.doPasswordCallback(callbackHandler, pwCb);
                password = pwCb.getPassword();
            }

            if (password == null && WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE != usernameTokenPasswordType) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE);
            }

            final String wsuId = IDGenerator.generateID(null);

            boolean useDerivedKeyForMAC =
                ((WSSSecurityProperties)getSecurityProperties()).isUseDerivedKeyForMAC();
            int derivedIterations =
                ((WSSSecurityProperties)getSecurityProperties()).getDerivedKeyIterations();
            byte[] salt = null;
            if (WSSConstants.USERNAMETOKEN_SIGNED.equals(getAction())) {
                salt = UsernameTokenUtil.generateSalt(useDerivedKeyForMAC);
            }

            byte[] nonceValue = null;
            if (usernameTokenPasswordType == WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST
                || ((WSSSecurityProperties) getSecurityProperties()).isAddUsernameTokenNonce()) {
                nonceValue = WSSConstants.generateBytes(16);
            }

            XMLGregorianCalendar created = null;
            String createdStr = "";
            if (usernameTokenPasswordType == WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST
                || ((WSSSecurityProperties) getSecurityProperties()).isAddUsernameTokenCreated()) {
                created = WSSConstants.datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar(TimeZone.getTimeZone("UTC")));
                createdStr = created.toXMLFormat();
            }

            final OutputProcessor outputProcessor = this;

            final OutboundUsernameSecurityToken usernameSecurityToken =
                    new OutboundUsernameSecurityToken(((WSSSecurityProperties) getSecurityProperties()).getTokenUser(),
                            password,
                            createdStr,
                            nonceValue,
                            wsuId,
                            salt,
                            derivedIterations
                    );
            usernameSecurityToken.setProcessor(outputProcessor);

            SecurityTokenProvider<OutboundSecurityToken> securityTokenProvider =
                    new SecurityTokenProvider<OutboundSecurityToken>() {

                @Override
                public OutboundSecurityToken getSecurityToken() throws WSSecurityException {
                    return usernameSecurityToken;
                }

                @Override
                public String getId() {
                    return wsuId;
                }
            };
            if (WSSConstants.USERNAMETOKEN_SIGNED.equals(getAction())) {
                outputProcessorChain.getSecurityContext().registerSecurityTokenProvider(wsuId, securityTokenProvider);
                outputProcessorChain.getSecurityContext().put(WSSConstants.PROP_USE_THIS_TOKEN_ID_FOR_SIGNATURE, wsuId);
            }
            final FinalUsernameTokenOutputProcessor finalUsernameTokenOutputProcessor =
                new FinalUsernameTokenOutputProcessor(wsuId, nonceValue, password, created, salt, derivedIterations, getAction());
            finalUsernameTokenOutputProcessor.setXMLSecurityProperties(getSecurityProperties());
            finalUsernameTokenOutputProcessor.setAction(getAction());
            finalUsernameTokenOutputProcessor.init(outputProcessorChain);

        } finally {
            outputProcessorChain.removeProcessor(this);
        }
        outputProcessorChain.processEvent(xmlSecEvent);
    }

    static class FinalUsernameTokenOutputProcessor extends AbstractOutputProcessor {

        private String wsuId = null;
        private byte[] nonceValue = null;
        private String password = null;
        private XMLGregorianCalendar created = null;
        private byte[] salt;
        private int iterations;
        private XMLSecurityConstants.Action action;

        FinalUsernameTokenOutputProcessor(String wsuId, byte[] nonceValue, String password,
                                          XMLGregorianCalendar created, byte[] salt,
                                          int iterations, XMLSecurityConstants.Action action)
                throws XMLSecurityException {
            super();
            this.addAfterProcessor(UsernameTokenOutputProcessor.class.getName());
            this.addAfterProcessor(UsernameTokenOutputProcessor.class.getName());
            this.wsuId = wsuId;
            this.nonceValue = nonceValue;
            this.password = password;
            this.created = created;
            this.salt = salt;
            this.iterations = iterations;
            this.action = action;
        }

        @Override
        public void processEvent(XMLSecEvent xmlSecEvent, OutputProcessorChain outputProcessorChain)
                throws XMLStreamException, XMLSecurityException {

            outputProcessorChain.processEvent(xmlSecEvent);

            if (WSSUtils.isSecurityHeaderElement(xmlSecEvent, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {

                final QName headerElementName = WSSConstants.TAG_WSSE_USERNAME_TOKEN;
                OutputProcessorUtils.updateSecurityHeaderOrder(outputProcessorChain, headerElementName, getAction(), false);

                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                List<XMLSecAttribute> attributes = new ArrayList<>(1);
                attributes.add(createAttribute(WSSConstants.ATT_WSU_ID, this.wsuId));
                createStartElementAndOutputAsEvent(subOutputProcessorChain, headerElementName, false, attributes);
                createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSSE_USERNAME, false, null);
                createCharactersAndOutputAsEvent(subOutputProcessorChain, 
                                                 ((WSSSecurityProperties) getSecurityProperties()).getTokenUser());
                createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSSE_USERNAME);
                if (((WSSSecurityProperties) getSecurityProperties()).getUsernameTokenPasswordType() 
                    != WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE && !WSSConstants.USERNAMETOKEN_SIGNED.equals(action)) {
                    attributes = new ArrayList<>(1);
                    attributes.add(createAttribute(WSSConstants.ATT_NULL_Type,
                            ((WSSSecurityProperties) getSecurityProperties()).getUsernameTokenPasswordType() 
                                == WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST
                                    ? WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST.getNamespace()
                                    : WSSConstants.UsernameTokenPasswordType.PASSWORD_TEXT.getNamespace()));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSSE_PASSWORD, false, attributes);
                    createCharactersAndOutputAsEvent(subOutputProcessorChain,
                            ((WSSSecurityProperties) getSecurityProperties()).getUsernameTokenPasswordType() 
                                == WSSConstants.UsernameTokenPasswordType.PASSWORD_DIGEST
                                    ? WSSUtils.doPasswordDigest(this.nonceValue, this.created.toXMLFormat(), this.password)
                                    : this.password);
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSSE_PASSWORD);
                }

                if (salt != null) {
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSSE11_SALT, true, null);
                    createCharactersAndOutputAsEvent(subOutputProcessorChain, new Base64(76, new byte[]{'\n'}).encodeToString(this.salt));
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSSE11_SALT);

                    if (iterations > 0) {
                        createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSSE11_ITERATION, true, null);
                        createCharactersAndOutputAsEvent(subOutputProcessorChain, "" + iterations);
                        createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSSE11_ITERATION);
                    }
                }

                if (nonceValue != null && !WSSConstants.USERNAMETOKEN_SIGNED.equals(action)) {
                    attributes = new ArrayList<>(1);
                    attributes.add(createAttribute(WSSConstants.ATT_NULL_ENCODING_TYPE, WSSConstants.SOAPMESSAGE_NS10_BASE64_ENCODING));
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSSE_NONCE, false, attributes);
                    createCharactersAndOutputAsEvent(subOutputProcessorChain, 
                                                     new Base64(76, new byte[]{'\n'}).encodeToString(this.nonceValue));
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSSE_NONCE);
                }

                if (created != null && !WSSConstants.USERNAMETOKEN_SIGNED.equals(action)) {
                    createStartElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSU_CREATED, false, null);
                    createCharactersAndOutputAsEvent(subOutputProcessorChain, this.created.toXMLFormat());
                    createEndElementAndOutputAsEvent(subOutputProcessorChain, WSSConstants.TAG_WSU_CREATED);
                }

                createEndElementAndOutputAsEvent(subOutputProcessorChain, headerElementName);

                outputProcessorChain.removeProcessor(this);
            }
        }
    }
}
