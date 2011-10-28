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

import org.swssf.binding.wssc.AbstractSecurityContextTokenType;
import org.swssf.wss.ext.*;
import org.swssf.wss.impl.securityToken.AbstractAlgorithmSuiteSecurityEventFiringSecurityToken;
import org.swssf.wss.securityEvent.SecurityContextTokenSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.xmlsec.config.JCEAlgorithmMapper;
import org.swssf.xmlsec.crypto.Crypto;
import org.swssf.xmlsec.ext.*;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.stream.events.XMLEvent;
import java.security.Key;
import java.util.Deque;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Processor for the SecurityContextToken XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityContextTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    public SecurityContextTokenInputHandler(InputProcessorChain inputProcessorChain,
                                            final WSSSecurityProperties securityProperties,
                                            Deque<XMLEvent> eventQueue, Integer index) throws XMLSecurityException {

        @SuppressWarnings("unchecked")
        JAXBElement<AbstractSecurityContextTokenType> securityContextTokenTypeJAXBElement =
                ((JAXBElement<AbstractSecurityContextTokenType>) parseStructure(eventQueue, index));
        final AbstractSecurityContextTokenType securityContextTokenType = securityContextTokenTypeJAXBElement.getValue();
        if (securityContextTokenType.getId() == null) {
            securityContextTokenType.setId(UUID.randomUUID().toString());
        }

        final String identifier = (String) XMLSecurityUtils.getQNameType(securityContextTokenType.getAny(),
                new QName(securityContextTokenTypeJAXBElement.getName().getNamespaceURI(), WSSConstants.TAG_wsc0502_Identifier.getLocalPart()));

        final SecurityToken securityContextToken = new AbstractAlgorithmSuiteSecurityEventFiringSecurityToken(
                inputProcessorChain.getSecurityContext(), securityContextTokenType.getId()) {

            public boolean isAsymmetric() {
                return false;
            }

            public Key getSecretKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
                super.getSecretKey(algorithmURI, keyUsage);
                String algo = JCEAlgorithmMapper.translateURItoJCEID(algorithmURI);
                WSPasswordCallback passwordCallback = new WSPasswordCallback(identifier, WSPasswordCallback.Usage.SECURITY_CONTEXT_TOKEN);
                WSSUtils.doSecretKeyCallback(securityProperties.getCallbackHandler(), passwordCallback, null);
                if (passwordCallback.getKey() == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noKey", securityContextTokenType.getId());
                }
                return new SecretKeySpec(passwordCallback.getKey(), algo);
            }

            public SecurityToken getKeyWrappingToken() {
                return null;
            }

            public String getKeyWrappingTokenAlgorithm() {
                return null;
            }

            public WSSConstants.TokenType getTokenType() {
                //todo and set externalUriRef
                return null;
            }
        };

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private Map<Crypto, SecurityToken> securityTokens = new HashMap<Crypto, SecurityToken>();

            public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                SecurityToken securityToken = securityTokens.get(crypto);
                if (securityToken != null) {
                    return securityToken;
                }
                securityTokens.put(crypto, securityContextToken);
                return securityContextToken;
            }

            public String getId() {
                return securityContextTokenType.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(securityContextTokenType.getId(), securityTokenProvider);

        //also register a SecurityProvider with the identifier. @see SecurityContexTest#testSCTKDKTSignAbsolute
        SecurityTokenProvider securityTokenProviderDirectReference = new SecurityTokenProvider() {

            private Map<Crypto, SecurityToken> securityTokens = new HashMap<Crypto, SecurityToken>();

            public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                SecurityToken securityToken = securityTokens.get(crypto);
                if (securityToken != null) {
                    return securityToken;
                }
                securityTokens.put(crypto, securityContextToken);
                return securityContextToken;
            }

            public String getId() {
                return identifier;
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(identifier, securityTokenProviderDirectReference);

        SecurityContextTokenSecurityEvent securityContextTokenSecurityEvent = new SecurityContextTokenSecurityEvent(SecurityEvent.Event.SecurityContextToken);
        securityContextTokenSecurityEvent.setSecurityToken(securityContextToken);
        //todo how to find the issuer?
        securityContextTokenSecurityEvent.setIssuerName(identifier);
        securityContextTokenSecurityEvent.setExternalUriRef(identifier != null);
        ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(securityContextTokenSecurityEvent);
    }
}
