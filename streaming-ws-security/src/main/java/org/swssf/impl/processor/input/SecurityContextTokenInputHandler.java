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

import org.oasis_open.docs.ws_sx.ws_secureconversation._200512.SecurityContextTokenType;
import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.securityToken.AbstractAlgorithmSuiteSecurityEventFiringSecurityToken;
import org.swssf.securityEvent.SecurityContextTokenSecurityEvent;
import org.swssf.securityEvent.SecurityEvent;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.stream.events.StartElement;
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

    public SecurityContextTokenInputHandler(InputProcessorChain inputProcessorChain, final SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException {

        final SecurityContextTokenType securityContextTokenType = (SecurityContextTokenType) parseStructure(eventQueue, index);
        if (securityContextTokenType.getId() == null) {
            securityContextTokenType.setId(UUID.randomUUID().toString());
        }

        final SecurityToken securityContextToken = new AbstractAlgorithmSuiteSecurityEventFiringSecurityToken(inputProcessorChain.getSecurityContext(), securityContextTokenType.getId()) {

            public boolean isAsymmetric() {
                return false;
            }

            public Key getSecretKey(String algorithmURI, Constants.KeyUsage keyUsage) throws WSSecurityException {
                super.getSecretKey(algorithmURI, keyUsage);
                String algo = JCEAlgorithmMapper.translateURItoJCEID(algorithmURI);
                WSPasswordCallback passwordCallback = new WSPasswordCallback(securityContextTokenType.getIdentifier(), WSPasswordCallback.Usage.SECURITY_CONTEXT_TOKEN);
                Utils.doSecretKeyCallback(securityProperties.getCallbackHandler(), passwordCallback, null);
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

            public Constants.TokenType getTokenType() {
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
                return securityContextTokenType.getIdentifier();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(securityContextTokenType.getIdentifier(), securityTokenProviderDirectReference);

        SecurityContextTokenSecurityEvent securityContextTokenSecurityEvent = new SecurityContextTokenSecurityEvent(SecurityEvent.Event.SecurityContextToken);
        securityContextTokenSecurityEvent.setSecurityToken(securityContextToken);
        //todo how to find the issuer?
        securityContextTokenSecurityEvent.setIssuerName(securityContextTokenType.getIdentifier());
        securityContextTokenSecurityEvent.setExternalUriRef(securityContextTokenType.getIdentifier() != null);
        inputProcessorChain.getSecurityContext().registerSecurityEvent(securityContextTokenSecurityEvent);
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new SecurityContextTokenType(startElement);
    }
}
