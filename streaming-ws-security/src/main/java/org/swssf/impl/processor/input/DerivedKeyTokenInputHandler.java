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

import org.oasis_open.docs.ws_sx.ws_secureconversation._200512.DerivedKeyTokenType;
import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.derivedKey.DerivedKeyUtils;
import org.swssf.impl.securityToken.AbstractAlgorithmSuiteSecurityEventFiringSecurityToken;
import org.swssf.impl.securityToken.SAMLSecurityToken;
import org.swssf.impl.securityToken.SecurityTokenFactory;
import org.swssf.impl.securityToken.UsernameSecurityToken;

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
public class DerivedKeyTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    public DerivedKeyTokenInputHandler(final InputProcessorChain inputProcessorChain, final SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException {

        final DerivedKeyTokenType derivedKeyTokenType = (DerivedKeyTokenType) parseStructure(eventQueue, index);
        if (derivedKeyTokenType.getId() == null) {
            derivedKeyTokenType.setId(UUID.randomUUID().toString());
        }
        if (derivedKeyTokenType.getSecurityTokenReference() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, "noReference");
        }

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private Map<Crypto, SecurityToken> securityTokens = new HashMap<Crypto, SecurityToken>();

            public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {

                SecurityToken securityToken = securityTokens.get(crypto);
                if (securityToken != null) {
                    return securityToken;
                }

                final SecurityToken referencedSecurityToken = SecurityTokenFactory.newInstance().getSecurityToken(
                        derivedKeyTokenType.getSecurityTokenReference(),
                        securityProperties.getDecryptionCrypto(),
                        securityProperties.getCallbackHandler(),
                        inputProcessorChain.getSecurityContext(),
                        null
                );

                securityToken = new AbstractAlgorithmSuiteSecurityEventFiringSecurityToken(inputProcessorChain.getSecurityContext(), derivedKeyTokenType.getId()) {

                    public boolean isAsymmetric() {
                        return false;
                    }

                    public Key getSecretKey(String algorithmURI, Constants.KeyUsage keyUsage) throws WSSecurityException {
                        super.getSecretKey(algorithmURI, keyUsage);
                        byte[] secret;
                        if (referencedSecurityToken != null) {
                            if (referencedSecurityToken instanceof UsernameSecurityToken) {
                                UsernameSecurityToken usernameSecurityToken = (UsernameSecurityToken) referencedSecurityToken;
                                secret = usernameSecurityToken.generateDerivedKey(
                                        usernameSecurityToken.getPassword(),
                                        usernameSecurityToken.getSalt(),
                                        usernameSecurityToken.getIteration()
                                );
                            } else if (referencedSecurityToken instanceof SAMLSecurityToken) {
                                SAMLSecurityToken samlSecurityToken = (SAMLSecurityToken) referencedSecurityToken;
                                secret = samlSecurityToken.getSamlKeyInfo().getSecret();
                            } else {
                                //todo is this the correct algo and KeyUsage?
                                secret = referencedSecurityToken.getSecretKey(algorithmURI, Constants.KeyUsage.Sig_KD).getEncoded();
                            }
                        } else {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, "unsupportedKeyId");
                        }
                        byte[] nonce = derivedKeyTokenType.getNonce();
                        if (nonce == null || nonce.length == 0) {
                            throw new WSSecurityException("Missing wsc:Nonce value");
                        }
                        byte[] keyBytes = DerivedKeyUtils.deriveKey(
                                derivedKeyTokenType.getAlgorithm(),
                                derivedKeyTokenType.getLabel(),
                                derivedKeyTokenType.getLength(),
                                secret,
                                nonce,
                                derivedKeyTokenType.getOffset()
                        );
                        String algo = JCEAlgorithmMapper.translateURItoJCEID(algorithmURI);
                        return new SecretKeySpec(keyBytes, algo);
                    }

                    public SecurityToken getKeyWrappingToken() {
                        //todo?
                        return null;
                    }

                    public String getKeyWrappingTokenAlgorithm() {
                        //todo?
                        return null;
                    }

                    public Constants.TokenType getTokenType() {
                        //todo?
                        return null;
                    }
                };
                securityTokens.put(crypto, securityToken);
                return securityToken;
            }

            public String getId() {
                return derivedKeyTokenType.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(derivedKeyTokenType.getId(), securityTokenProvider);
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new DerivedKeyTokenType(startElement);
    }
}
