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

import org.swssf.binding.wssc.AbstractDerivedKeyTokenType;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSecurityContext;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.impl.derivedKey.DerivedKeyUtils;
import org.swssf.wss.impl.securityToken.AbstractSecurityToken;
import org.swssf.wss.impl.securityToken.SAMLSecurityToken;
import org.swssf.wss.impl.securityToken.SecurityTokenFactoryImpl;
import org.swssf.wss.impl.securityToken.UsernameSecurityToken;
import org.swssf.xmlsec.config.JCEAlgorithmMapper;
import org.swssf.xmlsec.crypto.Crypto;
import org.swssf.xmlsec.ext.*;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.JAXBElement;
import javax.xml.stream.events.XMLEvent;
import java.security.Key;
import java.security.PublicKey;
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

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLEvent> eventQueue, Integer index) throws XMLSecurityException {

        @SuppressWarnings("unchecked")
        final AbstractDerivedKeyTokenType derivedKeyTokenType =
                ((JAXBElement<AbstractDerivedKeyTokenType>) parseStructure(eventQueue, index)).getValue();
        if (derivedKeyTokenType.getId() == null) {
            derivedKeyTokenType.setId(UUID.randomUUID().toString());
        }
        if (derivedKeyTokenType.getSecurityTokenReference() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, "noReference");
        }

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private Map<Crypto, SecurityToken> securityTokens = new HashMap<Crypto, SecurityToken>();

            public SecurityToken getSecurityToken(Crypto crypto) throws XMLSecurityException {

                SecurityToken securityToken = securityTokens.get(crypto);
                if (securityToken != null) {
                    return securityToken;
                }

                final SecurityToken referencedSecurityToken = SecurityTokenFactoryImpl.getSecurityToken(
                        derivedKeyTokenType.getSecurityTokenReference(),
                        securityProperties.getDecryptionCrypto(),
                        securityProperties.getCallbackHandler(),
                        inputProcessorChain.getSecurityContext(),
                        null
                );

                securityToken = new AbstractSecurityToken(
                        (WSSecurityContext) inputProcessorChain.getSecurityContext(), null, null,
                        derivedKeyTokenType.getId(), null, null) {

                    public boolean isAsymmetric() {
                        return false;
                    }

                    protected Key getKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
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
                                WSSConstants.KeyUsage newKeyUsage;
                                if (keyUsage == WSSConstants.Sym_Sig || keyUsage == WSSConstants.Asym_Sig || keyUsage == WSSConstants.Sig_KD) {
                                    newKeyUsage = WSSConstants.Sig_KD;
                                } else {
                                    newKeyUsage = WSSConstants.Enc_KD;
                                }
                                secret = referencedSecurityToken.getSecretKey(algorithmURI, keyUsage).getEncoded();
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
                                derivedKeyTokenType.getLength().intValue(),
                                secret,
                                nonce,
                                derivedKeyTokenType.getOffset().intValue()
                        );
                        String algo = JCEAlgorithmMapper.translateURItoJCEID(algorithmURI);
                        return new SecretKeySpec(keyBytes, algo);
                    }

                    @Override
                    protected PublicKey getPubKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage) throws XMLSecurityException {
                        return null;
                    }

                    public SecurityToken getKeyWrappingToken() {
                        return referencedSecurityToken;
                    }

                    public String getKeyWrappingTokenAlgorithm() {
                        //todo?
                        return null;
                    }

                    public WSSConstants.TokenType getTokenType() {
                        return WSSConstants.DerivedKeyToken;
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
}
