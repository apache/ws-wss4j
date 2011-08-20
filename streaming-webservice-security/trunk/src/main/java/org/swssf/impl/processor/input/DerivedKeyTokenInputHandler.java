/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
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
