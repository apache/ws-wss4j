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
