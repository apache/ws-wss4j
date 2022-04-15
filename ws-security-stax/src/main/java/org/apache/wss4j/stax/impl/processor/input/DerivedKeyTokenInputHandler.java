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
package org.apache.wss4j.stax.impl.processor.input;

import java.security.Key;
import java.util.Deque;
import java.util.List;

import javax.crypto.spec.SecretKeySpec;
import jakarta.xml.bind.JAXBElement;
import javax.xml.namespace.QName;

import org.apache.wss4j.binding.wssc.AbstractDerivedKeyTokenType;
import org.apache.wss4j.common.derivedKey.DerivedKeyUtils;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.impl.securityToken.SecurityTokenFactoryImpl;
import org.apache.wss4j.stax.securityEvent.DerivedKeyTokenSecurityEvent;
import org.apache.wss4j.stax.securityToken.UsernameSecurityToken;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.AbstractInputSecurityHeaderHandler;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.AlgorithmSuiteSecurityEvent;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

/**
 * Processor for the SecurityContextToken XML Structure
 */
public class DerivedKeyTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLSecEvent> eventQueue, Integer index) throws XMLSecurityException {

        @SuppressWarnings("unchecked")
        final AbstractDerivedKeyTokenType derivedKeyTokenType =
                ((JAXBElement<AbstractDerivedKeyTokenType>) parseStructure(eventQueue, index, securityProperties)).getValue();
        if (derivedKeyTokenType.getId() == null) {
            derivedKeyTokenType.setId(IDGenerator.generateID(null));
        }
        if (derivedKeyTokenType.getSecurityTokenReference() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "noReference");
        }

        final List<QName> elementPath = getElementPath(eventQueue);
        final XMLSecEvent responsibleXMLSecStartXMLEvent = getResponsibleStartXMLEvent(eventQueue, index);

        SecurityTokenProvider<InboundSecurityToken> securityTokenProvider = new SecurityTokenProvider<InboundSecurityToken>() {

            private AbstractInboundSecurityToken derivedKeySecurityToken;

            @Override
            public InboundSecurityToken getSecurityToken() throws XMLSecurityException {

                if (this.derivedKeySecurityToken != null) {
                    return this.derivedKeySecurityToken;
                }

                //todo implement interface to access all derivedKeys? The same would be needed in UserNameToken
                this.derivedKeySecurityToken = new AbstractInboundSecurityToken(
                        (WSInboundSecurityContext) inputProcessorChain.getSecurityContext(),
                        derivedKeyTokenType.getId(), WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE,
                        true) {

                    private InboundSecurityToken referencedSecurityToken;

                    private InboundSecurityToken getReferencedSecurityToken() throws XMLSecurityException {
                        if (this.referencedSecurityToken != null) {
                            return referencedSecurityToken;
                        }

                        this.referencedSecurityToken = SecurityTokenFactoryImpl.getSecurityToken(
                                derivedKeyTokenType.getSecurityTokenReference(),
                                ((WSSSecurityProperties) securityProperties).getDecryptionCrypto(),
                                ((WSSSecurityProperties)securityProperties).getCallbackHandler(),
                                inputProcessorChain.getSecurityContext(),
                                (WSSSecurityProperties)securityProperties
                        );
                        this.referencedSecurityToken.addWrappedToken(this);
                        return this.referencedSecurityToken;
                    }

                    @Override
                    protected Key getKey(String algorithmURI, XMLSecurityConstants.AlgorithmUsage algorithmUsage,
                                         String correlationID) throws XMLSecurityException {
                        byte[] secret;
                        InboundSecurityToken referencedSecurityToken = getReferencedSecurityToken();
                        if (referencedSecurityToken != null) {
                            if (referencedSecurityToken instanceof UsernameSecurityToken) {
                                UsernameSecurityToken usernameSecurityToken = (UsernameSecurityToken) referencedSecurityToken;
                                secret = usernameSecurityToken.generateDerivedKey();
                            } else {
                                secret = referencedSecurityToken.getSecretKey(algorithmURI, algorithmUsage, correlationID).getEncoded();
                            }
                        } else {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "unsupportedKeyId");
                        }
                        byte[] nonce = derivedKeyTokenType.getNonce();
                        if (nonce == null || nonce.length == 0) {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "empty",
                                                          new Object[] {"Missing wsc:Nonce value"});
                        }
                        String derivedKeyAlgorithm = derivedKeyTokenType.getAlgorithm();
                        if (derivedKeyAlgorithm == null) {
                            derivedKeyAlgorithm = WSSConstants.P_SHA_1;
                        }
                        byte[] keyBytes = DerivedKeyUtils.deriveKey(
                                derivedKeyAlgorithm,
                                derivedKeyTokenType.getLabel(),
                                derivedKeyTokenType.getLength().intValue(),
                                secret,
                                nonce,
                                derivedKeyTokenType.getOffset().intValue()
                        );
                        XMLSecurityConstants.AlgorithmUsage derivedKeyAlgorithmUsage;
                        if (WSSConstants.Enc.equals(algorithmUsage)) {
                            derivedKeyAlgorithmUsage = WSSConstants.ENC_KD;
                        } else {
                            derivedKeyAlgorithmUsage = WSSConstants.SIG_KD;
                        }
                        AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
                        algorithmSuiteSecurityEvent.setAlgorithmURI(derivedKeyAlgorithm);
                        algorithmSuiteSecurityEvent.setAlgorithmUsage(derivedKeyAlgorithmUsage);
                        algorithmSuiteSecurityEvent.setKeyLength(keyBytes.length * 8);
                        algorithmSuiteSecurityEvent.setCorrelationID(correlationID);
                        inputProcessorChain.getSecurityContext().registerSecurityEvent(algorithmSuiteSecurityEvent);

                        String algo = JCEAlgorithmMapper.getJCEKeyAlgorithmFromURI(algorithmURI);
                        return new SecretKeySpec(keyBytes, algo);
                    }

                    @Override
                    public InboundSecurityToken getKeyWrappingToken() throws XMLSecurityException {
                        return getReferencedSecurityToken();
                    }

                    @Override
                    public WSSecurityTokenConstants.TokenType getTokenType() {
                        return WSSecurityTokenConstants.DerivedKeyToken;
                    }
                };
                this.derivedKeySecurityToken.setElementPath(elementPath);
                this.derivedKeySecurityToken.setXMLSecEvent(responsibleXMLSecStartXMLEvent);
                return this.derivedKeySecurityToken;
            }

            @Override
            public String getId() {
                return derivedKeyTokenType.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(derivedKeyTokenType.getId(), securityTokenProvider);

        //fire a tokenSecurityEvent
        DerivedKeyTokenSecurityEvent derivedKeyTokenSecurityEvent = new DerivedKeyTokenSecurityEvent();
        derivedKeyTokenSecurityEvent.setSecurityToken(securityTokenProvider.getSecurityToken());
        derivedKeyTokenSecurityEvent.setCorrelationID(derivedKeyTokenType.getId());
        inputProcessorChain.getSecurityContext().registerSecurityEvent(derivedKeyTokenSecurityEvent);
    }
}
