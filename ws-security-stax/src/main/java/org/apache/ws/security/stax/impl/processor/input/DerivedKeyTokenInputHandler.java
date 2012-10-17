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
package org.apache.ws.security.stax.impl.processor.input;

import org.apache.ws.security.binding.wssc.AbstractDerivedKeyTokenType;
import org.apache.ws.security.common.derivedKey.DerivedKeyUtils;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.ext.WSSecurityContext;
import org.apache.ws.security.stax.impl.securityToken.SAMLSecurityToken;
import org.apache.ws.security.stax.impl.securityToken.SecurityTokenFactoryImpl;
import org.apache.ws.security.stax.impl.securityToken.UsernameSecurityToken;
import org.apache.ws.security.stax.securityEvent.DerivedKeyTokenSecurityEvent;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityEvent.AlgorithmSuiteSecurityEvent;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import java.security.Key;
import java.util.Deque;
import java.util.List;

/**
 * Processor for the SecurityContextToken XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
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

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private AbstractInboundSecurityToken derivedKeySecurityToken = null;

            @Override
            public SecurityToken getSecurityToken() throws XMLSecurityException {

                if (this.derivedKeySecurityToken != null) {
                    return this.derivedKeySecurityToken;
                }

                //todo implement interface to access all derivedKeys? The same would be needed in UserNameToken
                this.derivedKeySecurityToken = new AbstractInboundSecurityToken(
                        (WSSecurityContext) inputProcessorChain.getSecurityContext(),
                        derivedKeyTokenType.getId(), null) {

                    private SecurityToken referencedSecurityToken = null;

                    private SecurityToken getReferencedSecurityToken() throws XMLSecurityException {
                        if (this.referencedSecurityToken != null) {
                            return referencedSecurityToken;
                        }

                        this.referencedSecurityToken = SecurityTokenFactoryImpl.getSecurityToken(
                                derivedKeyTokenType.getSecurityTokenReference(),
                                ((WSSSecurityProperties) securityProperties).getDecryptionCrypto(),
                                securityProperties.getCallbackHandler(),
                                inputProcessorChain.getSecurityContext()
                        );
                        this.referencedSecurityToken.addWrappedToken(this);
                        return this.referencedSecurityToken;
                    }

                    @Override
                    protected Key getKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage,
                                         String correlationID) throws XMLSecurityException {
                        byte[] secret;
                        SecurityToken referencedSecurityToken = getReferencedSecurityToken();
                        if (referencedSecurityToken != null) {
                            if (referencedSecurityToken instanceof UsernameSecurityToken) {
                                UsernameSecurityToken usernameSecurityToken = (UsernameSecurityToken) referencedSecurityToken;
                                secret = usernameSecurityToken.generateDerivedKey();
                            } else if (referencedSecurityToken instanceof SAMLSecurityToken) {
                                SAMLSecurityToken samlSecurityToken = (SAMLSecurityToken) referencedSecurityToken;
                                secret = samlSecurityToken.getSamlKeyInfo().getSecret();
                            } else {
                                secret = referencedSecurityToken.getSecretKey(algorithmURI, keyUsage, correlationID).getEncoded();
                            }
                        } else {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "unsupportedKeyId");
                        }
                        byte[] nonce = derivedKeyTokenType.getNonce();
                        if (nonce == null || nonce.length == 0) {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "empty", "Missing wsc:Nonce value");
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
                        XMLSecurityConstants.KeyUsage derivedKeyUsage;
                        if (WSSConstants.Enc.equals(keyUsage)) {
                            derivedKeyUsage = WSSConstants.Enc_KD;
                        } else {
                            derivedKeyUsage = WSSConstants.Sig_KD;
                        }
                        AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = new AlgorithmSuiteSecurityEvent();
                        algorithmSuiteSecurityEvent.setAlgorithmURI(derivedKeyAlgorithm);
                        algorithmSuiteSecurityEvent.setKeyUsage(derivedKeyUsage);
                        algorithmSuiteSecurityEvent.setKeyLength(keyBytes.length * 8);
                        algorithmSuiteSecurityEvent.setCorrelationID(correlationID);
                        inputProcessorChain.getSecurityContext().registerSecurityEvent(algorithmSuiteSecurityEvent);

                        String algo = JCEAlgorithmMapper.getJCERequiredKeyFromURI(algorithmURI);
                        return new SecretKeySpec(keyBytes, algo);
                    }

                    @Override
                    public SecurityToken getKeyWrappingToken() throws XMLSecurityException {
                        return getReferencedSecurityToken();
                    }

                    @Override
                    public WSSConstants.TokenType getTokenType() {
                        return WSSConstants.DerivedKeyToken;
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
        derivedKeyTokenSecurityEvent.setSecurityToken((SecurityToken) securityTokenProvider.getSecurityToken());
        derivedKeyTokenSecurityEvent.setCorrelationID(derivedKeyTokenType.getId());
        ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(derivedKeyTokenSecurityEvent);
    }
}
