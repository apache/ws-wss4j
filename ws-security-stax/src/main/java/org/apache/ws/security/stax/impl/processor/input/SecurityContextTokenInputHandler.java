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

import org.apache.ws.security.binding.wssc.AbstractSecurityContextTokenType;
import org.apache.ws.security.common.ext.WSPasswordCallback;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSUtils;
import org.apache.ws.security.stax.ext.WSSecurityContext;
import org.apache.ws.security.stax.securityEvent.SecurityContextTokenSecurityEvent;
import org.apache.xml.security.stax.config.JCEAlgorithmMapper;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.securityToken.AbstractInboundSecurityToken;
import org.apache.xml.security.stax.impl.util.IDGenerator;

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
public class SecurityContextTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    @Override
    public void handle(InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLSecEvent> eventQueue, Integer index) throws XMLSecurityException {

        @SuppressWarnings("unchecked")
        JAXBElement<AbstractSecurityContextTokenType> securityContextTokenTypeJAXBElement =
                ((JAXBElement<AbstractSecurityContextTokenType>) parseStructure(eventQueue, index, securityProperties));
        final AbstractSecurityContextTokenType securityContextTokenType = securityContextTokenTypeJAXBElement.getValue();
        if (securityContextTokenType.getId() == null) {
            securityContextTokenType.setId(IDGenerator.generateID(null));
        }

        final String identifier = (String) XMLSecurityUtils.getQNameType(securityContextTokenType.getAny(),
                new QName(securityContextTokenTypeJAXBElement.getName().getNamespaceURI(), WSSConstants.TAG_wsc0502_Identifier.getLocalPart()));

        final List<QName> elementPath = getElementPath(eventQueue);
        final XMLSecEvent responsibleXMLSecStartXMLEvent = getResponsibleStartXMLEvent(eventQueue, index);

        final AbstractInboundSecurityToken securityContextToken =
                new AbstractInboundSecurityToken(
                        (WSSecurityContext) inputProcessorChain.getSecurityContext(),
                        securityProperties.getCallbackHandler(), securityContextTokenType.getId(), null) {

                    @Override
                    public boolean isAsymmetric() {
                        return false;
                    }

                    @Override
                    public Key getKey(String algorithmURI, XMLSecurityConstants.KeyUsage keyUsage,
                                      String correlationID) throws XMLSecurityException {

                        Key key = getSecretKey().get(algorithmURI);
                        if (key != null) {
                            return key;
                        }

                        String algo = JCEAlgorithmMapper.translateURItoJCEID(algorithmURI);
                        WSPasswordCallback passwordCallback = new WSPasswordCallback(identifier, WSPasswordCallback.Usage.SECURITY_CONTEXT_TOKEN);
                        WSSUtils.doSecretKeyCallback(securityProperties.getCallbackHandler(), passwordCallback, null);
                        if (passwordCallback.getKey() == null) {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noKey", securityContextTokenType.getId());
                        }
                        key = new SecretKeySpec(passwordCallback.getKey(), algo);
                        setSecretKey(algorithmURI, key);
                        return key;
                    }

                    @Override
                    public WSSConstants.TokenType getTokenType() {
                        //todo and set externalUriRef
                        return WSSConstants.SecurityContextToken;
                    }
                };

        securityContextToken.setElementPath(elementPath);
        securityContextToken.setXMLSecEvent(responsibleXMLSecStartXMLEvent);

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            @Override
            public SecurityToken getSecurityToken() throws WSSecurityException {
                return securityContextToken;
            }

            @Override
            public String getId() {
                return securityContextTokenType.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(securityContextTokenType.getId(), securityTokenProvider);

        //fire a tokenSecurityEvent
        SecurityContextTokenSecurityEvent securityContextTokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        securityContextTokenSecurityEvent.setSecurityToken((SecurityToken) securityTokenProvider.getSecurityToken());
        securityContextTokenSecurityEvent.setCorrelationID(securityContextTokenType.getId());
        ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(securityContextTokenSecurityEvent);

        //also register a SecurityProvider with the identifier. @see SecurityContexTest#testSCTKDKTSignAbsolute
        SecurityTokenProvider securityTokenProviderDirectReference = new SecurityTokenProvider() {

            @Override
            public SecurityToken getSecurityToken() throws WSSecurityException {
                return securityContextToken;
            }

            @Override
            public String getId() {
                return identifier;
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(identifier, securityTokenProviderDirectReference);
    }
}
