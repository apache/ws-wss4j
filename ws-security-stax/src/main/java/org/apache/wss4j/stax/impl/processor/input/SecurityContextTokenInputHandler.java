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

import org.apache.wss4j.binding.wssc.AbstractSecurityContextTokenType;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityEvent.SecurityContextTokenSecurityEvent;
import org.apache.wss4j.stax.validate.SecurityContextTokenValidator;
import org.apache.wss4j.stax.validate.SecurityContextTokenValidatorImpl;
import org.apache.wss4j.stax.validate.TokenContext;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

import jakarta.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import java.util.Deque;
import java.util.List;

/**
 * Processor for the SecurityContextToken XML Structure
 */
public class SecurityContextTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    @Override
    public void handle(InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLSecEvent> eventQueue, Integer index) throws XMLSecurityException {

        JAXBElement<AbstractSecurityContextTokenType> securityContextTokenTypeJAXBElement =
                parseStructure(eventQueue, index, securityProperties);
        final AbstractSecurityContextTokenType securityContextTokenType = securityContextTokenTypeJAXBElement.getValue();
        if (securityContextTokenType.getId() == null) {
            securityContextTokenType.setId(IDGenerator.generateID(null));
        }

        final QName identifierElementName = new QName(securityContextTokenTypeJAXBElement.getName().getNamespaceURI(),
                WSSConstants.TAG_WSC0502_IDENTIFIER.getLocalPart());
        final String identifier = XMLSecurityUtils.getQNameType(securityContextTokenType.getAny(),
                identifierElementName);

        final WSInboundSecurityContext wsInboundSecurityContext =
            (WSInboundSecurityContext) inputProcessorChain.getSecurityContext();
        final WSSSecurityProperties wssSecurityProperties = (WSSSecurityProperties) securityProperties;
        final List<XMLSecEvent> xmlSecEvents = getResponsibleXMLSecEvents(eventQueue, index);
        final List<QName> elementPath = getElementPath(eventQueue);

        final TokenContext tokenContext =
            new TokenContext(wssSecurityProperties, wsInboundSecurityContext, xmlSecEvents, elementPath);

        final QName elementName = securityContextTokenTypeJAXBElement.getName();
        SecurityContextTokenValidator securityContextTokenValidator = wssSecurityProperties.getValidator(elementName);
        if (securityContextTokenValidator == null) {
            securityContextTokenValidator = new SecurityContextTokenValidatorImpl();
        }
        final InboundSecurityToken securityContextToken =
                securityContextTokenValidator.validate(securityContextTokenType, identifier, tokenContext);

        SecurityTokenProvider<InboundSecurityToken> securityTokenProvider =
                new SecurityTokenProvider<InboundSecurityToken>() {

            @Override
            public InboundSecurityToken getSecurityToken() throws XMLSecurityException {
                return securityContextToken;
            }

            @Override
            public String getId() {
                return securityContextTokenType.getId();
            }
        };
        wsInboundSecurityContext.registerSecurityTokenProvider(securityContextTokenType.getId(), securityTokenProvider);

        //also register a SecurityProvider with the identifier. @see SecurityContexTest#testSCTKDKTSignAbsolute
        SecurityTokenProvider<InboundSecurityToken> securityTokenProviderDirectReference =
                new SecurityTokenProvider<InboundSecurityToken>() {

            @Override
            public InboundSecurityToken getSecurityToken() throws XMLSecurityException {
                return securityContextToken;
            }

            @Override
            public String getId() {
                return identifier;
            }
        };
        wsInboundSecurityContext.registerSecurityTokenProvider(identifier, securityTokenProviderDirectReference);

        //fire a tokenSecurityEvent
        SecurityContextTokenSecurityEvent securityEvent = createTokenSecurityEvent(securityContextTokenType, securityTokenProvider);
        wsInboundSecurityContext.registerSecurityEvent(securityEvent);
    }

    private SecurityContextTokenSecurityEvent createTokenSecurityEvent(AbstractSecurityContextTokenType securityContextTokenType,
                                                                       SecurityTokenProvider<InboundSecurityToken> securityTokenProvider)
            throws XMLSecurityException {
        SecurityContextTokenSecurityEvent securityContextTokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        securityContextTokenSecurityEvent.setSecurityToken(securityTokenProvider.getSecurityToken());
        securityContextTokenSecurityEvent.setCorrelationID(securityContextTokenType.getId());
        return securityContextTokenSecurityEvent;
    }

}
