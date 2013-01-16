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
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.ext.WSSecurityContext;
import org.apache.ws.security.stax.securityEvent.SecurityContextTokenSecurityEvent;
import org.apache.ws.security.stax.validate.SecurityContextTokenValidator;
import org.apache.ws.security.stax.validate.SecurityContextTokenValidatorImpl;
import org.apache.ws.security.stax.validate.TokenContext;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.impl.util.IDGenerator;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
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

        final QName elementName = new QName(securityContextTokenTypeJAXBElement.getName().getNamespaceURI(),
                WSSConstants.TAG_wsc0502_Identifier.getLocalPart());
        final String identifier = (String) XMLSecurityUtils.getQNameType(securityContextTokenType.getAny(),
                elementName);

        final WSSecurityContext wsSecurityContext = (WSSecurityContext) inputProcessorChain.getSecurityContext();
        final WSSSecurityProperties wssSecurityProperties = (WSSSecurityProperties) securityProperties;
        final List<XMLSecEvent> xmlSecEvents = getResponsibleXMLSecEvents(eventQueue, index);
        final List<QName> elementPath = getElementPath(eventQueue);

        final TokenContext tokenContext = new TokenContext(wssSecurityProperties, wsSecurityContext, xmlSecEvents, elementPath);

        SecurityContextTokenValidator securityContextTokenValidator = wssSecurityProperties.getValidator(elementName);
        if (securityContextTokenValidator == null) {
            securityContextTokenValidator = new SecurityContextTokenValidatorImpl();
        }
        final SecurityToken securityContextToken =
                securityContextTokenValidator.validate(securityContextTokenType, identifier, tokenContext);

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            @SuppressWarnings("unchecked")
            @Override
            public SecurityToken getSecurityToken() throws XMLSecurityException {
                return securityContextToken;
            }

            @Override
            public String getId() {
                return securityContextTokenType.getId();
            }
        };
        wsSecurityContext.registerSecurityTokenProvider(securityContextTokenType.getId(), securityTokenProvider);

        //also register a SecurityProvider with the identifier. @see SecurityContexTest#testSCTKDKTSignAbsolute
        SecurityTokenProvider securityTokenProviderDirectReference = new SecurityTokenProvider() {

            @SuppressWarnings("unchecked")
            @Override
            public SecurityToken getSecurityToken() throws XMLSecurityException {
                return securityContextToken;
            }

            @Override
            public String getId() {
                return identifier;
            }
        };
        wsSecurityContext.registerSecurityTokenProvider(identifier, securityTokenProviderDirectReference);

        //fire a tokenSecurityEvent
        SecurityContextTokenSecurityEvent securityContextTokenSecurityEvent = new SecurityContextTokenSecurityEvent();
        securityContextTokenSecurityEvent.setSecurityToken((SecurityToken) securityTokenProvider.getSecurityToken());
        securityContextTokenSecurityEvent.setCorrelationID(securityContextTokenType.getId());
        wsSecurityContext.registerSecurityEvent(securityContextTokenSecurityEvent);
    }
}
