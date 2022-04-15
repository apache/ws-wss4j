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

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

import jakarta.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;

import org.apache.wss4j.binding.wss10.KeyIdentifierType;
import org.apache.wss4j.binding.wss10.ReferenceType;
import org.apache.wss4j.binding.wss10.SecurityTokenReferenceType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.impl.securityToken.SecurityTokenReferenceImpl;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.utils.WSSUtils;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.AbstractInputProcessor;
import org.apache.xml.security.stax.ext.AbstractInputSecurityHeaderHandler;
import org.apache.xml.security.stax.ext.InputProcessorChain;
import org.apache.xml.security.stax.ext.XMLSecurityProperties;
import org.apache.xml.security.stax.ext.XMLSecurityUtils;
import org.apache.xml.security.stax.ext.stax.XMLSecEndElement;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;
import org.apache.xml.security.stax.securityToken.InboundSecurityToken;
import org.apache.xml.security.stax.securityToken.SecurityTokenProvider;

/**
 * Processor for the SecurityTokenReference XML Structure
 */
public class SecurityTokenReferenceInputHandler extends AbstractInputSecurityHeaderHandler {

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLSecEvent> eventQueue, Integer index) throws XMLSecurityException {

        @SuppressWarnings("unchecked")
        final SecurityTokenReferenceType securityTokenReferenceType =
                ((JAXBElement<SecurityTokenReferenceType>) parseStructure(eventQueue, index, securityProperties)).getValue();

        QName attributeName = null;
        String attributeValue = null;

        final KeyIdentifierType keyIdentifierType = XMLSecurityUtils.getQNameType(
                securityTokenReferenceType.getAny(), WSSConstants.TAG_WSSE_KEY_IDENTIFIER);
        if (keyIdentifierType != null) {
            attributeValue = keyIdentifierType.getValue().trim();
            if (WSSConstants.NS_SAML10_TYPE.equals(keyIdentifierType.getValueType())) {
                attributeName = WSSConstants.ATT_NULL_ASSERTION_ID;
            } else if (WSSConstants.NS_SAML20_TYPE.equals(keyIdentifierType.getValueType())) {
                attributeName = WSSConstants.ATT_NULL_ID;
            }
        }
        final ReferenceType referenceType = XMLSecurityUtils.getQNameType(
                securityTokenReferenceType.getAny(), WSSConstants.TAG_WSSE_REFERENCE);
        if (referenceType != null) {
            attributeValue = WSSUtils.dropReferenceMarker(referenceType.getURI());
            if (WSSConstants.NS_SAML10_TYPE.equals(referenceType.getValueType())) {
                attributeName = WSSConstants.ATT_NULL_ASSERTION_ID;
            } else if (WSSConstants.NS_SAML20_TYPE.equals(referenceType.getValueType())) {
                attributeName = WSSConstants.ATT_NULL_ID;
            }
        }

        if (attributeName != null) {
            InternalSecurityTokenReferenceInputProcessor internalSecurityTokenReferenceInputHandler
                    = new InternalSecurityTokenReferenceInputProcessor(
                    securityTokenReferenceType.getId(), attributeName,
                    attributeValue, (WSSSecurityProperties) securityProperties);
            inputProcessorChain.addProcessor(internalSecurityTokenReferenceInputHandler);
        } else {
            throw new WSSecurityException(WSSecurityException.ErrorCode.UNSUPPORTED_SECURITY_TOKEN);
        }
    }

    static class InternalSecurityTokenReferenceInputProcessor extends AbstractInputProcessor {

        private final String securityTokenReferenceId;
        private final QName attribute;
        private final String attributeValue;
        private boolean refFound = false;
        private boolean end = false;
        private QName startElementName;
        private int startElementLevel;

        private final ArrayDeque<XMLSecEvent> xmlSecEventList = new ArrayDeque<>();

        InternalSecurityTokenReferenceInputProcessor(String securityTokenReferenceId, QName attribute,
                                                     String attributeValue, WSSSecurityProperties securityProperties) {
            super(securityProperties);
            this.securityTokenReferenceId = securityTokenReferenceId;
            this.attribute = attribute;
            this.attributeValue = attributeValue;
        }

        @Override
        public XMLSecEvent processHeaderEvent(InputProcessorChain inputProcessorChain)
                throws XMLStreamException, XMLSecurityException {
            return inputProcessorChain.processHeaderEvent();
        }

        @Override
        public XMLSecEvent processEvent(final InputProcessorChain inputProcessorChain)
                throws XMLStreamException, XMLSecurityException {
            XMLSecEvent xmlSecEvent = inputProcessorChain.processEvent();
            switch (xmlSecEvent.getEventType()) {
                case XMLStreamConstants.START_ELEMENT:
                    XMLSecStartElement xmlSecStartElement = xmlSecEvent.asStartElement();
                    Attribute attribute = xmlSecStartElement.getAttributeByName(this.attribute);
                    if (attribute != null && this.attributeValue.equals(attribute.getValue())) {
                        if (refFound) {
                            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "duplicateId");
                        }
                        refFound = true;
                        startElementName = xmlSecStartElement.getName();
                        List<QName> elementPath = xmlSecStartElement.getElementPath();
                        startElementLevel = elementPath.size();
                    }
                    break;
                case XMLStreamConstants.END_ELEMENT:
                    XMLSecEndElement xmlSecEndElement = xmlSecEvent.asEndElement();
                    if (xmlSecEndElement.getName().equals(startElementName)
                            && xmlSecEndElement.getDocumentLevel() == startElementLevel) {
                        end = true;
                        xmlSecEventList.push(xmlSecEvent);

                        SecurityTokenProvider<InboundSecurityToken> securityTokenProvider =
                                new SecurityTokenProvider<InboundSecurityToken>() {

                            private InboundSecurityToken securityToken;

                            @Override
                            public InboundSecurityToken getSecurityToken() throws XMLSecurityException {
                                if (this.securityToken != null) {
                                    return this.securityToken;
                                }

                                SecurityTokenProvider<? extends InboundSecurityToken> securityTokenProvider =
                                        inputProcessorChain.getSecurityContext().getSecurityTokenProvider(attributeValue);
                                return this.securityToken = new SecurityTokenReferenceImpl(
                                        securityTokenProvider.getSecurityToken(),
                                        xmlSecEventList,
                                        (WSInboundSecurityContext) inputProcessorChain.getSecurityContext(),
                                        securityTokenReferenceId,
                                        WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
                            }

                            @Override
                            public String getId() {
                                return securityTokenReferenceId;
                            }
                        };
                        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(securityTokenReferenceId,
                                                                                               securityTokenProvider);

                        return xmlSecEvent;
                    } else if (xmlSecEndElement.getDocumentLevel() == 3
                            && xmlSecEndElement.getName().equals(WSSConstants.TAG_WSSE_SECURITY)
                            && WSSUtils.isInSecurityHeader(xmlSecEndElement,
                                                           ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
                        //we can now remove this processor from the chain
                        inputProcessorChain.removeProcessor(this);
                    }
                    break;
            }
            if (refFound && !end) {
                xmlSecEventList.push(xmlSecEvent);
            }
            return xmlSecEvent;
        }
    }
}
