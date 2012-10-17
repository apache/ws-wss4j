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

import org.apache.ws.security.binding.wss10.KeyIdentifierType;
import org.apache.ws.security.binding.wss10.SecurityTokenReferenceType;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.ws.security.stax.ext.WSSSecurityProperties;
import org.apache.ws.security.stax.ext.WSSUtils;
import org.apache.ws.security.stax.ext.WSSecurityContext;
import org.apache.ws.security.stax.impl.securityToken.SecurityTokenReference;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.ext.*;
import org.apache.xml.security.stax.ext.stax.XMLSecEndElement;
import org.apache.xml.security.stax.ext.stax.XMLSecEvent;
import org.apache.xml.security.stax.ext.stax.XMLSecStartElement;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamConstants;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;

/**
 * Processor for the SecurityTokenReference XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityTokenReferenceInputHandler extends AbstractInputSecurityHeaderHandler {

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLSecEvent> eventQueue, Integer index) throws XMLSecurityException {

        @SuppressWarnings("unchecked")
        final SecurityTokenReferenceType securityTokenReferenceType =
                ((JAXBElement<SecurityTokenReferenceType>) parseStructure(eventQueue, index, securityProperties)).getValue();

        final KeyIdentifierType keyIdentifierType = XMLSecurityUtils.getQNameType(
                securityTokenReferenceType.getAny(), WSSConstants.TAG_wsse_KeyIdentifier);
        if (keyIdentifierType != null) {
            if (WSSConstants.NS_SAML10_TYPE.equals(keyIdentifierType.getValueType())) {
                InternalSecurityTokenReferenceInputProcessor internalSecurityTokenReferenceInputHandler
                        = new InternalSecurityTokenReferenceInputProcessor(
                        securityTokenReferenceType.getId(), WSSConstants.ATT_NULL_AssertionID,
                        keyIdentifierType.getValue().trim(), (WSSSecurityProperties) securityProperties);
                inputProcessorChain.addProcessor(internalSecurityTokenReferenceInputHandler);
            } else if (WSSConstants.NS_SAML20_TYPE.equals(keyIdentifierType.getValueType())) {
                InternalSecurityTokenReferenceInputProcessor internalSecurityTokenReferenceInputHandler
                        = new InternalSecurityTokenReferenceInputProcessor(
                        securityTokenReferenceType.getId(), WSSConstants.ATT_NULL_ID,
                        keyIdentifierType.getValue().trim(), (WSSSecurityProperties) securityProperties);
                inputProcessorChain.addProcessor(internalSecurityTokenReferenceInputHandler);
            }
        }
    }

    class InternalSecurityTokenReferenceInputProcessor extends AbstractInputProcessor {

        private final String securityTokenReferenceId;
        private final QName attribute;
        private final String attributeValue;
        private boolean refFound = false;
        private boolean end = false;
        private QName startElementName;
        private int startElementLevel;

        private final ArrayDeque<XMLSecEvent> xmlSecEventList = new ArrayDeque<XMLSecEvent>();

        InternalSecurityTokenReferenceInputProcessor(String securityTokenReferenceId, QName attribute,
                                                     String attributeValue, WSSSecurityProperties securityProperties) {
            super(securityProperties);
            this.securityTokenReferenceId = securityTokenReferenceId;
            this.attribute = attribute;
            this.attributeValue = attributeValue;
        }

        @Override
        public XMLSecEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain)
                throws XMLStreamException, XMLSecurityException {
            return inputProcessorChain.processHeaderEvent();
        }

        @Override
        public XMLSecEvent processNextEvent(final InputProcessorChain inputProcessorChain)
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

                        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

                            private SecurityToken securityToken = null;

                            @Override
                            public SecurityToken getSecurityToken() throws XMLSecurityException {
                                if (this.securityToken != null) {
                                    return this.securityToken;
                                }

                                SecurityTokenProvider securityTokenProvider =
                                        inputProcessorChain.getSecurityContext().getSecurityTokenProvider(attributeValue);
                                SecurityToken securityToken = securityTokenProvider.getSecurityToken();
                                return this.securityToken = new SecurityTokenReference(
                                        securityToken,
                                        xmlSecEventList,
                                        (WSSecurityContext) inputProcessorChain.getSecurityContext(),
                                        securityTokenReferenceId,
                                        WSSConstants.WSSKeyIdentifierType.SECURITY_TOKEN_REFERENCE);
                            }

                            @Override
                            public String getId() {
                                return securityTokenReferenceId;
                            }
                        };
                        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(securityTokenReferenceId, securityTokenProvider);

                        return xmlSecEvent;
                    } else if (xmlSecEndElement.getDocumentLevel() == 3
                            && xmlSecEndElement.getName().equals(WSSConstants.TAG_wsse_Security)
                            && WSSUtils.isInSecurityHeader(xmlSecEndElement, ((WSSSecurityProperties) getSecurityProperties()).getActor())) {
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
