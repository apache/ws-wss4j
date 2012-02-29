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

import org.swssf.binding.wss10.KeyIdentifierType;
import org.swssf.binding.wss10.SecurityTokenReferenceType;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSDocumentContext;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.impl.securityToken.SecurityTokenFactoryImpl;
import org.swssf.xmlsec.ext.*;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.EndElement;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Processor for the SecurityTokenReference XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SecurityTokenReferenceInputHandler extends AbstractInputSecurityHeaderHandler {

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLEvent> eventQueue, Integer index) throws XMLSecurityException {

        @SuppressWarnings("unchecked")
        final SecurityTokenReferenceType securityTokenReferenceType =
                ((JAXBElement<SecurityTokenReferenceType>) parseStructure(eventQueue, index)).getValue();

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

        private String securityTokenReferenceId;
        private QName attribute;
        private String attributeValue;
        private boolean refFound = false;
        private boolean end = false;
        private QName startElementName;
        private int startElementLevel;

        private ArrayDeque<XMLEvent> xmlEventList = new ArrayDeque<XMLEvent>();

        InternalSecurityTokenReferenceInputProcessor(String securityTokenReferenceId, QName attribute,
                                                     String attributeValue, WSSSecurityProperties securityProperties) {
            super(securityProperties);
            this.securityTokenReferenceId = securityTokenReferenceId;
            this.attribute = attribute;
            this.attributeValue = attributeValue;
        }

        @Override
        public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain)
                throws XMLStreamException, XMLSecurityException {
            return inputProcessorChain.processHeaderEvent();
        }

        @Override
        public XMLEvent processNextEvent(final InputProcessorChain inputProcessorChain)
                throws XMLStreamException, XMLSecurityException {
            XMLEvent xmlEvent = inputProcessorChain.processEvent();
            if (xmlEvent.isStartElement()) {
                StartElement startElement = xmlEvent.asStartElement();
                Attribute attribute = startElement.getAttributeByName(this.attribute);
                if (attribute != null && this.attributeValue.equals(attribute.getValue())) {
                    if (refFound) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, "duplicateId");
                    }
                    refFound = true;
                    startElementName = startElement.getName();
                    startElementLevel = inputProcessorChain.getDocumentContext().getDocumentLevel();
                }
            } else if (xmlEvent.isEndElement()) {
                EndElement endElement = xmlEvent.asEndElement();
                if (startElementName != null && endElement.getName().equals(startElementName)
                        && inputProcessorChain.getDocumentContext().getDocumentLevel() == startElementLevel - 1) {
                    end = true;
                    xmlEventList.push(xmlEvent);

                    SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

                        private SecurityToken securityToken = null;

                        public SecurityToken getSecurityToken() throws XMLSecurityException {
                            if (this.securityToken != null) {
                                return this.securityToken;
                            }
                            this.securityToken = SecurityTokenFactoryImpl.getSecurityToken(
                                    attributeValue, xmlEventList, getSecurityProperties().getCallbackHandler(),
                                    inputProcessorChain.getSecurityContext(), securityTokenReferenceId);
                            return this.securityToken;
                        }

                        public String getId() {
                            return securityTokenReferenceId;
                        }
                    };
                    inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(securityTokenReferenceId, securityTokenProvider);

                    return xmlEvent;
                } else if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 1
                        && ((WSSDocumentContext) inputProcessorChain.getDocumentContext()).isInSecurityHeader()) {
                    //we can now remove this processor from the chain
                    inputProcessorChain.removeProcessor(this);
                }
            }
            if (refFound && !end) {
                xmlEventList.push(xmlEvent);
            }
            return xmlEvent;
        }
    }
}
