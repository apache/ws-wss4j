/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.impl.processor.input;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.KeyIdentifierType;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.SecurityTokenReferenceType;
import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.securityToken.SecurityTokenFactory;

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
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class SecurityTokenReferenceInputHandler extends AbstractInputSecurityHeaderHandler {

    public SecurityTokenReferenceInputHandler(InputProcessorChain inputProcessorChain, final SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException {

        final SecurityTokenReferenceType securityTokenReferenceType = (SecurityTokenReferenceType) parseStructure(eventQueue, index);

        if (securityTokenReferenceType.getKeyIdentifierType() != null) {
            KeyIdentifierType keyIdentifierType = securityTokenReferenceType.getKeyIdentifierType();
            if (Constants.NS_SAML10_TYPE.equals(keyIdentifierType.getValueType())) {
                InternalSecurityTokenReferenceInputHandler internalSecurityTokenReferenceInputHandler
                        = new InternalSecurityTokenReferenceInputHandler(securityTokenReferenceType.getId(), Constants.ATT_NULL_AssertionID, keyIdentifierType.getValue().trim(), securityProperties);
                inputProcessorChain.addProcessor(internalSecurityTokenReferenceInputHandler);
            } else if (Constants.NS_SAML20_TYPE.equals(keyIdentifierType.getValueType())) {
                InternalSecurityTokenReferenceInputHandler internalSecurityTokenReferenceInputHandler
                        = new InternalSecurityTokenReferenceInputHandler(securityTokenReferenceType.getId(), Constants.ATT_NULL_ID, keyIdentifierType.getValue().trim(), securityProperties);
                inputProcessorChain.addProcessor(internalSecurityTokenReferenceInputHandler);
            }
        }
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new SecurityTokenReferenceType(startElement);
    }

    class InternalSecurityTokenReferenceInputHandler extends AbstractInputProcessor {

        private String securityTokenReferenceId;
        private QName attribute;
        private String attributeValue;
        private boolean refFound = false;
        private boolean end = false;
        private QName startElementName;
        private int startElementLevel;

        private ArrayDeque<XMLEvent> xmlEventList = new ArrayDeque<XMLEvent>();

        InternalSecurityTokenReferenceInputHandler(String securityTokenReferenceId, QName attribute, String attributeValue, SecurityProperties securityProperties) {
            super(securityProperties);
            this.securityTokenReferenceId = securityTokenReferenceId;
            this.attribute = attribute;
            this.attributeValue = attributeValue;
        }

        @Override
        public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
            return inputProcessorChain.processHeaderEvent();
        }

        @Override
        public XMLEvent processNextEvent(final InputProcessorChain inputProcessorChain) throws XMLStreamException, WSSecurityException {
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
                if (startElementName != null && endElement.getName().equals(startElementName) && inputProcessorChain.getDocumentContext().getDocumentLevel() == startElementLevel - 1) {
                    end = true;
                    xmlEventList.push(xmlEvent);

                    SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {
                        public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                            return SecurityTokenFactory.newInstance().getSecurityToken(
                                    attributeValue, xmlEventList, crypto, getSecurityProperties().getCallbackHandler(),
                                    inputProcessorChain.getSecurityContext(), securityTokenReferenceId, this);
                        }

                        public String getId() {
                            return securityTokenReferenceId;
                        }
                    };
                    inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(securityTokenReferenceId, securityTokenProvider);

                    return xmlEvent;
                } else if (inputProcessorChain.getDocumentContext().getDocumentLevel() == 1
                        && inputProcessorChain.getDocumentContext().isInSecurityHeader()) {
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
