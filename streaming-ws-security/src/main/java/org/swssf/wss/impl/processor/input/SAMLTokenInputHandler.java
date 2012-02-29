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

import org.swssf.wss.ext.*;
import org.swssf.wss.impl.saml.SAMLAssertionWrapper;
import org.swssf.wss.impl.saml.SAMLKeyInfo;
import org.swssf.wss.impl.securityToken.SAMLSecurityToken;
import org.swssf.wss.securityEvent.SamlTokenSecurityEvent;
import org.swssf.xmlsec.ext.*;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.events.*;
import java.util.Deque;
import java.util.Iterator;
import java.util.List;

/**
 * Processor for the SAML Assertion XML Structure
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class SAMLTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    private static final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();

    static {
        documentBuilderFactory.setNamespaceAware(true);
    }

    @Override
    public void handle(final InputProcessorChain inputProcessorChain, final XMLSecurityProperties securityProperties,
                       Deque<XMLEvent> eventQueue, Integer index) throws XMLSecurityException {

        final Document samlTokenDocument = (Document) parseStructure(eventQueue, index);

        final SAMLAssertionWrapper samlAssertionWrapper = new SAMLAssertionWrapper(samlTokenDocument.getDocumentElement());

        if (samlAssertionWrapper.isSigned()) {
            SAMLKeyInfo samlIssuerKeyInfo = samlAssertionWrapper.verifySignature((WSSSecurityProperties) securityProperties);
            // Verify trust on the signature
            samlAssertionWrapper.verifySignedAssertion(samlIssuerKeyInfo, (WSSSecurityProperties) securityProperties);
        }
        // Parse the HOK subject if it exists
        final SAMLKeyInfo samlSubjectKeyInfo = samlAssertionWrapper.parseHOKSubject((WSSSecurityProperties) securityProperties);

        if (logger.isDebugEnabled()) {
            logger.debug("SAML Assertion issuer " + samlAssertionWrapper.getIssuerString());
        }

        final List<QName> elementPath = getElementPath(inputProcessorChain.getDocumentContext(), eventQueue);

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private WSSecurityToken securityToken = null;

            @Override
            public SecurityToken getSecurityToken() throws XMLSecurityException {
                if (this.securityToken != null) {
                    return this.securityToken;
                }

                this.securityToken = new SAMLSecurityToken(samlAssertionWrapper.getSAMLVersion(), samlSubjectKeyInfo,
                        samlAssertionWrapper.getIssuerString(),
                        (WSSecurityContext) inputProcessorChain.getSecurityContext(), securityProperties.getSignatureVerificationCrypto(),
                        securityProperties.getCallbackHandler(), samlAssertionWrapper.getId(), null);

                this.securityToken.setElementPath(elementPath);
                return this.securityToken;
            }

            @Override
            public String getId() {
                return samlAssertionWrapper.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(samlAssertionWrapper.getId(), securityTokenProvider);

        //fire a tokenSecurityEvent
        SamlTokenSecurityEvent samlTokenSecurityEvent = new SamlTokenSecurityEvent();
        samlTokenSecurityEvent.setSecurityToken(securityTokenProvider.getSecurityToken());
        ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(samlTokenSecurityEvent);
    }

    @SuppressWarnings("unchecked")
    @Override
    protected <T> T parseStructure(Deque<XMLEvent> eventDeque, int index) throws XMLSecurityException {
        Document document = null;
        try {
            document = documentBuilderFactory.newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, e);
        }

        Iterator<XMLEvent> xmlEventIterator = eventDeque.descendingIterator();
        int curIdx = 0;
        while (curIdx++ < index) {
            xmlEventIterator.next();
        }

        Node currentNode = document;
        while (xmlEventIterator.hasNext()) {
            XMLEvent next = xmlEventIterator.next();
            currentNode = parseXMLEvent(next, currentNode, document);
        }
        return (T) document;
    }

    //todo custom SAML unmarshaller directly to XMLObject?
    public Node parseXMLEvent(XMLEvent xmlEvent, Node currentNode, Document document) throws WSSecurityException {
        switch (xmlEvent.getEventType()) {
            case XMLEvent.START_ELEMENT:
                StartElement startElement = xmlEvent.asStartElement();
                Element element = document.createElementNS(startElement.getName().getNamespaceURI(), startElement.getName().getLocalPart());
                if (startElement.getName().getPrefix() != null && !"".equals(startElement.getName().getPrefix())) {
                    element.setPrefix(startElement.getName().getPrefix());
                }
                currentNode = currentNode.appendChild(element);
                @SuppressWarnings("unchecked")
                Iterator<Namespace> namespaceIterator = startElement.getNamespaces();
                while (namespaceIterator.hasNext()) {
                    Namespace next = namespaceIterator.next();
                    parseXMLEvent(next, currentNode, document);
                }
                @SuppressWarnings("unchecked")
                Iterator<Attribute> attributesIterator = startElement.getAttributes();
                while (attributesIterator.hasNext()) {
                    Attribute next = attributesIterator.next();
                    parseXMLEvent(next, currentNode, document);
                }
                break;
            case XMLEvent.END_ELEMENT:
                if (currentNode.getParentNode() != null) {
                    currentNode = currentNode.getParentNode();
                }
                break;
            case XMLEvent.PROCESSING_INSTRUCTION:
                Node piNode = document.createProcessingInstruction(
                        ((ProcessingInstruction) xmlEvent).getTarget(),
                        ((ProcessingInstruction) xmlEvent).getTarget()
                );
                currentNode.appendChild(piNode);
                break;
            case XMLEvent.CHARACTERS:
                Node characterNode = document.createTextNode(xmlEvent.asCharacters().getData());
                currentNode.appendChild(characterNode);
                break;
            case XMLEvent.COMMENT:
                Node commentNode = document.createComment(((Comment) xmlEvent).getText());
                currentNode.appendChild(commentNode);
                break;
            case XMLEvent.START_DOCUMENT:
                break;
            case XMLEvent.END_DOCUMENT:
                return currentNode;
            case XMLEvent.ATTRIBUTE:
                Attr attributeNode = document.createAttributeNS(
                        ((Attribute) xmlEvent).getName().getNamespaceURI(), ((Attribute) xmlEvent).getName().getLocalPart()
                );
                attributeNode.setPrefix(((Attribute) xmlEvent).getName().getPrefix());
                attributeNode.setValue(((Attribute) xmlEvent).getValue());
                ((Element) currentNode).setAttributeNodeNS(attributeNode);
                break;
            case XMLEvent.DTD:
                //todo?:
                /*
                Node dtdNode = document.getDoctype().getEntities()
                ((DTD)xmlEvent).getDocumentTypeDeclaration():
                ((DTD)xmlEvent).getEntities()
                */
                break;
            case XMLEvent.NAMESPACE:
                Namespace namespace = (Namespace) xmlEvent;
                Attr namespaceNode;
                if ("".equals(namespace.getPrefix())) {
                    namespaceNode = document.createAttributeNS(WSSConstants.NS_XML, "xmlns");
                } else {
                    namespaceNode = document.createAttributeNS(WSSConstants.NS_XML, "xmlns:" + namespace.getPrefix());
                }
                namespaceNode.setValue(namespace.getNamespaceURI());
                ((Element) currentNode).setAttributeNodeNS(namespaceNode);
                break;
            default:
                throw new WSSecurityException("Illegal XMLEvent received: " + xmlEvent.getEventType());
        }
        return currentNode;
    }

}
