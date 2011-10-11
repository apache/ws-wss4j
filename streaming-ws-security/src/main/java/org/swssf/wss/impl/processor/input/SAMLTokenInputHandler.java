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

import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.ext.WSSSecurityProperties;
import org.swssf.wss.ext.WSSecurityContext;
import org.swssf.wss.ext.WSSecurityException;
import org.swssf.wss.impl.saml.SAMLAssertionWrapper;
import org.swssf.wss.impl.saml.SAMLKeyInfo;
import org.swssf.wss.impl.securityToken.SecurityTokenFactoryImpl;
import org.swssf.wss.securityEvent.SamlTokenSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.xmlsec.crypto.Crypto;
import org.swssf.xmlsec.ext.*;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.events.*;
import java.util.Deque;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

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

    public SAMLTokenInputHandler(final InputProcessorChain inputProcessorChain, final WSSSecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws XMLSecurityException {

        final SAMLTokenParseable samlTokenParseable = (SAMLTokenParseable) parseStructure(eventQueue, index);

        final SAMLAssertionWrapper samlAssertionWrapper = new SAMLAssertionWrapper(samlTokenParseable.getDocument().getDocumentElement());

        if (samlAssertionWrapper.isSigned()) {
            SAMLKeyInfo samlIssuerKeyInfo = samlAssertionWrapper.verifySignature(securityProperties);
            // Verify trust on the signature
            samlAssertionWrapper.verifySignedAssertion(samlIssuerKeyInfo, securityProperties);
        }
        // Parse the HOK subject if it exists
        final SAMLKeyInfo samlSubjectKeyInfo = samlAssertionWrapper.parseHOKSubject(securityProperties);

        if (logger.isDebugEnabled()) {
            logger.debug("SAML Assertion issuer " + samlAssertionWrapper.getIssuerString());
        }

        SecurityTokenProvider securityTokenProvider = new SecurityTokenProvider() {

            private Map<Crypto, SecurityToken> securityTokens = new HashMap<Crypto, SecurityToken>();

            public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                SecurityToken securityToken = securityTokens.get(crypto);
                if (securityToken != null) {
                    return securityToken;
                }

                securityToken = SecurityTokenFactoryImpl.getSecurityToken(
                        samlAssertionWrapper.getSAMLVersion(), samlSubjectKeyInfo,
                        inputProcessorChain.getSecurityContext(), crypto,
                        securityProperties.getCallbackHandler(), samlAssertionWrapper.getId(), null);
                securityTokens.put(crypto, securityToken);
                return securityToken;
            }

            public String getId() {
                return samlAssertionWrapper.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(samlAssertionWrapper.getId(), securityTokenProvider);

        SamlTokenSecurityEvent samlTokenSecurityEvent = new SamlTokenSecurityEvent(SecurityEvent.Event.SamlToken);
        samlTokenSecurityEvent.setIssuerName(samlAssertionWrapper.getIssuerString());
        samlTokenSecurityEvent.setSamlVersion(samlAssertionWrapper.getSAMLVersion());
        samlTokenSecurityEvent.setSecurityToken(securityTokenProvider.getSecurityToken(null));
        ((WSSecurityContext) inputProcessorChain.getSecurityContext()).registerSecurityEvent(samlTokenSecurityEvent);
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new SAMLTokenParseable(startElement);
    }

    class SAMLTokenParseable implements Parseable {

        private Document document;
        private Node currentNode;

        SAMLTokenParseable(StartElement startElement) {
            try {
                currentNode = document = documentBuilderFactory.newDocumentBuilder().newDocument();
                parseXMLEvent(startElement);
            } catch (ParserConfigurationException e) {
                throw new RuntimeException(e);
            } catch (ParseException e) {
                throw new RuntimeException(e);
            }
        }

        //todo custom SAML unmarshaller directly to XMLObject?
        public boolean parseXMLEvent(XMLEvent xmlEvent) throws ParseException {
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
                        parseXMLEvent(next);
                    }
                    @SuppressWarnings("unchecked")
                    Iterator<Attribute> attributesIterator = startElement.getAttributes();
                    while (attributesIterator.hasNext()) {
                        Attribute next = attributesIterator.next();
                        parseXMLEvent(next);
                    }
                    break;
                case XMLEvent.END_ELEMENT:
                    if (currentNode.getParentNode() != null) {
                        currentNode = currentNode.getParentNode();
                    }
                    break;
                case XMLEvent.PROCESSING_INSTRUCTION:
                    Node piNode = document.createProcessingInstruction(((ProcessingInstruction) xmlEvent).getTarget(), ((ProcessingInstruction) xmlEvent).getTarget());
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
                    return true;
                case XMLEvent.ATTRIBUTE:
                    Attr attributeNode = document.createAttributeNS(((Attribute) xmlEvent).getName().getNamespaceURI(), ((Attribute) xmlEvent).getName().getLocalPart());
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
                    throw new IllegalArgumentException("Illegal XMLEvent received: " + xmlEvent.getEventType());
            }
            return false;
        }

        public void validate() throws ParseException {
        }

        public Document getDocument() {
            return document;
        }
    }
}
