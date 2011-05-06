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

import org.swssf.crypto.Crypto;
import org.swssf.ext.*;
import org.swssf.impl.saml.SAMLAssertionWrapper;
import org.swssf.impl.saml.SAMLKeyInfo;
import org.swssf.impl.securityToken.SecurityTokenFactory;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.events.*;
import java.util.Deque;
import java.util.Iterator;

/**
 * Processor for the SAML Assertion XML Structure
 *
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class SAMLTokenInputHandler extends AbstractInputSecurityHeaderHandler {

    private static final DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();

    static {
        documentBuilderFactory.setNamespaceAware(true);
    }

    public SAMLTokenInputHandler(InputProcessorChain inputProcessorChain, final SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException {

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
            public SecurityToken getSecurityToken(Crypto crypto) throws WSSecurityException {
                return SecurityTokenFactory.newInstance().getSecurityToken(samlSubjectKeyInfo, crypto, securityProperties.getCallbackHandler());
            }

            public String getId() {
                return samlAssertionWrapper.getId();
            }
        };
        inputProcessorChain.getSecurityContext().registerSecurityTokenProvider(samlAssertionWrapper.getId(), securityTokenProvider);
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
                    Iterator<Namespace> namespaceIterator = startElement.getNamespaces();
                    while (namespaceIterator.hasNext()) {
                        Namespace next = namespaceIterator.next();
                        parseXMLEvent(next);
                    }
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
                        namespaceNode = document.createAttributeNS(Constants.NS_XML, "xmlns");
                    } else {
                        namespaceNode = document.createAttributeNS(Constants.NS_XML, "xmlns:" + namespace.getPrefix());
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
