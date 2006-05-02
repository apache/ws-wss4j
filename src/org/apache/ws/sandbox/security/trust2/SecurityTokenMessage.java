/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.sandbox.security.trust2;

import org.apache.ws.sandbox.security.trust2.exception.ElementParsingException;
import org.apache.ws.sandbox.security.trust2.exception.EmptyTokenOrReference;
import org.apache.ws.sandbox.security.trust2.exception.TrustException;
import org.apache.axis.utils.DOM2Writer;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSSConfig;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/**
 * @author ddelvecc
 *         <p/>
 *         A base class for WS-Trust messages such as <RequestSecurityToken> and <RequestSecurityTokenResponse>.
 */
public abstract class SecurityTokenMessage {

    protected URI context = null;
    protected URI tokenType = null;
    protected URI keyType;

    protected int keySize;
    protected URI signatureAlgorithm;
    protected SecurityTokenOrReference encryption;
    protected SecurityTokenOrReference proofEncryption;
    protected Lifetime lifetime = null;

    protected ArrayList customElements = new ArrayList();

    protected Element element;
    protected Document doc;

    /**
     * Constructs a SecurityTokenMessage object from an existing element.
     *
     * @param element
     */
    public SecurityTokenMessage(Element element) throws ElementParsingException {
        if (element != null) {
            this.doc = element.getOwnerDocument();
            initialize(element);
        }
    }

    public SecurityTokenMessage(Element element, Document doc) throws ElementParsingException {
        if (element != null) {
            this.doc = doc;
            initialize(element);
        }
    }

    private void initialize(Element element) throws ElementParsingException {
        try {
            Attr context = element.getAttributeNodeNS(TrustConstants.WST_NS, TrustConstants.CONTEXT_ATTR);

            if (context != null)
                setContext(new URI(context.getValue()));

            NodeList childNodes = element.getChildNodes();
            if (childNodes != null) {
                for (int i = 0; i < childNodes.getLength(); i++) {
                    Node currentNode = childNodes.item(i);
                    if (!TrustConstants.WST_NS.equals(currentNode.getNamespaceURI())) {
                        if (currentNode instanceof Element)
                            addCustomElement((Element) currentNode);
                        continue;
                    } else if (currentNode.getLocalName().equals(TrustConstants.TOKEN_TYPE)) {
                        String textContent = getTextContent(currentNode);
                        if (textContent != null && !textContent.equals(""))
                            setTokenType(new URI(textContent));
                    } else if (currentNode.getLocalName().equals(TrustConstants.LIFETIME) ||
                            (TrustConstants.MS_COMPATIBLE_LIFETIMES && currentNode.getLocalName().equals(TrustConstants.LIFETIME_MS))) {

                        lifetime = new Lifetime(WSSConfig.getDefaultWSConfig(), doc, (Element) currentNode);
                    } else {
                        if (currentNode instanceof Element)
                            addCustomElement((Element) currentNode);
                    }
                }
            }
        } catch (URISyntaxException e) {
            throw new ElementParsingException("URISyntaxException while creating SecurityTokenMessage from XML element: " + e.getMessage());
        } catch (WSSecurityException e) {
            throw new ElementParsingException("WSSecurityException while creating SecurityTokenMessage from XML element: " + e.getMessage());
        }
    }

    public SecurityTokenMessage(Document doc) {
        this.doc = doc;
    }

    public void setDocument(Document doc) {
        this.doc = doc;
    }

    public Document getDocument() {
        return doc;
    }

    public void setContext(URI context) {
        this.context = context;
    }

    public URI getContext() {
        return context;
    }

    public void setTokenType(URI tokenType) {
        this.tokenType = tokenType;
    }

    public URI getTokenType() {
        return tokenType;
    }

    public void addCustomElement(Element element) {
        customElements.add(element);
    }

    public Element addCustomElement(String tagName) {
        Element element = doc.createElement(tagName);
        addCustomElement(element);
        return element;
    }

    public Element addCustomElementNS(String namespaceUri, String qualifiedName) {
        Element element = doc.createElementNS(namespaceUri, qualifiedName);
        addCustomElement(element);
        return element;
    }

    public List getCustomElements() {
        return customElements;
    }

    public Element getCustomElement(String namespaceUri, String localName) {
        Element currentElement;
        for (Iterator itr = customElements.iterator(); itr.hasNext();) {
            currentElement = (Element) itr.next();
            String elementNs = currentElement.getNamespaceURI();
            if ((namespaceUri == null && elementNs == null) || (namespaceUri != null && namespaceUri.equals(elementNs))) {
                String elementLocalName = currentElement.getLocalName();
                if ((localName == null && elementLocalName == null) || (localName != null && localName.equals(elementLocalName)))
                    return currentElement;
            }
        }
        return null;
    }

    public void setLifetime(Lifetime lifetime) {
        this.lifetime = lifetime;
    }

    public Lifetime getLifetime() {
        return lifetime;
    }

    public abstract Element getElement() throws TrustException;

    protected Element getElement(String tagName) throws TrustException {
        element = doc.createElementNS(TrustConstants.WST_NS, tagName);
        if (context != null) {
            element.setAttributeNS(TrustConstants.WST_NS, TrustConstants.WST_PREFIX + TrustConstants.CONTEXT_ATTR, context.toString());
        }

        if (tokenType != null) {
            Element tokenTypeElement = doc.createElementNS(TrustConstants.WST_NS, TrustConstants.WST_PREFIX + TrustConstants.TOKEN_TYPE);
            setTextContent(tokenTypeElement, tokenType.toString());
            element.appendChild(tokenTypeElement);
        }

        for (Iterator itr = customElements.iterator(); itr.hasNext();) {
            element.appendChild((Element) itr.next());
        }

        if (lifetime != null) {
            element.appendChild(lifetime.getElement());
        }

        return element;
    }

    protected Element createTokenOrReferenceElement(String enclosingTagName, SecurityTokenOrReference token) throws TrustException {
        Element element = doc.createElementNS(TrustConstants.WST_NS, enclosingTagName);
        Element tokenElement = token.getElement();
        if (tokenElement == null)
            throw new EmptyTokenOrReference("SecurityTokenOrReference specified does not contain " +
                    "a security token element or reference element.");
        element.appendChild(tokenElement);
        return element;
    }

    /**
     * Adds a text child node to the given element.
     *
     * @param element The element to add text to
     * @param string  The text string to add
     */
    protected void setTextContent(Element element, String string) {
        Node textNode = doc.createTextNode(string);
        element.appendChild(textNode);
    }

    protected String getTextContent(Node currentNode) {
        NodeList nodes = currentNode.getChildNodes();
        for (int j = 0; j < nodes.getLength(); j++) {
            if (nodes.item(j).getNodeValue() != null)
                return nodes.item(j).getNodeValue();
        }
        return null;
    }

    protected Element getFirstNonBlankChildAsElement(Node currentNode) {
        NodeList nodes = currentNode.getChildNodes();
        for (int j = 0; j < nodes.getLength(); j++) {
            if (nodes.item(j).getLocalName() != null)
                return (Element) nodes.item(j);
        }
        return null;
    }

    public String toString() {
        try {
            return DOM2Writer.nodeToString(getElement(), true);
        } catch (TrustException e) {
            return "TrustException when trying to convert to String: " + e.getMessage();
        }
    }
}
