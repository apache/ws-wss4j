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

package org.apache.ws.security.trust2;

import org.apache.ws.security.trust2.exception.ElementParsingException;
import org.apache.ws.security.trust2.exception.NoRequestType;
import org.apache.ws.security.trust2.exception.TrustException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class RequestSecurityToken extends SecurityTokenMessage {

    protected URI requestType = null;

    protected SecurityTokenOrReference base = null;
    protected List supporting = new ArrayList();

    public RequestSecurityToken(Document doc, URI requestType) {
        super(doc);
        this.requestType = requestType;
    }

    /**
     * Constructs a RequestSecurityToken object from an existing element.
     *
     * @param element
     */
    public RequestSecurityToken(Element element) throws ElementParsingException {
        super(element);
        initialize(element);
    }

    public RequestSecurityToken(Element element, Document document) throws ElementParsingException {
        super(element, document);
        initialize(element);
    }

    private void initialize(Element element) throws ElementParsingException {
        ArrayList elements = (ArrayList) customElements.clone();
        customElements.clear();

        for (int i = 0; i < elements.size(); i++) {
            Element currentNode = (Element) elements.get(i);

            if (!TrustConstants.WST_NS.equals(currentNode.getNamespaceURI())) {
                addCustomElement(currentNode);
                continue;
            } else if (currentNode.getLocalName().equals(TrustConstants.REQUEST_TYPE)) {
                String textContent = getTextContent(currentNode);
                if (textContent != null && !textContent.equals("")) {
                    try {
                        setRequestType(new URI(textContent));
                    } catch (URISyntaxException e) {
                        throw new ElementParsingException("URISyntaxException while creating RequestSecurityToken (RequestType) from XML Element: "
                                + e.getMessage());
                    }
                }
            } else if (currentNode.getLocalName().equals(TrustConstants.BASE)) {
                Element elem = getFirstNonBlankChildAsElement(currentNode);
                if (elem != null)
                    setBase(new SecurityTokenOrReference(elem, doc));
            } else if (currentNode.getLocalName().equals(TrustConstants.SUPPORTING)) {
                NodeList supportingNodes = currentNode.getChildNodes();
                if (supportingNodes != null) {
                    for (int j = 0; j < supportingNodes.getLength(); j++)
                        if (supportingNodes.item(j).getLocalName() != null)
                            addSupporting(new SecurityTokenOrReference((Element) supportingNodes.item(j), doc));
                }
            } else {
                addCustomElement(currentNode);
            }
        }
    }

    public void setRequestType(URI requestType) {
        this.requestType = requestType;
    }

    public URI getRequestType() {
        return requestType;
    }

    public void setBase(SecurityTokenOrReference base) {
        this.base = base;
    }

    public SecurityTokenOrReference getBase() {
        return base;
    }

    public void addSupporting(SecurityTokenOrReference supportingToken) {
        supporting.add(supportingToken);
    }

    public List getSupporting() {
        return supporting;
    }

    public Element getElement() throws TrustException {
        Element wstElement = getElement(TrustConstants.WST_PREFIX + TrustConstants.REQUEST_TAG);

        if (requestType != null) {
            Element requestTypeElement = doc.createElementNS(TrustConstants.WST_NS, TrustConstants.WST_PREFIX + TrustConstants.REQUEST_TYPE);
            setTextContent(requestTypeElement, requestType.toString());
            wstElement.appendChild(requestTypeElement);
        } else {
            throw new NoRequestType("RequestType is a required element that cannot be null.");
        }

        if (base != null) {
            wstElement.appendChild(createTokenOrReferenceElement(TrustConstants.WST_PREFIX + TrustConstants.BASE, base));
        }

        if (!supporting.isEmpty()) {
            Element supportingElement = doc.createElementNS(TrustConstants.WST_NS, TrustConstants.WST_PREFIX + TrustConstants.SUPPORTING);

            for (Iterator itr = supporting.iterator(); itr.hasNext();) {
                SecurityTokenOrReference next = (SecurityTokenOrReference) itr.next();
                supportingElement.appendChild(next.getElement());
            }

            wstElement.appendChild(supportingElement);
        }
        return wstElement;
    }
}
