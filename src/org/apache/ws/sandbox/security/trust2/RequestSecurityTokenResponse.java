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
import org.apache.ws.security.trust2.exception.NoTokenInResponse;
import org.apache.ws.security.trust2.exception.TrustException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.ArrayList;

/**
 * @author ddelvecc
 *         <p/>
 *         Represents the WS-Trust <RequestSecurityTokenResponse> message which includes the requested token.
 */
public class RequestSecurityTokenResponse extends SecurityTokenMessage {

    protected SecurityTokenOrReference requestedSecurityToken = null;
    protected SecurityTokenOrReference requestedProofToken = null;

    public RequestSecurityTokenResponse(Document doc) {
        super(doc);
    }

    public RequestSecurityTokenResponse(Document doc, SecurityTokenOrReference requestedSecurityToken) {
        super(doc);
        this.requestedSecurityToken = requestedSecurityToken;
    }

    /**
     * Constructs a RequestSecurityToken object from an existing element.
     *
     * @param element
     */
    public RequestSecurityTokenResponse(Element element) throws ElementParsingException {
        super(element);
        initialize();
    }

    public RequestSecurityTokenResponse(Element element, Document document) throws ElementParsingException {
        super(element, document);
        initialize();
    }

    private void initialize() throws ElementParsingException {
        ArrayList elements = (ArrayList) customElements.clone();
        customElements.clear();

        for (int i = 0; i < elements.size(); i++) {
            Element currentNode = (Element) elements.get(i);

            if (!TrustConstants.WST_NS.equals(currentNode.getNamespaceURI())) {
                addCustomElement(currentNode);
                continue;
            } else if (currentNode.getLocalName().equals(TrustConstants.REQUESTED_TOKEN)) {
                Element elem = getFirstNonBlankChildAsElement(currentNode);
                if (elem != null)
                    setRequestedSecurityToken(new SecurityTokenOrReference(elem, doc));
            } else if (currentNode.getLocalName().equals(TrustConstants.REQUESTED_PROOF)) {
                Element elem = getFirstNonBlankChildAsElement(currentNode);
                if (elem != null)
                    setRequestedProofToken(new SecurityTokenOrReference(elem, doc));
            } else
                addCustomElement(currentNode);
        }
    }

    public SecurityTokenOrReference getRequestedSecurityToken() {
        return requestedSecurityToken;
    }

    public void setRequestedSecurityToken(SecurityTokenOrReference requestedToken) {
        this.requestedSecurityToken = requestedToken;
    }

    public SecurityTokenOrReference getRequestedProofToken() {
        return requestedProofToken;
    }

    public void setRequestedProofToken(SecurityTokenOrReference requestedProofToken) {
        this.requestedProofToken = requestedProofToken;
    }

    public Element getElement() throws TrustException {
        Element wstElement = getElement(TrustConstants.WST_PREFIX + TrustConstants.RESPONSE_TAG);

        if ((requestedSecurityToken == null) && (requestedProofToken == null))
            throw new NoTokenInResponse("Either a RequestedSecurityToken or a RequestedProofToken is required. Both cannot be null.");
        else if (requestedSecurityToken != null)
            wstElement.appendChild(createTokenOrReferenceElement(TrustConstants.WST_PREFIX + TrustConstants.REQUESTED_TOKEN,
                    requestedSecurityToken));
        else if (requestedProofToken != null)
            wstElement.appendChild(createTokenOrReferenceElement(TrustConstants.WST_PREFIX + TrustConstants.REQUESTED_PROOF,
                    requestedSecurityToken));

        return wstElement;
    }
}
