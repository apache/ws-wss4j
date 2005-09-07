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

import org.apache.ws.sandbox.security.trust2.exception.NoRequestType;
import org.apache.ws.sandbox.security.trust2.exception.NoSoapBody;
import org.apache.ws.sandbox.security.trust2.exception.TrustException;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.net.URI;

/**
 * @author ddelvecc
 *         <p/>
 *         A class for adding a WS-Trust RequestSecurityToken element to a SOAP envelope (an XML document).
 */
public class WSAddTokenRequest {

    private URI action = null;
    private RequestSecurityToken tokenRequest;

    public WSAddTokenRequest(RequestSecurityToken tokenRequest) {
        this.tokenRequest = tokenRequest;
    }

    /**
     * Adds the standard Action element corresponding to the RequestType specified in the RequestSecurityToken message being used.
     * If the request type is non-standard (not Issue, Renew, Validate), the Action URI added will be the same as the RequestType URI.
     *
     * @throws NoRequestType
     */
    public void addAction() throws NoRequestType {
        action = TrustConstants.getActionRequest(tokenRequest.getRequestType());
        if (action == null) {
            throw new NoRequestType("Cannot generate standard action element, no requestType specified.");
        }
    }

    /**
     * Adds a custom Action element to the SOAP header. See WS-Addressing specs for more details.
     *
     * @param action The action URI to add.
     */
    public void addAction(URI action) {
        this.action = action;
    }

    /**
     * Adds a new <code>RequestSecurityToken</code> to a soap envelope.
     * <p/>
     *
     * @param doc The SOAP enevlope as W3C document
     * @return Document with RequestSecurityToken added
     * @throws DOMException NoRequestType NoSoapBody
     */
    public Document build(Document doc) throws DOMException, TrustException {
        SOAPConstants soapConsts = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());

        if (action != null) {
            Element envelope = doc.getDocumentElement();
            Element soapHeader = (Element) WSSecurityUtil.getDirectChild(doc.getFirstChild(), soapConsts.getHeaderQName().getLocalPart(),
                    soapConsts.getEnvelopeURI());

            if (soapHeader == null) {
                soapHeader = createElementInSameNamespace(envelope, soapConsts.getHeaderQName().getLocalPart());
                soapHeader = WSSecurityUtil.prependChildElement(doc, envelope, soapHeader, true);
            }

            Element actionElement = doc.createElementNS(TrustConstants.WSA_NS, TrustConstants.WST_PREFIX + TrustConstants.ACTION_TAG);
            Node actionContent = doc.createTextNode(action.toString());
            actionElement.appendChild(actionContent);
            soapHeader.appendChild(actionElement);
        }
        Element soapBody = WSSecurityUtil.findBodyElement(doc, soapConsts);
        if (soapBody == null) {
            throw new NoSoapBody("A SOAP Body element is needed to insert the <RequestSecurityToken>.");
        }

        setWsuId(soapBody);
        if (tokenRequest != null)
            soapBody.appendChild(tokenRequest.getElement());
        return doc;
    }

    /**
     * create a new element in the same namespace
     * <p/>
     *
     * @param parent
     * @param localName
     * @return
     */
    private static Element createElementInSameNamespace(Element parent, String localName) {
        String prefix = parent.getPrefix();
        if (prefix == null) {
            prefix = "";
        }
        String qName = prefix + ":" + localName;
        String nsUri = parent.getNamespaceURI();
        return parent.getOwnerDocument().createElementNS(nsUri, qName);
    }

    private String setWsuId(Element bodyElement) {
        String id = bodyElement.getAttributeNS(WSConstants.WSU_NS, "Id");
        if ((id == null) || (id.length() == 0)) {
            id = "id-" + Integer.toString(bodyElement.hashCode());
            String prefix = WSSecurityUtil.setNamespace(bodyElement, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
            bodyElement.setAttributeNS(WSConstants.WSU_NS, prefix + ":Id", id);
        }
        return id;
    }

    public static void main(String[] args) throws Exception {
        SOAPEnvelope env = new SOAPEnvelope();
        Document doc = env.getAsDocument();
        WSSConfig wssConfig = WSSConfig.getDefaultWSConfig();

        RequestSecurityToken tokenRequest = new RequestSecurityToken(doc, TrustConstants.REQUEST_ISSUE);

        tokenRequest.setContext(new URI("http://context.context"));
        tokenRequest.setTokenType(TokenTypes.X509);

        UsernameToken userToken = new UsernameToken(wssConfig.isPrecisionInMilliSeconds(), doc);
        userToken.setName("bob");
        userToken.setPassword("bobspass");
        tokenRequest.setBase(new SecurityTokenOrReference(userToken));

        UsernameToken user2Token = new UsernameToken(wssConfig.isPrecisionInMilliSeconds(), doc);
        user2Token.setName("joe");
        user2Token.setPassword("bobspass");
        tokenRequest.addSupporting(new SecurityTokenOrReference(user2Token));

        UsernameToken user3Token = new UsernameToken(wssConfig.isPrecisionInMilliSeconds(), doc);
        user3Token.setName("mike");
        user3Token.setPassword("bobspass");
        tokenRequest.addSupporting(new SecurityTokenOrReference(user3Token));

        WSAddTokenRequest builder = new WSAddTokenRequest(tokenRequest);
        builder.addAction();
        doc = builder.build(doc);
        /*
        WSSignEnvelope builder = new WSSignEnvelope();
        builder.setUserInfo(credName, password);
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        doc = builder.build(env.getAsDocument(), CryptoFactory.getInstance(cryptoPropFile));
*/
										
        System.out.println("\n============= Request ==============");
        System.out.println(org.apache.axis.utils.XMLUtils.DocumentToString(doc));
    }

}
