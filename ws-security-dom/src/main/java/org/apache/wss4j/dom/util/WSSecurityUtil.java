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

package org.apache.wss4j.dom.util;

import org.apache.wss4j.common.dom.WSConstants;
import org.apache.wss4j.common.dom.engine.WSSConfig;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.dom.callback.CallbackLookup;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.AttachmentUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.common.dom.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

//import com.sun.xml.internal.messaging.saaj.soap.SOAPDocumentImpl;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.CallbackHandler;


/**
 * WS-Security Utility methods. <p/>
 */
public final class WSSecurityUtil {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(WSSecurityUtil.class);


    private WSSecurityUtil() {
        // Complete
    }

    public static Element getSOAPHeader(Document doc) {
        String soapNamespace = XMLUtils.getSOAPNamespace(doc.getDocumentElement());
        return
            XMLUtils.getDirectChildElement(
                doc.getDocumentElement(), WSConstants.ELEM_HEADER, soapNamespace
            );
    }

    /**
     * Returns the first WS-Security header element for a given actor. Only one
     * WS-Security header is allowed for an actor.
     *
     * @param doc
     * @param actor
     * @return the <code>wsse:Security</code> element or <code>null</code>
     *         if not such element found
     */
    public static Element getSecurityHeader(Document doc, String actor) throws WSSecurityException {
        Element soapHeaderElement = getSOAPHeader(doc);
        if (soapHeaderElement == null) { // no SOAP header at all
            return null;
        }

        String soapNamespace = XMLUtils.getSOAPNamespace(doc.getDocumentElement());
        return getSecurityHeader(soapHeaderElement, actor, WSConstants.URI_SOAP12_ENV.equals(soapNamespace));
    }

    /**
     * Returns the first WS-Security header element for a given actor. Only one
     * WS-Security header is allowed for an actor.
     */
    public static Element getSecurityHeader(Element soapHeader, String actor, boolean soap12)
        throws WSSecurityException {

        String actorLocal = WSConstants.ATTR_ACTOR;
        String soapNamespace = WSConstants.URI_SOAP11_ENV;
        if (soap12) {
            actorLocal = WSConstants.ATTR_ROLE;
            soapNamespace = WSConstants.URI_SOAP12_ENV;
        }

        //
        // Iterate through the security headers
        //
        Element foundSecurityHeader = null;
        for (
            Node currentChild = soapHeader.getFirstChild();
            currentChild != null;
            currentChild = currentChild.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()
                && WSConstants.WSSE_LN.equals(currentChild.getLocalName())
                && (WSConstants.WSSE_NS.equals(currentChild.getNamespaceURI())
                    || WSConstants.OLD_WSSE_NS.equals(currentChild.getNamespaceURI()))) {

                Element elem = (Element)currentChild;
                Attr attr = elem.getAttributeNodeNS(soapNamespace, actorLocal);
                String hActor = (attr != null) ? attr.getValue() : null;

                if (XMLUtils.isActorEqual(actor, hActor)) {
                    if (foundSecurityHeader != null) {
                        LOG.debug(
                            "Two or more security headers have the same actor name: {}", actor
                        );
                        throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
                    }
                    foundSecurityHeader = elem;
                }
            }
        }
        return foundSecurityHeader;
    }

    /**
     * Gets all direct children with specified localname and namespace. <p/>
     *
     * @param fNode the node where to start the search
     * @param localName local name of the children to get
     * @param namespace the namespace of the children to get
     * @return the list of nodes or <code>null</code> if not such nodes are found
     */
    public static List<Element> getDirectChildElements(
        Node fNode,
        String localName,
        String namespace
    ) {
        List<Element> children = new ArrayList<>();
        for (
            Node currentChild = fNode.getFirstChild();
            currentChild != null;
            currentChild = currentChild.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()
                && localName.equals(currentChild.getLocalName())
                && namespace.equals(currentChild.getNamespaceURI())) {
                children.add((Element)currentChild);
            }
        }
        return children;
    }


    /**
     * return the first soap "Body" element. <p/>
     *
     * @param doc
     * @return the body element or <code>null</code> if document does not
     *         contain a SOAP body
     */
    public static Element findBodyElement(Document doc) {
        Element docElement = doc.getDocumentElement();
        String ns = docElement.getNamespaceURI();
        return XMLUtils.getDirectChildElement(docElement, WSConstants.ELEM_BODY, ns);
    }


    /**
     * Find the DOM Element in the SOAP Envelope that is referenced by the
     * WSEncryptionPart argument. The "Id" is used before the Element localname/namespace.
     *
     * @param part The WSEncryptionPart object corresponding to the DOM Element(s) we want
     * @param callbackLookup The CallbackLookup object used to find Elements
     * @return the DOM Element in the SOAP Envelope that is found
     */
    public static List<Element> findElements(
        WSEncryptionPart part, CallbackLookup callbackLookup
    ) throws WSSecurityException {
        // See if the DOM Element is stored in the WSEncryptionPart first
        if (part.getElement() != null) {
            return Collections.singletonList(part.getElement());
        }

        // Next try to find the Element via its wsu:Id
        String id = part.getId();
        if (id != null) {
            Element foundElement = callbackLookup.getElement(id, null, false);
            return Collections.singletonList(foundElement);
        }
        // Otherwise just lookup all elements with the localname/namespace
        return callbackLookup.getElements(part.getName(), part.getNamespace());
    }



    /**
     * Get the default encryption part - the SOAP Body of type "Content".
     */
    public static WSEncryptionPart getDefaultEncryptionPart(Document doc) {
        String soapNamespace =
            XMLUtils.getSOAPNamespace(doc.getDocumentElement());
        return new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace, "Content");
    }


    /**
     * create a base64 test node <p/>
     *
     * @param doc the DOM document (SOAP request)
     * @param data to encode
     * @return a Text node containing the base64 encoded data
     */
    public static Text createBase64EncodedTextNode(Document doc, byte[] data) {
        return doc.createTextNode(org.apache.xml.security.utils.XMLUtils.encodeToString(data));
    }

    public static List<Integer> decodeAction(String action) throws WSSecurityException {
        String actionToParse = action;
        if (actionToParse == null) {
            return Collections.emptyList();
        }
        actionToParse = actionToParse.trim();
        if (actionToParse.length() == 0) {
            return Collections.emptyList();
        }

        List<Integer> actions = new ArrayList<>();
        String[] single = actionToParse.split("\\s");
        for (String parsedAction : single) {
            if (parsedAction.equals(WSHandlerConstants.NO_SECURITY)) {
                return Collections.emptyList();
            } else if (parsedAction.equals(WSHandlerConstants.USERNAME_TOKEN)) {
                actions.add(WSConstants.UT);
            } else if (parsedAction.equals(WSHandlerConstants.USERNAME_TOKEN_NO_PASSWORD)) {
                actions.add(WSConstants.UT_NOPASSWORD);
            } else if (parsedAction.equals(WSHandlerConstants.SIGNATURE)) {
                actions.add(WSConstants.SIGN);
            } else if (parsedAction.equals(WSHandlerConstants.SIGNATURE_DERIVED)) {
                actions.add(WSConstants.DKT_SIGN);
            } else if (parsedAction.equals(WSHandlerConstants.ENCRYPT)
                || parsedAction.equals(WSHandlerConstants.ENCRYPTION)) {
                actions.add(WSConstants.ENCR);
            } else if (parsedAction.equals(WSHandlerConstants.ENCRYPT_DERIVED)
                || parsedAction.equals(WSHandlerConstants.ENCRYPTION_DERIVED)) {
                actions.add(WSConstants.DKT_ENCR);
            } else if (parsedAction.equals(WSHandlerConstants.SAML_TOKEN_UNSIGNED)) {
                actions.add(WSConstants.ST_UNSIGNED);
            } else if (parsedAction.equals(WSHandlerConstants.SAML_TOKEN_SIGNED)) {
                actions.add(WSConstants.ST_SIGNED);
            } else if (parsedAction.equals(WSHandlerConstants.TIMESTAMP)) {
                actions.add(WSConstants.TS);
            } else if (parsedAction.equals(WSHandlerConstants.USERNAME_TOKEN_SIGNATURE)) {
                actions.add(WSConstants.UT_SIGN);
            } else if (parsedAction.equals(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION)) {
                actions.add(WSConstants.SC);
            } else if (parsedAction.equals(WSHandlerConstants.CUSTOM_TOKEN)) {
                actions.add(WSConstants.CUSTOM_TOKEN);
            } else {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                                              new Object[] {"Unknown action defined: " + parsedAction}
                );
            }
        }
        return actions;
    }


    /**
     * Decode an action String. This method should only be called on the outbound side.
     * @param action The initial String of actions to perform
     * @param wssConfig This object holds the list of custom actions to be performed.
     * @return The list of HandlerAction Objects
     * @throws WSSecurityException
     */
    public static List<HandlerAction> decodeHandlerAction(
        String action,
        WSSConfig wssConfig
    ) throws WSSecurityException {
        if (action == null) {
            return Collections.emptyList();
        }

        List<HandlerAction> actions = new ArrayList<>();
        String[] single = action.split(" ");
        for (String parsedAction : single) {
            if (parsedAction.equals(WSHandlerConstants.NO_SECURITY)) {
                return actions;
            } else if (parsedAction.equals(WSHandlerConstants.USERNAME_TOKEN)) {
                actions.add(new HandlerAction(WSConstants.UT));
            } else if (parsedAction.equals(WSHandlerConstants.USERNAME_TOKEN_NO_PASSWORD)) {
                actions.add(new HandlerAction(WSConstants.UT_NOPASSWORD));
            } else if (parsedAction.equals(WSHandlerConstants.SIGNATURE)) {
                actions.add(new HandlerAction(WSConstants.SIGN));
            } else if (parsedAction.equals(WSHandlerConstants.SIGNATURE_DERIVED)) {
                actions.add(new HandlerAction(WSConstants.DKT_SIGN));
            } else if (parsedAction.equals(WSHandlerConstants.ENCRYPT)
                || parsedAction.equals(WSHandlerConstants.ENCRYPTION)) {
                actions.add(new HandlerAction(WSConstants.ENCR));
            } else if (parsedAction.equals(WSHandlerConstants.ENCRYPT_DERIVED)
                || parsedAction.equals(WSHandlerConstants.ENCRYPTION_DERIVED)) {
                actions.add(new HandlerAction(WSConstants.DKT_ENCR));
            } else if (parsedAction.equals(WSHandlerConstants.SAML_TOKEN_UNSIGNED)) {
                actions.add(new HandlerAction(WSConstants.ST_UNSIGNED));
            } else if (parsedAction.equals(WSHandlerConstants.SAML_TOKEN_SIGNED)) {
                actions.add(new HandlerAction(WSConstants.ST_SIGNED));
            } else if (parsedAction.equals(WSHandlerConstants.TIMESTAMP)) {
                actions.add(new HandlerAction(WSConstants.TS));
            } else if (parsedAction.equals(WSHandlerConstants.USERNAME_TOKEN_SIGNATURE)) {
                actions.add(new HandlerAction(WSConstants.UT_SIGN));
            } else if (parsedAction.equals(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION)) {
                actions.add(new HandlerAction(WSConstants.SC));
            } else if (parsedAction.equals(WSHandlerConstants.CUSTOM_TOKEN)) {
                actions.add(new HandlerAction(WSConstants.CUSTOM_TOKEN));
            } else {
                try {
                    int customAction = Integer.parseInt(parsedAction);
                    if (wssConfig == null || wssConfig.getAction(customAction) == null) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                                                      new Object[] {"Unknown action defined: " + parsedAction}
                        );
                    }
                    actions.add(new HandlerAction(customAction));
                } catch (NumberFormatException ex) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                                                  new Object[] {"Unknown action defined: " + parsedAction}
                    );
                }
            }
        }
        return actions;
    }

    public static void inlineAttachments(List<Element> includeElements,
                                         CallbackHandler attachmentCallbackHandler,
                                         boolean removeAttachments) throws WSSecurityException {
        for (Element includeElement : includeElements) {
            String xopURI = includeElement.getAttributeNS(null, "href");
            if (xopURI != null) {
                // Retrieve the attachment bytes
                byte[] attachmentBytes =
                    WSSecurityUtil.getBytesFromAttachment(xopURI, attachmentCallbackHandler, removeAttachments);
                String encodedBytes = org.apache.xml.security.utils.XMLUtils.encodeToString(attachmentBytes);

                Node encodedChild =
                    includeElement.getOwnerDocument().createTextNode(encodedBytes);
                includeElement.getParentNode().replaceChild(encodedChild, includeElement);
            }
        }
    }

    public static byte[] getBytesFromAttachment(
        String xopUri, RequestData data
    ) throws WSSecurityException {
        return getBytesFromAttachment(xopUri, data.getAttachmentCallbackHandler());
    }

    public static byte[] getBytesFromAttachment(
        String xopUri, CallbackHandler attachmentCallbackHandler
    ) throws WSSecurityException {
        return getBytesFromAttachment(xopUri, attachmentCallbackHandler, true);
    }

    public static byte[] getBytesFromAttachment(
        String xopUri, CallbackHandler attachmentCallbackHandler, boolean removeAttachments
    ) throws WSSecurityException {
        return AttachmentUtils.getBytesFromAttachment(xopUri, attachmentCallbackHandler, removeAttachments);
    }

    public static String getAttachmentId(String xopUri) throws WSSecurityException {
        return AttachmentUtils.getAttachmentId(xopUri);
    }

}
