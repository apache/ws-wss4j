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

import org.apache.wss4j.dom.SOAP11Constants;
import org.apache.wss4j.dom.SOAP12Constants;
import org.apache.wss4j.dom.SOAPConstants;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.callback.CallbackLookup;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.AttachmentResultCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.utils.JavaUtils;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

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
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
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

        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
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

                if (WSSecurityUtil.isActorEqual(actor, hActor)) {
                    if (foundSecurityHeader != null) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(
                                "Two or more security headers have the same actor name: " + actor
                            );
                        }
                        throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
                    }
                    foundSecurityHeader = elem;
                }
            }
        }
        return foundSecurityHeader;
    }


    /**
     * Compares two actor strings and returns true if these are equal. Takes
     * care of the null length strings and uses ignore case.
     *
     * @param actor
     * @param hActor
     * @return true is the actor arguments are equal
     */
    public static boolean isActorEqual(String actor, String hActor) {
        if ((hActor == null || hActor.length() == 0)
            && (actor == null || actor.length() == 0)) {
            return true;
        }

        if (hActor != null && actor != null && hActor.equalsIgnoreCase(actor)) {
            return true;
        }

        return false;
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
     * @param doc The owning document
     * @return the DOM Element in the SOAP Envelope that is found
     */
    public static List<Element> findElements(
        WSEncryptionPart part, CallbackLookup callbackLookup, Document doc
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
            WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        return new WSEncryptionPart(WSConstants.ELEM_BODY, soapNamespace, "Content");
    }

    /**
     * create a new element in the same namespace <p/>
     *
     * @param parent for the new element
     * @param localName of the new element
     * @return the new element
     */
    private static Element createElementInSameNamespace(Element parent, String localName) {
        String qName = localName;
        String prefix = parent.getPrefix();
        if (prefix != null && prefix.length() > 0) {
            qName = prefix + ":" + localName;
        }

        String nsUri = parent.getNamespaceURI();
        return parent.getOwnerDocument().createElementNS(nsUri, qName);
    }


    /**
     * prepend a child element <p/>
     *
     * @param parent element of this child element
     * @param child the element to append
     * @return the child element
     */
    public static Element prependChildElement(
        Element parent,
        Element child
    ) {
        Node firstChild = parent.getFirstChild();
        if (firstChild == null) {
            return (Element)parent.appendChild(child);
        } else {
            return (Element)parent.insertBefore(child, firstChild);
        }
    }


    /**
     * find the first ws-security header block <p/>
     *
     * @param doc the DOM document (SOAP request)
     * @param envelope the SOAP envelope
     * @param doCreate if true create a new WSS header block if none exists
     * @return the WSS header or null if none found and doCreate is false
     */
    public static Element findWsseSecurityHeaderBlock(
        Document doc,
        Element envelope,
        boolean doCreate
    ) throws WSSecurityException {
        return findWsseSecurityHeaderBlock(doc, envelope, null, doCreate);
    }

    /**
     * find a WS-Security header block for a given actor <p/>
     *
     * @param doc the DOM document (SOAP request)
     * @param envelope the SOAP envelope
     * @param actor the actor (role) name of the WSS header
     * @param doCreate if true create a new WSS header block if none exists
     * @return the WSS header or null if none found and doCreate is false
     */
    public static Element findWsseSecurityHeaderBlock(
        Document doc,
        Element envelope,
        String actor,
        boolean doCreate
    ) throws WSSecurityException {
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        Element header =
            XMLUtils.getDirectChildElement(
                doc.getDocumentElement(),
                WSConstants.ELEM_HEADER,
                soapNamespace
            );
        if (header == null) { // no SOAP header at all
            if (doCreate) {
                header = createElementInSameNamespace(envelope, WSConstants.ELEM_HEADER);
                header = prependChildElement(envelope, header);
            } else {
                return null;
            }
        }

        String actorLocal = WSConstants.ATTR_ACTOR;
        if (WSConstants.URI_SOAP12_ENV.equals(soapNamespace)) {
            actorLocal = WSConstants.ATTR_ROLE;
        }

        //
        // Iterate through the security headers
        //
        Element foundSecurityHeader = null;
        for (
            Node currentChild = header.getFirstChild();
            currentChild != null;
            currentChild = currentChild.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()
                && WSConstants.WSSE_LN.equals(currentChild.getLocalName())
                && WSConstants.WSSE_NS.equals(currentChild.getNamespaceURI())) {

                Element elem = (Element)currentChild;
                Attr attr = elem.getAttributeNodeNS(soapNamespace, actorLocal);
                String hActor = (attr != null) ? attr.getValue() : null;

                if (WSSecurityUtil.isActorEqual(actor, hActor)) {
                    if (foundSecurityHeader != null) {
                        if (LOG.isDebugEnabled()) {
                            LOG.debug(
                                "Two or more security headers have the same actor name: " + actor
                            );
                        }
                        throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY);
                    }
                    foundSecurityHeader = elem;
                }
            }
        }
        if (foundSecurityHeader != null) {
            return foundSecurityHeader;
        } else if (doCreate) {
            foundSecurityHeader = doc.createElementNS(WSConstants.WSSE_NS, "wsse:Security");
            foundSecurityHeader.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:wsse", WSConstants.WSSE_NS);
            return prependChildElement(header, foundSecurityHeader);
        }
        return null;
    }

    /**
     * create a base64 test node <p/>
     *
     * @param doc the DOM document (SOAP request)
     * @param data to encode
     * @return a Text node containing the base64 encoded data
     */
    public static Text createBase64EncodedTextNode(Document doc, byte[] data) {
        return doc.createTextNode(Base64.getMimeEncoder().encodeToString(data));
    }

    public static SOAPConstants getSOAPConstants(Element startElement) {
        Document doc = startElement.getOwnerDocument();
        String ns = doc.getDocumentElement().getNamespaceURI();
        if (WSConstants.URI_SOAP12_ENV.equals(ns)) {
            return new SOAP12Constants();
        }
        return new SOAP11Constants();
    }

    public static String getSOAPNamespace(Element startElement) {
        return getSOAPConstants(startElement).getEnvelopeURI();
    }

    public static List<Integer> decodeAction(String action) throws WSSecurityException {
        String actionToParse = action;
        if (actionToParse == null) {
            return Collections.emptyList();
        }
        actionToParse = actionToParse.trim();
        if ("".equals(actionToParse)) {
            return Collections.emptyList();
        }

        List<Integer> actions = new ArrayList<>();
        String[] single = actionToParse.split("\\s");
        for (int i = 0; i < single.length; i++) {
            if (single[i].equals(WSHandlerConstants.NO_SECURITY)) {
                return actions;
            } else if (single[i].equals(WSHandlerConstants.USERNAME_TOKEN)) {
                actions.add(WSConstants.UT);
            } else if (single[i].equals(WSHandlerConstants.USERNAME_TOKEN_NO_PASSWORD)) {
                actions.add(WSConstants.UT_NOPASSWORD);
            } else if (single[i].equals(WSHandlerConstants.SIGNATURE)) {
                actions.add(WSConstants.SIGN);
            } else if (single[i].equals(WSHandlerConstants.SIGNATURE_DERIVED)) {
                actions.add(WSConstants.DKT_SIGN);
            } else if (single[i].equals(WSHandlerConstants.ENCRYPT)) {
                actions.add(WSConstants.ENCR);
            } else if (single[i].equals(WSHandlerConstants.ENCRYPT_DERIVED)) {
                actions.add(WSConstants.DKT_ENCR);
            } else if (single[i].equals(WSHandlerConstants.SAML_TOKEN_UNSIGNED)) {
                actions.add(WSConstants.ST_UNSIGNED);
            } else if (single[i].equals(WSHandlerConstants.SAML_TOKEN_SIGNED)) {
                actions.add(WSConstants.ST_SIGNED);
            } else if (single[i].equals(WSHandlerConstants.TIMESTAMP)) {
                actions.add(WSConstants.TS);
            } else if (single[i].equals(WSHandlerConstants.USERNAME_TOKEN_SIGNATURE)) {
                actions.add(WSConstants.UT_SIGN);
            } else if (single[i].equals(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION)) {
                actions.add(WSConstants.SC);
            } else if (single[i].equals(WSHandlerConstants.CUSTOM_TOKEN)) {
                actions.add(WSConstants.CUSTOM_TOKEN);
            } else {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                                              new Object[] {"Unknown action defined: " + single[i]}
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
        for (int i = 0; i < single.length; i++) {
            if (single[i].equals(WSHandlerConstants.NO_SECURITY)) {
                return actions;
            } else if (single[i].equals(WSHandlerConstants.USERNAME_TOKEN)) {
                actions.add(new HandlerAction(WSConstants.UT));
            } else if (single[i].equals(WSHandlerConstants.SIGNATURE)) {
                actions.add(new HandlerAction(WSConstants.SIGN));
            } else if (single[i].equals(WSHandlerConstants.SIGNATURE_DERIVED)) {
                actions.add(new HandlerAction(WSConstants.DKT_SIGN));
            } else if (single[i].equals(WSHandlerConstants.ENCRYPT)) {
                actions.add(new HandlerAction(WSConstants.ENCR));
            } else if (single[i].equals(WSHandlerConstants.ENCRYPT_DERIVED)) {
                actions.add(new HandlerAction(WSConstants.DKT_ENCR));
            } else if (single[i].equals(WSHandlerConstants.SAML_TOKEN_UNSIGNED)) {
                actions.add(new HandlerAction(WSConstants.ST_UNSIGNED));
            } else if (single[i].equals(WSHandlerConstants.SAML_TOKEN_SIGNED)) {
                actions.add(new HandlerAction(WSConstants.ST_SIGNED));
            } else if (single[i].equals(WSHandlerConstants.TIMESTAMP)) {
                actions.add(new HandlerAction(WSConstants.TS));
            } else if (single[i].equals(WSHandlerConstants.USERNAME_TOKEN_SIGNATURE)) {
                actions.add(new HandlerAction(WSConstants.UT_SIGN));
            } else if (single[i].equals(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION)) {
                actions.add(new HandlerAction(WSConstants.SC));
            } else {
                try {
                    int parsedAction = Integer.parseInt(single[i]);
                    if (wssConfig.getAction(parsedAction) == null) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                                                      new Object[] {"Unknown action defined: " + single[i]}
                        );
                    }
                    actions.add(new HandlerAction(parsedAction));
                } catch (NumberFormatException ex) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                                                  new Object[] {"Unknown action defined: " + single[i]}
                    );
                }
            }
        }
        return actions;
    }

    /**
     * Generate a nonce of the given length using the SHA1PRNG algorithm. The SecureRandom
     * instance that backs this method is cached for efficiency.
     *
     * @return a nonce of the given length
     * @throws WSSecurityException
     */
    public static byte[] generateNonce(int length) throws WSSecurityException {
        try {
            return XMLSecurityConstants.generateBytes(length);
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, ex,
                    "empty", new Object[] {"Error in generating nonce of length " + length}
            );
        }
    }

    public static byte[] getBytesFromAttachment(
        String xopUri, RequestData data
    ) throws WSSecurityException {
        CallbackHandler attachmentCallbackHandler = data.getAttachmentCallbackHandler();
        if (attachmentCallbackHandler == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
        }

        String attachmentId = null;
        try {
            attachmentId = URLDecoder.decode(xopUri.substring("cid:".length()), StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.INVALID_SECURITY,
                "empty", new Object[] {"Attachment ID cannot be decoded: " + xopUri}
            );
        }

        AttachmentRequestCallback attachmentRequestCallback = new AttachmentRequestCallback();
        attachmentRequestCallback.setAttachmentId(attachmentId);

        try {
            attachmentCallbackHandler.handle(new Callback[]{attachmentRequestCallback});

            List<Attachment> attachments = attachmentRequestCallback.getAttachments();
            if (attachments == null || attachments.isEmpty()
                || !attachmentId.equals(attachments.get(0).getId())) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.INVALID_SECURITY,
                    "empty", new Object[] {"Attachment not found: " + xopUri}
                );
            }
            Attachment attachment = attachments.get(0);
            InputStream inputStream = attachment.getSourceStream();

            return JavaUtils.getBytesFromStream(inputStream);
        } catch (UnsupportedCallbackException | IOException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
        }
    }

    public static void storeBytesInAttachment(
        Element parentElement,
        Document doc,
        String attachmentId,
        byte[] bytes,
        CallbackHandler attachmentCallbackHandler
    ) throws WSSecurityException {
        parentElement.setAttributeNS(XMLUtils.XMLNS_NS, "xmlns:xop", WSConstants.XOP_NS);
        Element xopInclude =
            doc.createElementNS(WSConstants.XOP_NS, "xop:Include");
        xopInclude.setAttributeNS(null, "href", "cid:" + attachmentId);
        parentElement.appendChild(xopInclude);

        Attachment resultAttachment = new Attachment();
        resultAttachment.setId(attachmentId);
        resultAttachment.setMimeType("application/ciphervalue");
        resultAttachment.setSourceStream(new ByteArrayInputStream(bytes));

        AttachmentResultCallback attachmentResultCallback = new AttachmentResultCallback();
        attachmentResultCallback.setAttachmentId(attachmentId);
        attachmentResultCallback.setAttachment(resultAttachment);
        try {
            attachmentCallbackHandler.handle(new Callback[]{attachmentResultCallback});
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }

    }
}
