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
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.ext.Attachment;
import org.apache.wss4j.common.ext.AttachmentRequestCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.message.CallbackLookup;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.JavaUtils;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.namespace.QName;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;
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

    /**
     * A cached MessageDigest object
     */
    private static MessageDigest digest;
    
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
    public static Element getSecurityHeader(Element soapHeader, String actor, boolean soap12) throws WSSecurityException {
        
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
     * Gets a direct child with specified localname and namespace. <p/>
     * 
     * @param parentNode the node where to start the search
     * @param localName local name of the child to get
     * @param namespace the namespace of the child to get
     * @return the node or <code>null</code> if not such node found
     */
    public static Element getDirectChildElement(
        Node parentNode, 
        String localName,
        String namespace
    ) {
        if (parentNode == null) {
            return null;
        }
        for (
            Node currentChild = parentNode.getFirstChild(); 
            currentChild != null; 
            currentChild = currentChild.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()
                && localName.equals(currentChild.getLocalName())
                && namespace.equals(currentChild.getNamespaceURI())) {
                return (Element)currentChild;
            }
        }
        return null;
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
        List<Element> children = new ArrayList<Element>();
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
        //
        // Find the SOAP Envelope NS. Default to SOAP11 NS
        //
        Element docElement = doc.getDocumentElement();
        String ns = docElement.getNamespaceURI();
        return getDirectChildElement(docElement, WSConstants.ELEM_BODY, ns);
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
     * Returns the first element that matches <code>name</code> and
     * <code>namespace</code>. <p/> This is a replacement for a XPath lookup
     * <code>//name</code> with the given namespace. It's somewhat faster than
     * XPath, and we do not deal with prefixes, just with the real namespace URI
     * 
     * @param startNode Where to start the search
     * @param name Local name of the element
     * @param namespace Namespace URI of the element
     * @return The found element or <code>null</code>
     */
    public static Element findElement(Node startNode, String name, String namespace) {
        //
        // Replace the formerly recursive implementation with a depth-first-loop
        // lookup
        //
        if (startNode == null) {
            return null;
        }
        Node startParent = startNode.getParentNode();
        Node processedNode = null;

        while (startNode != null) {
            // start node processing at this point
            if (startNode.getNodeType() == Node.ELEMENT_NODE
                && startNode.getLocalName().equals(name)) {
                String ns = startNode.getNamespaceURI();
                if (ns != null && ns.equals(namespace)) {
                    return (Element)startNode;
                }

                if ((namespace == null || namespace.length() == 0)
                    && (ns == null || ns.length() == 0)) {
                    return (Element)startNode;
                }
            }
            processedNode = startNode;
            startNode = startNode.getFirstChild();

            // no child, this node is done.
            if (startNode == null) {
                // close node processing, get sibling
                startNode = processedNode.getNextSibling();
            }
            // no more siblings, get parent, all children
            // of parent are processed.
            while (startNode == null) {
                processedNode = processedNode.getParentNode();
                if (processedNode == startParent) {
                    return null;
                }
                // close parent node processing (processed node now)
                startNode = processedNode.getNextSibling();
            }
        }
        return null;
    }
    
    /**
     * Returns all elements that match <code>name</code> and <code>namespace</code>. 
     * <p/> This is a replacement for a XPath lookup
     * <code>//name</code> with the given namespace. It's somewhat faster than
     * XPath, and we do not deal with prefixes, just with the real namespace URI
     * 
     * @param startNode Where to start the search
     * @param name Local name of the element
     * @param namespace Namespace URI of the element
     * @return The found elements (or an empty list)
     */
    public static List<Element> findElements(Node startNode, String name, String namespace) {
        //
        // Replace the formerly recursive implementation with a depth-first-loop
        // lookup
        //
        if (startNode == null) {
            return null;
        }
        Node startParent = startNode.getParentNode();
        Node processedNode = null;

        List<Element> foundNodes = new ArrayList<Element>();
        while (startNode != null) {
            // start node processing at this point
            if (startNode.getNodeType() == Node.ELEMENT_NODE
                && startNode.getLocalName().equals(name)) {
                String ns = startNode.getNamespaceURI();
                if (ns != null && ns.equals(namespace)) {
                    foundNodes.add((Element)startNode);
                }

                if ((namespace == null || namespace.length() == 0)
                    && (ns == null || ns.length() == 0)) {
                    foundNodes.add((Element)startNode);
                }
            }
            processedNode = startNode;
            startNode = startNode.getFirstChild();

            // no child, this node is done.
            if (startNode == null) {
                // close node processing, get sibling
                startNode = processedNode.getNextSibling();
            }
            // no more siblings, get parent, all children
            // of parent are processed.
            while (startNode == null) {
                processedNode = processedNode.getParentNode();
                if (processedNode == startParent) {
                    return foundNodes;
                }
                // close parent node processing (processed node now)
                startNode = processedNode.getNextSibling();
            }
        }
        return foundNodes;
    }
    
    /**
     * Returns the single SAMLAssertion element that contains an AssertionID/ID that
     * matches the supplied parameter.
     * 
     * @param startNode Where to start the search
     * @param value Value of the AssertionID/ID attribute
     * @return The found element if there was exactly one match, or
     *         <code>null</code> otherwise
     */
    public static Element findSAMLAssertionElementById(Node startNode, String value) {
        Element foundElement = null;

        //
        // Replace the formerly recursive implementation with a depth-first-loop
        // lookup
        //
        if (startNode == null) {
            return null;
        }
        Node startParent = startNode.getParentNode();
        Node processedNode = null;

        while (startNode != null) {
            // start node processing at this point
            if (startNode.getNodeType() == Node.ELEMENT_NODE) {
                Element se = (Element) startNode;
                if (se.hasAttributeNS(null, "ID") && value.equals(se.getAttributeNS(null, "ID"))
                    || se.hasAttributeNS(null, "AssertionID") 
                        && value.equals(se.getAttributeNS(null, "AssertionID"))) {
                    if (foundElement == null) {
                        foundElement = se; // Continue searching to find duplicates
                    } else {
                        LOG.warn("Multiple elements with the same 'ID' attribute value!");
                        return null;
                    }
                }
            }

            processedNode = startNode;
            startNode = startNode.getFirstChild();

            // no child, this node is done.
            if (startNode == null) {
                // close node processing, get sibling
                startNode = processedNode.getNextSibling();
            }
            // no more siblings, get parent, all children
            // of parent are processed.
            while (startNode == null) {
                processedNode = processedNode.getParentNode();
                if (processedNode == startParent) {
                    return foundElement;
                }
                // close parent node processing (processed node now)
                startNode = processedNode.getNextSibling();
            }
        }
        return foundElement;
    }
    

    /**
     * Returns the single element that contains an Id with value
     * <code>uri</code> and <code>namespace</code>. The Id can be either a wsu:Id or an Id
     * with no namespace. This is a replacement for a XPath Id lookup with the given namespace. 
     * It's somewhat faster than XPath, and we do not deal with prefixes, just with the real
     * namespace URI
     * 
     * If checkMultipleElements is true and there are multiple elements, we LOG.a 
     * warning and return null as this can be used to get around the signature checking.
     * 
     * @param startNode Where to start the search
     * @param value Value of the Id attribute
     * @param checkMultipleElements If true then go through the entire tree and return 
     *        null if there are multiple elements with the same Id
     * @return The found element if there was exactly one match, or
     *         <code>null</code> otherwise
     */
    public static Element findElementById(
        Node startNode, String value, boolean checkMultipleElements
    ) {
        //
        // Replace the formerly recursive implementation with a depth-first-loop lookup
        //
        Node startParent = startNode.getParentNode();
        Node processedNode = null;
        Element foundElement = null;
        String id = getIDFromReference(value);

        while (startNode != null) {
            // start node processing at this point
            if (startNode.getNodeType() == Node.ELEMENT_NODE) {
                Element se = (Element) startNode;
                // Try the wsu:Id first
                String attributeNS = se.getAttributeNS(WSConstants.WSU_NS, "Id");
                if ("".equals(attributeNS) || !id.equals(attributeNS)) {
                    attributeNS = se.getAttributeNS(null, "Id");
                }
                if (!"".equals(attributeNS) && id.equals(attributeNS)) {
                    if (!checkMultipleElements) {
                        return se;
                    } else if (foundElement == null) {
                        foundElement = se; // Continue searching to find duplicates
                    } else {
                        LOG.warn("Multiple elements with the same 'Id' attribute value!");
                        return null;
                    }
                }
            }

            processedNode = startNode;
            startNode = startNode.getFirstChild();

            // no child, this node is done.
            if (startNode == null) {
                // close node processing, get sibling
                startNode = processedNode.getNextSibling();
            }
            // no more siblings, get parent, all children
            // of parent are processed.
            while (startNode == null) {
                processedNode = processedNode.getParentNode();
                if (processedNode == startParent) {
                    return foundElement;
                }
                // close parent node processing (processed node now)
                startNode = processedNode.getNextSibling();
            }
        }
        return foundElement;
    }

    /**
     * Set a namespace/prefix on an element if it is not set already. First off, it
     * searches for the element for the prefix associated with the specified
     * namespace. If the prefix isn't null, then this is returned. Otherwise, it
     * creates a new attribute using the namespace/prefix passed as parameters.
     * 
     * @param element
     * @param namespace
     * @param prefix
     * @return the prefix associated with the set namespace
     */
    public static String setNamespace(Element element, String namespace, String prefix) {
        String pre = getPrefixNS(namespace, element);
        if (pre != null) {
            return pre;
        }
        element.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:" + prefix, namespace);
        return prefix;
    }

    /*
     * The following methods were copied over from axis.utils.XMLUtils and adapted
     */
    public static String getPrefixNS(String uri, Node e) {
        while (e != null && e.getNodeType() == Element.ELEMENT_NODE) {
            NamedNodeMap attrs = e.getAttributes();
            for (int n = 0; n < attrs.getLength(); n++) {
                Attr a = (Attr) attrs.item(n);
                String name = a.getName();
                if (name.startsWith("xmlns:") && a.getNodeValue().equals(uri)) {
                    return name.substring("xmlns:".length());
                }
            }
            e = e.getParentNode();
        }
        return null;
    }

    public static String getNamespace(String prefix, Node e) {
        while (e != null && e.getNodeType() == Node.ELEMENT_NODE) {
            Attr attr = null;
            if (prefix == null) {
                attr = ((Element) e).getAttributeNodeNS(null, "xmlns");
            } else {
                attr = ((Element) e).getAttributeNodeNS(WSConstants.XMLNS_NS, prefix);
            }
            if (attr != null) {
                return attr.getValue();
            }
            e = e.getParentNode();
        }
        return null;
    }

    /**
     * Return a QName when passed a string like "foo:bar" by mapping the "foo"
     * prefix to a namespace in the context of the given Node.
     * 
     * @return a QName generated from the given string representation
     */
    public static QName getQNameFromString(String str, Node e) {
        return getQNameFromString(str, e, false);
    }

    /**
     * Return a QName when passed a string like "foo:bar" by mapping the "foo"
     * prefix to a namespace in the context of the given Node. If default
     * namespace is found it is returned as part of the QName.
     * 
     * @return a QName generated from the given string representation
     */
    public static QName getFullQNameFromString(String str, Node e) {
        return getQNameFromString(str, e, true);
    }

    private static QName getQNameFromString(String str, Node e, boolean defaultNS) {
        if (str == null || e == null) {
            return null;
        }
        int idx = str.indexOf(':');
        if (idx > -1) {
            String prefix = str.substring(0, idx);
            String ns = XMLUtils.getNamespace(prefix, e);
            if (ns == null) {
                return null;
            }
            return new QName(ns, str.substring(idx + 1));
        } else {
            if (defaultNS) {
                String ns = XMLUtils.getNamespace(null, e);
                if (ns != null) {
                    return new QName(ns, str);
                }
            }
            return new QName("", str);
        }
    }

    /**
     * Return a string for a particular QName, mapping a new prefix if
     * necessary.
     */
    public static String getStringForQName(QName qname, Element e) {
        String uri = qname.getNamespaceURI();
        String prefix = getPrefixNS(uri, e);
        if (prefix == null) {
            int i = 1;
            prefix = "ns" + i;
            while (XMLUtils.getNamespace(prefix, e) != null) {
                i++;
                prefix = "ns" + i;
            }
            e.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:" + prefix, uri);
        }
        return prefix + ":" + qname.getLocalPart();
    }

    /**
     * Turn a reference (eg "#5") into an ID (eg "5").
     * 
     * @param ref
     * @return ref trimmed and with the leading "#" removed, or null if not
     *         correctly formed
     */
    public static String getIDFromReference(String ref) {
        if (ref == null) {
            return null;
        }
        String id = ref.trim();
        if (id.length() == 0) {
            return null;
        }
        if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        return id;
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
            getDirectChildElement(
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
    public static Text createBase64EncodedTextNode(Document doc, byte data[]) {
        return doc.createTextNode(Base64.encode(data));
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
    
    /**
     * Translate the "cipherAlgo" URI to a JCE ID, and return a javax.crypto.Cipher instance
     * of this type. 
     */
    public static Cipher getCipherInstance(String cipherAlgo)
        throws WSSecurityException {
        try {
            String keyAlgorithm = JCEMapper.translateURItoJCEID(cipherAlgo);
            String provider = JCEMapper.getProviderId();
            
            if (provider == null) {
                return Cipher.getInstance(keyAlgorithm);
            }
            return Cipher.getInstance(keyAlgorithm, provider);
        } catch (NoSuchPaddingException ex) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, ex, "unsupportedKeyTransp", 
                new Object[] {"No such padding: " + cipherAlgo});
        } catch (NoSuchAlgorithmException ex) {
            // Check to see if an RSA OAEP MGF-1 with SHA-1 algorithm was requested
            // Some JDKs don't support RSA/ECB/OAEPPadding
            if (WSConstants.KEYTRANSPORT_RSAOEP.equals(cipherAlgo)) {
                try {
                    return Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
                } catch (Exception e) {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, e, "unsupportedKeyTransp",
                        new Object[] {"No such algorithm: " + cipherAlgo});
                }
            } else {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, ex, "unsupportedKeyTransp",
                    new Object[] {"No such algorithm: " + cipherAlgo});
            }
        } catch (NoSuchProviderException ex) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, ex, "unsupportedKeyTransp",
                new Object[] {"No such provider " + JCEMapper.getProviderId() + " for: " + cipherAlgo});
        }
    }
    

    /**
     * Fetch the result of a given action from a given result list
     * 
     * @param resultList The result list to fetch an action from
     * @param action The action to fetch
     * @return The last result fetched from the result list, null if the result
     *         could not be found
     */
    public static WSSecurityEngineResult fetchActionResult(
        List<WSSecurityEngineResult> resultList, 
        int action
    ) {
        WSSecurityEngineResult returnResult = null;
        
        for (WSSecurityEngineResult result : resultList) {
            //
            // Check the result of every action whether it matches the given action
            //
            int resultAction =
                    (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            if (resultAction == action) {
                returnResult = result;
            }
        }

        return returnResult;
    }
    
    /**
     * Fetch the result of a given action from a given result list.
     * 
     * @param resultList The result list to fetch an action from
     * @param action The action to fetch
     * @return The result fetched from the result list, null if the result
     *         could not be found
     */
    public static List<WSSecurityEngineResult> fetchAllActionResults(
        List<WSSecurityEngineResult> resultList,
        int action
    ) {
        return fetchAllActionResults(resultList, Collections.singletonList(action));
    }
    
    /**
     * Fetch the results of a given number of actions action from a given result list.
     * 
     * @param resultList The result list to fetch an action from
     * @param actions The list of actions to fetch
     * @return The list of matching results fetched from the result list
     */
    public static List<WSSecurityEngineResult> fetchAllActionResults(
        List<WSSecurityEngineResult> resultList,
        List<Integer> actions
    ) {
        List<WSSecurityEngineResult> actionResultList = Collections.emptyList();
        if (actions == null || actions.isEmpty()) {
            return actionResultList;
        }
        
        for (WSSecurityEngineResult result : resultList) {
            //
            // Check the result of every action whether it matches the given action
            //
            int resultAction =
                    (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            if (actions.contains(resultAction)) {
                if (actionResultList.isEmpty()) {
                    actionResultList = new ArrayList<WSSecurityEngineResult>();
                }
                actionResultList.add(result);
            }
        }
        return actionResultList;
    }

    public static List<Integer> decodeAction(String action) throws WSSecurityException {
        List<Integer> actions = new ArrayList<Integer>();
        String actionToParse = action;
        if (actionToParse == null) {
            return actions;
        }
        actionToParse = actionToParse.trim();
        if ("".equals(actionToParse)) {
            return actions;
        }
        String single[] = actionToParse.split("\\s");
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
        List<HandlerAction> actions = new ArrayList<HandlerAction>();
        if (action == null) {
            return actions;
        }
        
        String single[] = action.split(" ");
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
    
    /**
     * Generate a (SHA1) digest of the input bytes. The MessageDigest instance that backs this
     * method is cached for efficiency.  
     * @param inputBytes the bytes to digest
     * @return the digest of the input bytes
     * @throws WSSecurityException
     */
    public static synchronized byte[] generateDigest(byte[] inputBytes) throws WSSecurityException {
        try {
            if (digest == null) {
                digest = MessageDigest.getInstance("SHA-1");
            }
            return digest.digest(inputBytes);
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e, "empty",
                                          new Object[] {"Error in generating digest"}
            );
        }
    }
    
    /**
     * @return  a list of child Nodes
     */
    public static List<Node>
    listChildren(
        final Node parent
    ) {
        final List<Node> ret = new ArrayList<Node>();
        if (parent != null) {
            Node node = parent.getFirstChild();
            while (node != null) {
                ret.add(node);
                node = node.getNextSibling();
            }
        }
        return ret;
    }
    
    /**
     * @return a list of Nodes in b that are not in a 
     */
    public static List<Node>
    newNodes(
        final List<Node> a,
        final List<Node> b
    ) {
        if (a.size() == 0) {
            return b;
        }
        final List<Node> ret = new ArrayList<Node>();
        if (b.size() == 0) {
            return ret;
        }
        for (
            final Iterator<Node> bpos = b.iterator();
            bpos.hasNext();
        ) {
            final Node bnode = bpos.next();
            final String bns = bnode.getNamespaceURI();
            final String bln = bnode.getLocalName();
            boolean found = false;
            for (
                final Iterator<Node> apos = a.iterator();
                apos.hasNext() && !found;
            ) {
                final Node anode = apos.next();
                final String ans = anode.getNamespaceURI();
                final String aln = anode.getLocalName();
                final boolean nsmatch =
                    ans == null
                    ? bns == null ? true : false
                    : bns == null ? false : ans.equals(bns);
                final boolean lnmatch =
                    aln == null
                    ? bln == null ? true : false
                    : bln == null ? false : aln.equals(bln);
                if (nsmatch && lnmatch) {
                    found = true;
                }
            }
            if (!found) {
                ret.add(bnode);
            }
        }
        return ret;
    }
    
    /**
     * Store the element argument in the DOM Crypto Context if it has one of the standard
     * "Id" attributes.
     */
    public static void storeElementInContext(
        DOMCryptoContext context, 
        Element element
    ) {
        if (element.hasAttributeNS(WSConstants.WSU_NS, "Id")) {
            context.setIdAttributeNS(element, WSConstants.WSU_NS, "Id");
        }
        if (element.hasAttributeNS(null, "Id")) {
            context.setIdAttributeNS(element, null, "Id");
        }
        if (element.hasAttributeNS(null, "ID")) {
            context.setIdAttributeNS(element, null, "ID");
        }
        if (element.hasAttributeNS(null, "AssertionID")) {
            context.setIdAttributeNS(element, null, "AssertionID");
        }
    }
    
    public static void verifySignedElement(Element elem, WSDocInfo wsDocInfo)
        throws WSSecurityException {
        verifySignedElement(elem, wsDocInfo.getResultsByTag(WSConstants.SIGN));
    }
    
    public static void verifySignedElement(Element elem, List<WSSecurityEngineResult> signedResults)
        throws WSSecurityException {
        if (signedResults != null) {
            for (WSSecurityEngineResult signedResult : signedResults) {
                @SuppressWarnings("unchecked")
                List<WSDataRef> dataRefs = 
                    (List<WSDataRef>)signedResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
                if (dataRefs != null) {
                    for (WSDataRef dataRef : dataRefs) {
                        if (isElementOrAncestorSigned(elem, dataRef.getProtectedElement())) {
                            return;
                        }
                    }
                }
            }
        }
        
        throw new WSSecurityException(
            WSSecurityException.ErrorCode.FAILED_CHECK, "requiredElementNotSigned", 
            new Object[] {elem});
    }
    
    /**
     * Does the current element or some ancestor of it correspond to the known "signedElement"? 
     */
    private static boolean isElementOrAncestorSigned(Element elem, Element signedElement) 
        throws WSSecurityException {
        final Element envelope = elem.getOwnerDocument().getDocumentElement();
        Node cur = elem;
        while (!cur.isSameNode(envelope)) {
            if (cur.getNodeType() == Node.ELEMENT_NODE && cur.equals(signedElement)) {
                return true;
            }
            cur = cur.getParentNode();
        }
        
        return false;
    }
    
    public static byte[] getBytesFromAttachment(
        String xopUri, RequestData data
    ) throws WSSecurityException {
        CallbackHandler attachmentCallbackHandler = data.getAttachmentCallbackHandler();
        if (attachmentCallbackHandler == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK);
        }

        final String attachmentId = xopUri.substring("cid:".length());

        AttachmentRequestCallback attachmentRequestCallback = new AttachmentRequestCallback();
        attachmentRequestCallback.setAttachmentId(attachmentId);

        try {
            attachmentCallbackHandler.handle(new Callback[]{attachmentRequestCallback});

            List<Attachment> attachments = attachmentRequestCallback.getAttachments();
            if (attachments == null || attachments.isEmpty() 
                || !attachmentId.equals(attachments.get(0).getId())) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.INVALID_SECURITY,
                    "empty", new Object[] {"Attachment not found"}
                );
            }
            Attachment attachment = attachments.get(0);
            InputStream inputStream = attachment.getSourceStream();

            return JavaUtils.getBytesFromStream(inputStream);
        } catch (UnsupportedCallbackException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
        } catch (IOException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, e);
        }
    }

}
