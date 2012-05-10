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

package org.apache.ws.security.util;

import org.apache.ws.security.SOAP11Constants;
import org.apache.ws.security.SOAP12Constants;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDataRef;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.CallbackLookup;
import org.apache.xml.security.algorithms.JCEMapper;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.crypto.dom.DOMCryptoContext;
import javax.xml.namespace.QName;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

/**
 * WS-Security Utility methods. <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public final class WSSecurityUtil {
    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(WSSecurityUtil.class);

    /**
     * A cached pseudo-random number generator
     * NB. On some JVMs, caching this random number
     * generator is required to overcome punitive
     * overhead.
     */
    private static SecureRandom random = null;
    
    /**
     * A cached MessageDigest object
     */
    private static MessageDigest digest = null;
    
    private WSSecurityUtil() {
        // Complete
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
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        Element soapHeaderElement = 
            getDirectChildElement(
                doc.getDocumentElement(), 
                WSConstants.ELEM_HEADER, 
                soapNamespace
            );
        if (soapHeaderElement == null) { // no SOAP header at all
            return null;
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
            Node currentChild = soapHeaderElement.getFirstChild(); 
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
                        if (log.isDebugEnabled()) {
                            log.debug(
                                "Two or more security headers have the same actor name: " + actor
                            );
                        }
                        throw new WSSecurityException(WSSecurityException.INVALID_SECURITY);
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
        if (((hActor == null) || (hActor.length() == 0)) 
            && ((actor == null) || (actor.length() == 0))) {
            return true;
        }
        
        if ((hActor != null) && (actor != null) && hActor.equalsIgnoreCase(actor)) {
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
                if ((se.hasAttribute("ID") && value.equals(se.getAttribute("ID")))
                    || (se.hasAttribute("AssertionID") 
                        && value.equals(se.getAttribute("AssertionID")))) {
                    if (foundElement == null) {
                        foundElement = se; // Continue searching to find duplicates
                    } else {
                        log.warn("Multiple elements with the same 'ID' attribute value!");
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
     * If checkMultipleElements is true and there are multiple elements, we log a 
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
                        log.warn("Multiple elements with the same 'Id' attribute value!");
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
        while (e != null && (e.getNodeType() == Element.ELEMENT_NODE)) {
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
        while (e != null && (e.getNodeType() == Node.ELEMENT_NODE)) {
            Attr attr = null;
            if (prefix == null) {
                attr = ((Element) e).getAttributeNode("xmlns");
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
            String ns = getNamespace(prefix, e);
            if (ns == null) {
                return null;
            }
            return new QName(ns, str.substring(idx + 1));
        } else {
            if (defaultNS) {
                String ns = getNamespace(null, e);
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
            while (getNamespace(prefix, e) != null) {
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
        Element wsseSecurity = getSecurityHeader(doc, actor);
        if (wsseSecurity != null) {
            return wsseSecurity;
        } else if (doCreate) {
            String soapNamespace = WSSecurityUtil.getSOAPNamespace(envelope);
            Element header = 
                getDirectChildElement(envelope, WSConstants.ELEM_HEADER, soapNamespace);
            if (header == null) {
                header = createElementInSameNamespace(envelope, WSConstants.ELEM_HEADER);
                header = prependChildElement(envelope, header);
            }
            wsseSecurity = doc.createElementNS(WSConstants.WSSE_NS, "wsse:Security");
            wsseSecurity.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:wsse", WSConstants.WSSE_NS);
            return prependChildElement(header, wsseSecurity);
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
     * Convert the raw key bytes into a SecretKey object of type symEncAlgo.
     */
    public static SecretKey prepareSecretKey(String symEncAlgo, byte[] rawKey) {
        // Do an additional check on the keysize required by the encryption algorithm
        int size = 0;
        try {
            size = JCEMapper.getKeyLengthFromURI(symEncAlgo) / 8;
        } catch (Exception e) {
            // ignore - some unknown (to JCEMapper) encryption algorithm
            if (log.isDebugEnabled()) {
                log.debug(e.getMessage());
            }
        }
        String keyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(symEncAlgo);
        SecretKeySpec keySpec;
        if (size > 0) {
            keySpec = 
                new SecretKeySpec(
                    rawKey, 0, ((rawKey.length > size) ? size : rawKey.length), keyAlgorithm
                );
        } else {
            keySpec = new SecretKeySpec(rawKey, keyAlgorithm);
        }
        return (SecretKey)keySpec;
    }


    /**
     * Translate the "cipherAlgo" URI to a JCE ID, and return a javax.crypto.Cipher instance
     * of this type. 
     */
    public static Cipher getCipherInstance(String cipherAlgo)
        throws WSSecurityException {
        try {
            String keyAlgorithm = JCEMapper.translateURItoJCEID(cipherAlgo);
            return Cipher.getInstance(keyAlgorithm);
        } catch (NoSuchPaddingException ex) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, "unsupportedKeyTransp", 
                new Object[] { "No such padding: " + cipherAlgo }, ex
            );
        } catch (NoSuchAlgorithmException ex) {
            // Check to see if an RSA OAEP MGF-1 with SHA-1 algorithm was requested
            // Some JDKs don't support RSA/ECB/OAEPPadding
            if (WSConstants.KEYTRANSPORT_RSAOEP.equals(cipherAlgo)) {
                try {
                    return Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding");
                } catch (Exception e) {
                    throw new WSSecurityException(
                        WSSecurityException.UNSUPPORTED_ALGORITHM, "unsupportedKeyTransp",
                        new Object[] { "No such algorithm: " + cipherAlgo }, e
                    );
                }
            } else {
                throw new WSSecurityException(
                    WSSecurityException.UNSUPPORTED_ALGORITHM, "unsupportedKeyTransp",
                    new Object[] { "No such algorithm: " + cipherAlgo }, ex
                );
            }
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
                ((java.lang.Integer)result.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
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
     * @param actionResultList where to store the found results data for the action
     * @return The result fetched from the result list, null if the result
     *         could not be found
     */
    public static List<WSSecurityEngineResult> fetchAllActionResults(
        List<WSSecurityEngineResult> resultList,
        int action, 
        List<WSSecurityEngineResult> actionResultList
    ) {
        for (WSSecurityEngineResult result : resultList) {
            //
            // Check the result of every action whether it matches the given action
            //
            int resultAction = 
                ((java.lang.Integer)result.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
            if (resultAction == action) {
                actionResultList.add(result);
            }
        }
        return actionResultList;
    }

    public static int decodeAction(
        String action, 
        List<Integer> actions
    ) throws WSSecurityException {

        int doAction = 0;
        if (action == null) {
            return doAction;
        }
        String single[] = StringUtil.split(action, ' ');
        for (int i = 0; i < single.length; i++) {
            if (single[i].equals(WSHandlerConstants.NO_SECURITY)) {
                doAction = WSConstants.NO_SECURITY;
                return doAction;
            } else if (single[i].equals(WSHandlerConstants.USERNAME_TOKEN)) {
                doAction |= WSConstants.UT;
                actions.add(Integer.valueOf(WSConstants.UT));
            } else if (single[i].equals(WSHandlerConstants.USERNAME_TOKEN_NO_PASSWORD)) {
                doAction |= WSConstants.UT_NOPASSWORD;
                actions.add(Integer.valueOf(WSConstants.UT_NOPASSWORD));
            } else if (single[i].equals(WSHandlerConstants.SIGNATURE)) {
                doAction |= WSConstants.SIGN;
                actions.add(Integer.valueOf(WSConstants.SIGN));
            } else if (single[i].equals(WSHandlerConstants.ENCRYPT)) {
                doAction |= WSConstants.ENCR;
                actions.add(Integer.valueOf(WSConstants.ENCR));
            } else if (single[i].equals(WSHandlerConstants.SAML_TOKEN_UNSIGNED)) {
                doAction |= WSConstants.ST_UNSIGNED;
                actions.add(Integer.valueOf(WSConstants.ST_UNSIGNED));
            } else if (single[i].equals(WSHandlerConstants.SAML_TOKEN_SIGNED)) {
                doAction |= WSConstants.ST_SIGNED;
                actions.add(Integer.valueOf(WSConstants.ST_SIGNED));
            } else if (single[i].equals(WSHandlerConstants.TIMESTAMP)) {
                doAction |= WSConstants.TS;
                actions.add(Integer.valueOf(WSConstants.TS));
            } else if (single[i].equals(WSHandlerConstants.SIGN_WITH_UT_KEY)) {
                doAction |= WSConstants.UT_SIGN;
                actions.add(Integer.valueOf(WSConstants.UT_SIGN));
            } else if (single[i].equals(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION)) {
                doAction |= WSConstants.SC;
                actions.add(Integer.valueOf(WSConstants.SC));
            } else {
                throw new WSSecurityException(
                    "Unknown action defined: " + single[i]
                );
            }
        }
        return doAction;
    }
    
    
    /**
     * Decode an action String. This method should only be called on the outbound side.
     * @param action The initial String of actions to perform
     * @param actions The list of created actions that will be performed
     * @param wssConfig This object holds the list of custom actions to be performed.
     * @return The or'd integer of all the actions (apart from the custom actions)
     * @throws WSSecurityException
     */
    public static int decodeAction(
        String action, 
        List<Integer> actions,
        WSSConfig wssConfig
    ) throws WSSecurityException {

        int doAction = 0;
        if (action == null) {
            return doAction;
        }
        String single[] = StringUtil.split(action, ' ');
        for (int i = 0; i < single.length; i++) {
            if (single[i].equals(WSHandlerConstants.NO_SECURITY)) {
                doAction = WSConstants.NO_SECURITY;
                return doAction;
            } else if (single[i].equals(WSHandlerConstants.USERNAME_TOKEN)) {
                doAction |= WSConstants.UT;
                actions.add(Integer.valueOf(WSConstants.UT));
            } else if (single[i].equals(WSHandlerConstants.SIGNATURE)) {
                doAction |= WSConstants.SIGN;
                actions.add(Integer.valueOf(WSConstants.SIGN));
            } else if (single[i].equals(WSHandlerConstants.ENCRYPT)) {
                doAction |= WSConstants.ENCR;
                actions.add(Integer.valueOf(WSConstants.ENCR));
            } else if (single[i].equals(WSHandlerConstants.SAML_TOKEN_UNSIGNED)) {
                doAction |= WSConstants.ST_UNSIGNED;
                actions.add(Integer.valueOf(WSConstants.ST_UNSIGNED));
            } else if (single[i].equals(WSHandlerConstants.SAML_TOKEN_SIGNED)) {
                doAction |= WSConstants.ST_SIGNED;
                actions.add(Integer.valueOf(WSConstants.ST_SIGNED));
            } else if (single[i].equals(WSHandlerConstants.TIMESTAMP)) {
                doAction |= WSConstants.TS;
                actions.add(Integer.valueOf(WSConstants.TS));
            } else if (single[i].equals(WSHandlerConstants.SIGN_WITH_UT_KEY)) {
                doAction |= WSConstants.UT_SIGN;
                actions.add(Integer.valueOf(WSConstants.UT_SIGN));
            } else if (single[i].equals(WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION)) {
                doAction |= WSConstants.SC;
                actions.add(Integer.valueOf(WSConstants.SC));
            } else {
                try {
                    int parsedAction = Integer.parseInt(single[i]);
                    if (wssConfig.getAction(parsedAction) == null) {
                        throw new WSSecurityException(
                            "Unknown action defined: " + single[i]
                        );
                    }
                    actions.add(Integer.valueOf(parsedAction));
                } catch (NumberFormatException ex) {
                    throw new WSSecurityException(
                        "Unknown action defined: " + single[i]
                    );
                }
            }
        }
        return doAction;
    }

    /**
     * Returns the length of the key in # of bytes
     * 
     * @param algorithm
     * @return the key length
     */
    public static int getKeyLength(String algorithm) throws WSSecurityException {
        if (algorithm.equals(WSConstants.TRIPLE_DES)) {
            return 24;
        } else if (algorithm.equals(WSConstants.AES_128)) {
            return 16;
        } else if (algorithm.equals(WSConstants.AES_192)) {
            return 24;
        } else if (algorithm.equals(WSConstants.AES_256)) {
            return 32;
        } else if (WSConstants.HMAC_SHA1.equals(algorithm)) {
            return 20;
        } else if (WSConstants.HMAC_SHA256.equals(algorithm)) {
            return 32;
        } else if (WSConstants.HMAC_SHA384.equals(algorithm)) {
            return 48;
        } else if (WSConstants.HMAC_SHA512.equals(algorithm)) {
            return 64;
        } else if (WSConstants.HMAC_MD5.equals(algorithm)) {
            return 16;
        } else {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, null
            );
        }
    }

    /**
     * Generate a nonce of the given length using the SHA1PRNG algorithm. The SecureRandom
     * instance that backs this method is cached for efficiency.
     * 
     * @return a nonce of the given length
     * @throws WSSecurityException
     */
    public static synchronized byte[] generateNonce(int length) throws WSSecurityException {
        try {
            if (random == null) {
                random = SecureRandom.getInstance("SHA1PRNG");
            }
            byte[] temp = new byte[length];
            random.nextBytes(temp);
            return temp;
        } catch (Exception ex) {
            throw new WSSecurityException(
                "Error in generating nonce of length " + length, ex
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
            throw new WSSecurityException(
                "Error in generating digest", e
            );
        }
    }
    
    /**
     * Check that all of the QName[] requiredParts are protected by a specified action in the
     * results list.
     * @param results The List of WSSecurityEngineResults from processing
     * @param action The action that is required (e.g. WSConstants.SIGN)
     * @param requiredParts An array of QNames that correspond to the required elements
     */
    @SuppressWarnings("unchecked")
    public static void checkAllElementsProtected(
        List<WSSecurityEngineResult> results,
        int action,
        QName[] requiredParts
    ) throws WSSecurityException {
        
        if (requiredParts != null) {
            for (int i = 0; i < requiredParts.length; i++) {
                QName requiredPart = requiredParts[i];
                
                boolean found = false;
                for (Iterator<WSSecurityEngineResult> iter = results.iterator(); 
                    iter.hasNext() && !found;) {
                    WSSecurityEngineResult result = iter.next();
                    int resultAction = 
                        ((java.lang.Integer)result.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
                    if (resultAction != action) {
                        continue;
                    }
                    List<WSDataRef> refList = 
                        (List<WSDataRef>)result.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
                    if (refList != null) {
                        for (WSDataRef dataRef : refList) {
                            if (dataRef.getName().equals(requiredPart)) {
                                found = true;
                                break;
                            }
                        }
                    }
                }
                if (!found) {
                    throw new WSSecurityException(
                        WSSecurityException.FAILED_CHECK,
                        "requiredElementNotProtected",
                        new Object[] {requiredPart}
                    );
                }
            }
            log.debug("All required elements are protected");
        }
    }

    /**
     * Ensure that this covers all required elements (identified by
     * their wsu:Id attributes).
     * 
     * @param resultItem the signature to check
     * @param requiredIDs the list of wsu:Id values that must be covered
     * @throws WSSecurityException if any required element is not included
     */
    @SuppressWarnings("unchecked")
    public static void checkSignsAllElements(
        WSSecurityEngineResult resultItem, 
        String[] requiredIDs
    ) throws WSSecurityException {
        int resultAction = 
            ((java.lang.Integer)resultItem.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
        if (resultAction != WSConstants.SIGN) {
            throw new IllegalArgumentException("Not a SIGN result");
        }

        List<WSDataRef> signedElemsRefList = 
            (List<WSDataRef>)resultItem.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
        if (signedElemsRefList == null) {
            throw new WSSecurityException(
                "WSSecurityEngineResult does not contain any references to signed elements"
            );
        }

        log.debug("Checking required elements are in the signature...");
        for (int i = 0; i < requiredIDs.length; i++) {
            boolean found = false;
            for (int j = 0; j < signedElemsRefList.size(); j++) {
                WSDataRef dataRef = (WSDataRef)signedElemsRefList.get(j);
                String wsuId = dataRef.getWsuId();
                if (wsuId.charAt(0) == '#') {
                    wsuId = wsuId.substring(1);
                }
                if (wsuId.equals(requiredIDs[i])) {
                    found = true;
                }
            }
            if (!found) {
                throw new WSSecurityException(
                    WSSecurityException.FAILED_CHECK,
                    "requiredElementNotSigned",
                    new Object[] {requiredIDs[i]}
                );
            }
            log.debug("Element with ID " + requiredIDs[i] + " was correctly signed");
        }
        log.debug("All required elements are signed");
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
                    ? ((bns == null) ? true : false)
                    : ((bns == null) ? false : ans.equals(bns));
                final boolean lnmatch =
                    aln == null
                    ? ((bln == null) ? true : false)
                    : ((bln == null) ? false : aln.equals(bln));
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
     * "Id" attributes that matches the given uri
     */
    public static void storeElementInContext(
        DOMCryptoContext context, 
        String uri,
        Element element
    ) {
        String id = uri;
        if (uri.charAt(0) == '#') {
            id = id.substring(1);
        }
        
        if (element.hasAttributeNS(WSConstants.WSU_NS, "Id")
            && id.equals(element.getAttributeNS(WSConstants.WSU_NS, "Id"))) {
            context.setIdAttributeNS(element, WSConstants.WSU_NS, "Id");
        }
        if (element.hasAttributeNS(null, "Id")
            && id.equals(element.getAttributeNS(null, "Id"))) {
    	    context.setIdAttributeNS(element, null, "Id");
        }
        if (element.hasAttributeNS(null, "ID")
            && id.equals(element.getAttributeNS(null, "ID"))) {
            context.setIdAttributeNS(element, null, "ID");
        }
        if (element.hasAttributeNS(null, "AssertionID")
            && id.equals(element.getAttributeNS(null, "AssertionID"))) {
            context.setIdAttributeNS(element, null, "AssertionID");
        }
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
    
    public static void verifySignedElement(Element elem, Document doc, Element securityHeader)
        throws WSSecurityException {
        final Element envelope = doc.getDocumentElement();
        final Set<String> signatureRefIDs = getSignatureReferenceIDs(securityHeader);
        if (!signatureRefIDs.isEmpty()) {
            Node cur = elem;
            while (!cur.isSameNode(envelope)) {
                if (cur.getNodeType() == Node.ELEMENT_NODE) {
                    if (WSConstants.SIG_LN.equals(cur.getLocalName())
                        && WSConstants.SIG_NS.equals(cur.getNamespaceURI())) {
                        throw new WSSecurityException(WSSecurityException.FAILED_CHECK,
                            "requiredElementNotSigned", new Object[] {elem});
                    } else if (isLinkedBySignatureRefs((Element)cur, signatureRefIDs)) {
                        return;
                    }
                }
                cur = cur.getParentNode();
            }
        }
        throw new WSSecurityException(
            WSSecurityException.FAILED_CHECK, "requiredElementNotSigned", new Object[] {elem});
    }
    
    private static boolean isLinkedBySignatureRefs(Element elem, Set<String> allIDs) {
        // Try the wsu:Id first
        String attributeNS = elem.getAttributeNS(WSConstants.WSU_NS, "Id");
        if (!"".equals(attributeNS) && allIDs.contains(attributeNS)) {
            return true;
        }
        attributeNS = elem.getAttributeNS(null, "Id");
        return (!"".equals(attributeNS) && allIDs.contains(attributeNS));
    }
    
    private static Set<String> getSignatureReferenceIDs(Element wsseHeader) throws WSSecurityException {
        final Set<String> refs = new HashSet<String>();
        final List<Element> signatures = WSSecurityUtil.getDirectChildElements(wsseHeader, WSConstants.SIG_LN, WSConstants.SIG_NS);
        for (Element signature : signatures) {
            Element sigInfo = WSSecurityUtil.getDirectChildElement(signature, WSConstants.SIG_INFO_LN, WSConstants.SIG_NS);
            List<Element> references = WSSecurityUtil.getDirectChildElements(sigInfo, WSConstants.REF_LN, WSConstants.SIG_NS);
            for (Element reference : references) {
                String uri = reference.getAttributeNS(null, "URI");
                if (!"".equals(uri)) {
                    boolean added = refs.add(WSSecurityUtil.getIDFromReference(uri));
                    if (!added) {
                        log.warn("Duplicated reference uri: " + uri);
                    }
                }
            }
        }
        return refs;
    }
    
}
