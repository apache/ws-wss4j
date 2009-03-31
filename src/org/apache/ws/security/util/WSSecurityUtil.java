/*
 * Copyright  2003-2006 The Apache Software Foundation, or their licensors, as
 * appropriate.
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

package org.apache.ws.security.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.SOAP11Constants;
import org.apache.ws.security.SOAP12Constants;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.namespace.QName;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Set;
import java.util.Vector;

/**
 * WS-Security Utility methods. <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class WSSecurityUtil {
    private static Log log = LogFactory.getLog(WSSecurityUtil.class);

    /**
     * A cached pseudo-random number generator
     * NB. On some JVMs, caching this random number
     * generator is required to overcome punitive
     * overhead.
     */
    private static SecureRandom random = null;
    private static String randomAlgorithm = null;
    
    /**
     * Returns the first WS-Security header element for a given actor. Only one
     * WS-Security header is allowed for an actor.
     * 
     * @param doc
     * @param actor
     * @deprecated use WSSecurityUtil.getSecurityHeader(Document, String) instead
     * @return the <code>wsse:Security</code> element or <code>null</code>
     *         if not such element found
     */
    public static Element getSecurityHeader(Document doc, String actor, SOAPConstants sc) {
        Element soapHeaderElement = 
            getDirectChildElement(
                doc.getDocumentElement(), 
                sc.getHeaderQName().getLocalPart(), 
                sc.getEnvelopeURI()
            );
        if (soapHeaderElement == null) { // no SOAP header at all
            return null;
        }

        // get all wsse:Security nodes
        NodeList list = 
            soapHeaderElement.getElementsByTagNameNS(WSConstants.WSSE_NS, WSConstants.WSSE_LN);
        if (list == null) {
            return null;
        }
        for (int i = 0; i < list.getLength(); i++) {
            Element elem = (Element) list.item(i);
            Attr attr = 
                elem.getAttributeNodeNS(
                    sc.getEnvelopeURI(), sc.getRoleAttributeQName().getLocalPart()
                );
            String hActor = (attr != null) ? attr.getValue() : null;
            if (WSSecurityUtil.isActorEqual(actor, hActor)) {
                return elem;
            }
        }
        return null;
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
    public static Element getSecurityHeader(Document doc, String actor) {
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

        // get all wsse:Security nodes
        NodeList list = 
            soapHeaderElement.getElementsByTagNameNS(WSConstants.WSSE_NS, WSConstants.WSSE_LN);
        if (list == null) {
            return null;
        }
        for (int i = 0; i < list.getLength(); i++) {
            Element elem = (Element) list.item(i);
            Attr attr = elem.getAttributeNodeNS(soapNamespace, actorLocal);
            String hActor = (attr != null) ? attr.getValue() : null;
            if (WSSecurityUtil.isActorEqual(actor, hActor)) {
                return elem;
            }
        }
        return null;
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
     * @param fNode the node where to start the search
     * @param localName local name of the child to get
     * @param namespace the namespace of the child to get
     * @deprecated see WSSecurityUtil#getDirectChildElement instead
     * @return the node or <code>null</code> if not such node found
     */
    public static Node getDirectChild(
        Node fNode, 
        String localName,
        String namespace
    ) {
        for (
            Node currentChild = fNode.getFirstChild(); 
            currentChild != null; 
            currentChild = currentChild.getNextSibling()
        ) {
            if (localName.equals(currentChild.getLocalName())
                && namespace.equals(currentChild.getNamespaceURI())) {
                return currentChild;
            }
        }
        return null;
    }
    
    /**
     * Gets a direct child with specified localname and namespace. <p/>
     * 
     * @param fNode the node where to start the search
     * @param localName local name of the child to get
     * @param namespace the namespace of the child to get
     * @return the node or <code>null</code> if not such node found
     */
    public static Element getDirectChildElement(
        Node fNode, 
        String localName,
        String namespace
    ) {
        for (
            Node currentChild = fNode.getFirstChild(); 
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
     * return the first soap "Body" element. <p/>
     * 
     * @deprecated use findBodyElement(Document) instead
     * @param doc
     * @return the body element or <code>null</code> if document does not
     *         contain a SOAP body
     */
    public static Element findBodyElement(Document doc, SOAPConstants sc) {
        Element soapBodyElement = 
            WSSecurityUtil.getDirectChildElement(
                doc.getFirstChild(), 
                sc.getBodyQName().getLocalPart(), 
                sc.getEnvelopeURI()
            );
        return soapBodyElement;
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
        String bodyNamespace = WSConstants.URI_SOAP11_ENV;
        if (WSConstants.URI_SOAP12_ENV.equals(ns)) {
            bodyNamespace = ns;
        }
        
        for (
            Node currentChild = docElement.getFirstChild(); 
            currentChild != null; 
            currentChild = currentChild.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()
                && WSConstants.ELEM_BODY.equals(currentChild.getLocalName())
                && bodyNamespace.equals(currentChild.getNamespaceURI())) {
                return (Element)currentChild;
            }
        }
        return null;
    }

    /**
     * Returns the first element that matches <code>name</code> and
     * <code>namespace</code>. <p/> This is a replacement for a XPath lookup
     * <code>//name</code> with the given namespace. It's somewhat faster than
     * XPath, and we do not deal with prefixes, just with the real namespace URI
     * 
     * @param start Node Where to start the search
     * @param name Local name of the element
     * @param namespace Namespace URI of the element
     * @return The found element or <code>null</code>
     */
    public static Node findElement(Node startNode, String name, String namespace) {
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
                    return startNode;
                }

                if ((namespace == null || namespace.length() == 0)
                    && (ns == null || ns.length() == 0)) {
                    return startNode;
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
     * Returns the single element that contains an Id with value
     * <code>uri</code> and <code>namespace</code>. <p/> This is a
     * replacement for a XPath Id lookup with the given namespace. It's somewhat
     * faster than XPath, and we do not deal with prefixes, just with the real
     * namespace URI
     * 
     * If there are multiple elements, we log a warning and return null as this
     * can be used to get around the signature checking.
     * 
     * @param startNode Where to start the search
     * @param value Value of the Id attribute
     * @param namespace Namespace URI of the Id
     * @return The found element if there was exactly one match, or
     *         <code>null</code> otherwise
     */
    public static Element findElementById(Node startNode, String value, String namespace) {
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
                if (se.hasAttributeNS(namespace, "Id")
                    && value.equals(se.getAttributeNS(namespace, "Id"))) {
                    if (foundElement == null) {
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
                    return name.substring(6);
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

    /* up to here */

    /**
     * Search for an element given its wsu:id. <p/>
     * 
     * @param doc the DOM document (SOAP request)
     * @param id the Id of the element
     * @return the found element or null if no element with the Id exists
     */
    public static Element getElementByWsuId(Document doc, String id) {
        if (id == null) {
            return null;
        }
        id = getIDFromReference(id);
        return WSSecurityUtil.findElementById(doc.getDocumentElement(), id, WSConstants.WSU_NS);
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
     * Turn a reference (eg "#5") into an ID (eg "5").
     * 
     * @param ref
     * @return ref trimmed and with the leading "#" removed, or null if not
     *         correctly formed
     * @deprecated use getIDFromReference instead
     */
    public static String getIDfromReference(String ref) {
        return getIDFromReference(ref);
    }

    /**
     * Search for an element given its generic id. <p/>
     * 
     * @param doc the DOM document (SOAP request)
     * @param id the Id of the element
     * @return the found element or null if no element with the Id exists
     */
    public static Element getElementByGenId(Document doc, String id) {
        if (id == null) {
            return null;
        }
        id = id.trim();
        if (id.length() == 0) {
            return null;
        }
        if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        return WSSecurityUtil.findElementById(doc.getDocumentElement(), id, null);
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
     * append a child element <p/>
     * 
     * @param doc the DOM document (SOAP request)
     * @param parent element of this child element
     * @param child the element to append
     * @deprecated use {@link Node#appendChild(Node)} instead
     * @return the child element
     */
    public static Element appendChildElement(
        Document doc, 
        Element parent,
        Element child
    ) {
        Node whitespaceText = doc.createTextNode("\n");
        parent.appendChild(whitespaceText);
        parent.appendChild(child);
        return child;
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
            parent.appendChild(child);
        } else {
            parent.insertBefore(child, firstChild);
        }
        return child;
    }

    /**
     * prepend a child element <p/>
     * 
     * @param doc the DOM document (SOAP request)
     * @param parent element of this child element
     * @param child the element to append
     * @param addWhitespace if true prepend a newline before child
     * @deprecated use {@link WSSecurityUtil#prependChildElement(Element, Element)}
     * instead
     * @return the child element
     */
    public static Element prependChildElement(
        Document doc, 
        Element parent,
        Element child, 
        boolean addWhitespace
    ) {
        Node firstChild = parent.getFirstChild();
        if (firstChild == null) {
            parent.appendChild(child);
        } else {
            parent.insertBefore(child, firstChild);
        }
        if (addWhitespace) {
            Node whitespaceText = doc.createTextNode("\n");
            parent.insertBefore(whitespaceText, child);
        }
        return child;
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
    ) {
        return findWsseSecurityHeaderBlock(doc, envelope, null, doCreate);
    }

    /**
     * find a ws-security header block for a given actor <p/>
     * 
     * @param doc the DOM document (SOAP request)
     * @param envelope the SOAP envelope
     * @param actot the actor (role) name of the WSS header
     * @param doCreate if true create a new WSS header block if none exists
     * @return the WSS header or null if none found and doCreate is false
     */
    public static Element findWsseSecurityHeaderBlock(
        Document doc,
        Element envelope, 
        String actor, 
        boolean doCreate
    ) {
        Element wsseSecurity = getSecurityHeader(doc, actor);
        if (wsseSecurity != null) {
            return wsseSecurity;
        }
        String soapNamespace = WSSecurityUtil.getSOAPNamespace(doc.getDocumentElement());
        Element header = 
            getDirectChildElement(envelope, WSConstants.ELEM_HEADER, soapNamespace);
        if (header == null && doCreate) {
            header = createElementInSameNamespace(envelope, WSConstants.ELEM_HEADER);
            header = prependChildElement(envelope, header);
        }
        if (doCreate) {
            wsseSecurity = 
                header.getOwnerDocument().createElementNS(WSConstants.WSSE_NS, "wsse:Security");
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

    public static SecretKey prepareSecretKey(String symEncAlgo, byte[] rawKey) {
        SecretKeySpec keySpec = 
            new SecretKeySpec(rawKey, JCEMapper.getJCEKeyAlgorithmFromURI(symEncAlgo));
        return (SecretKey) keySpec;
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
        Document doc = startElement.getOwnerDocument();
        String ns = doc.getDocumentElement().getNamespaceURI();
        if (WSConstants.URI_SOAP12_ENV.equals(ns)) {
            return ns;
        }
        return WSConstants.URI_SOAP11_ENV;
    }

    public static Cipher getCipherInstance(String cipherAlgo)
        throws WSSecurityException {
        Cipher cipher = null;
        try {
            if (WSConstants.KEYTRANSPORT_RSA15.equalsIgnoreCase(cipherAlgo)) {
                cipher = Cipher.getInstance("RSA/NONE/PKCS1PADDING");
            } else if (WSConstants.KEYTRANSPORT_RSAOEP.equalsIgnoreCase(cipherAlgo)) {
                cipher = Cipher.getInstance("RSA/NONE/OAEPPADDING");
            } else {
                throw new WSSecurityException(
                    WSSecurityException.UNSUPPORTED_ALGORITHM,
                    "unsupportedKeyTransp", new Object[] {cipherAlgo}
                );
            }
        } catch (NoSuchPaddingException ex) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, "unsupportedKeyTransp", 
                new Object[] { "No such padding: " + cipherAlgo }, ex
            );
        } catch (NoSuchAlgorithmException ex) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, "unsupportedKeyTransp",
                new Object[] { "No such algorithm: " + cipherAlgo }, ex
            );
        }
        return cipher;
    }

    /**
     * Fetch the result of a given action from a given result vector <p/>
     * 
     * @param wsResultVector The result vector to fetch an action from
     * @param action The action to fetch
     * @return The result fetched from the result vector, null if the result
     *         could not be found
     */
    public static WSSecurityEngineResult fetchActionResult(Vector wsResultVector, int action) {
        WSSecurityEngineResult wsResult = null;

        // Find the part of the security result that matches the given action
        for (int i = 0; i < wsResultVector.size(); i++) {
            // Check the result of every action whether it matches the given action
            WSSecurityEngineResult result = 
                (WSSecurityEngineResult) wsResultVector.get(i);
            int resultAction = 
                ((java.lang.Integer)result.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
            if (resultAction == action) {
                wsResult = (WSSecurityEngineResult) wsResultVector.get(i);
            }
        }

        return wsResult;
    }

    /**
     * Fetch the result of a given action from a given result vector <p/>
     * 
     * @param wsResultVector The result vector to fetch an action from
     * @param action The action to fetch
     * @param results where to store the found results data for the action
     * @return The result fetched from the result vector, null if the result
     *         could not be found
     */
    public static Vector fetchAllActionResults(
        Vector wsResultVector,
        int action, 
        Vector results
    ) {
        // Find the parts of the security result that matches the given action
        for (int i = 0; i < wsResultVector.size(); i++) {
            // Check the result of every action whether it matches the given
            // action
            WSSecurityEngineResult result = 
                (WSSecurityEngineResult) wsResultVector.get(i);
            int resultAction = 
                ((java.lang.Integer)result.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
            if (resultAction == action) {
                results.add(wsResultVector.get(i));
            }
        }
        return results;
    }

    public static int decodeAction(String action, Vector actions) throws WSSecurityException {

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
                actions.add(new Integer(WSConstants.UT));
            } else if (single[i].equals(WSHandlerConstants.SIGNATURE)) {
                doAction |= WSConstants.SIGN;
                actions.add(new Integer(WSConstants.SIGN));
            } else if (single[i].equals(WSHandlerConstants.ENCRYPT)) {
                doAction |= WSConstants.ENCR;
                actions.add(new Integer(WSConstants.ENCR));
            } else if (single[i].equals(WSHandlerConstants.SAML_TOKEN_UNSIGNED)) {
                doAction |= WSConstants.ST_UNSIGNED;
                actions.add(new Integer(WSConstants.ST_UNSIGNED));
            } else if (single[i].equals(WSHandlerConstants.SAML_TOKEN_SIGNED)) {
                doAction |= WSConstants.ST_SIGNED;
                actions.add(new Integer(WSConstants.ST_SIGNED));
            } else if (single[i].equals(WSHandlerConstants.TIMESTAMP)) {
                doAction |= WSConstants.TS;
                actions.add(new Integer(WSConstants.TS));
            } else if (single[i].equals(WSHandlerConstants.NO_SERIALIZATION)) {
                doAction |= WSConstants.NO_SERIALIZE;
                actions.add(new Integer(WSConstants.NO_SERIALIZE));
            } else if (single[i].equals(WSHandlerConstants.SIGN_WITH_UT_KEY)) {
                doAction |= WSConstants.UT_SIGN;
                actions.add(new Integer(WSConstants.UT_SIGN));
            } else {
                throw new WSSecurityException(
                    "Unknown action defined: " + single[i]
                );
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
        } else if (XMLSignature.ALGO_ID_MAC_HMAC_SHA1.equals(algorithm)) {
            return 20;
        } else if (XMLSignature.ALGO_ID_MAC_HMAC_SHA256.equals(algorithm)) {
            return 32;
        } else if (XMLSignature.ALGO_ID_MAC_HMAC_SHA384.equals(algorithm)) {
            return 48;
        } else if (XMLSignature.ALGO_ID_MAC_HMAC_SHA512.equals(algorithm)) {
            return 64;
        } else if (XMLSignature.ALGO_ID_MAC_HMAC_NOT_RECOMMENDED_MD5.equals(algorithm)) {
            return 16;
        } else {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, null
            );
        }
    }

    /**
     * Generate a nonce of the given length
     * 
     * @return a nonce of the given length
     * @throws Exception
     */
    public static byte[] generateNonce(int length) throws WSSecurityException {
        try {            
            final SecureRandom r = resolveSecureRandom();
            if (r == null) {
                throw new WSSecurityException("Random generator is not initialized.");
            }
            byte[] temp = new byte[length];            
            r.nextBytes(temp);
            return temp;
        } catch (Exception e) {
            throw new WSSecurityException(
                "Error in generating nonce of length " + length, e
            );
        }
    }

    /**
     * Search through a WSS4J results vector for a single signature covering all
     * these elements.
     * 
     * NOTE: it is important that the given elements are those that are 
     * referenced using wsu:Id. When the signed element is referenced using a
     * transformation such as XPath filtering the validation is carried out 
     * in signature verification itself.
     * 
     * @param results results (e.g., as stored as WSHandlerConstants.RECV_RESULTS on
     *                an Axis MessageContext)
     * @param elements the elements to check
     * @return the identity of the signer
     * @throws WSSecurityException if no suitable signature could be found or if any element
     *                             didn't have a wsu:Id attribute
     */
    public static X509Certificate ensureSignedTogether(Iterator results, Element[] elements) 
        throws WSSecurityException {
        log.debug("ensureSignedTogether()");

        if (results == null) {
            throw new IllegalArgumentException("No results vector");
        }
        if (elements == null || elements.length == 0) {
            throw new IllegalArgumentException("No elements to check!");
        }

        // Turn the list of required elements into a list of required wsu:Id
        // strings
        String[] requiredIDs = new String[elements.length];
        for (int i = 0; i < elements.length; i++) {
            Element e = (Element) elements[i];
            if (e == null) {
                throw new IllegalArgumentException("elements[" + i + "] is null!");
            }
            requiredIDs[i] = e.getAttributeNS(WSConstants.WSU_NS, "Id");
            if (requiredIDs[i] == null) {
                throw new WSSecurityException(
                    WSSecurityException.FAILED_CHECK,
                    "requiredElementNoID", 
                    new Object[] {e.getNodeName()}
                );
            }
            log.debug("Required element " + e.getNodeName() + " has wsu:Id " + requiredIDs[i]);
        }

        WSSecurityException fault = null;

        // Search through the results for a SIGN result
        while (results.hasNext()) {
            WSHandlerResult result = (WSHandlerResult) results.next();
            Iterator actions = result.getResults().iterator();

            while (actions.hasNext()) {
                WSSecurityEngineResult resultItem = 
                    (WSSecurityEngineResult) actions.next();
                int resultAction = 
                    ((java.lang.Integer)resultItem.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
                
                if (resultAction == WSConstants.SIGN) {
                    try {
                        checkSignsAllElements(resultItem, requiredIDs);
                        return 
                            (X509Certificate)resultItem.get(
                                WSSecurityEngineResult.TAG_X509_CERTIFICATE
                            );
                    } catch (WSSecurityException ex) {
                        // Store the exception but keep going... there may be a
                        // better signature later
                        log.debug("SIGN result does not sign all required elements", ex);
                        fault = ex;
                    }
                }
            }
        }

        if (fault != null)
            throw fault;

        throw new WSSecurityException(WSSecurityException.FAILED_CHECK, "noSignResult");
    }

    /**
     * Ensure that this signature covers all required elements (identified by
     * their wsu:Id attributes).
     * 
     * @param resultItem the signature to check
     * @param requiredIDs the list of wsu:Id values that must be covered
     * @throws WSSecurityException if any required element is not included
     */
    private static void checkSignsAllElements(
        WSSecurityEngineResult resultItem, 
        String[] requiredIDs
    ) throws WSSecurityException {
        int resultAction = 
            ((java.lang.Integer)resultItem.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
        if (resultAction != WSConstants.SIGN) {
            throw new IllegalArgumentException("Not a SIGN result");
        }

        Set sigElems = (Set)resultItem.get(WSSecurityEngineResult.TAG_SIGNED_ELEMENT_IDS);
        if (sigElems == null) {
            throw new RuntimeException(
                "Missing signedElements set in WSSecurityEngineResult!"
            );
        }

        log.debug("Found SIGN result...");
        for (Iterator i = sigElems.iterator(); i.hasNext();) {
            Object sigElement = i.next();
            if(sigElement instanceof String) {
                log.debug("Signature includes element with ID " + sigElement);
            } else {
                log.debug("Signature includes element with null uri " + sigElement.toString());
            }
        }

        log.debug("Checking required elements are in the signature...");
        for (int i = 0; i < requiredIDs.length; i++) {
            if (!sigElems.contains(requiredIDs[i])) {
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
     * @return      a SecureRandom instance initialized with the "SHA1PRNG"
     *              algorithm identifier
     */
    public static SecureRandom
    resolveSecureRandom() throws NoSuchAlgorithmException {
        return resolveSecureRandom("SHA1PRNG");
    }
    
    /**
     * @param       algorithm
     *              
     * @return      a SecureRandom instance initialized with the identifier
     *              specified in algorithm
     */
    public synchronized static SecureRandom
    resolveSecureRandom(
        final String algorithm
    ) throws NoSuchAlgorithmException {
        if (random == null || !algorithm.equals(randomAlgorithm)) {
            random = SecureRandom.getInstance(algorithm);
            randomAlgorithm = algorithm;
            random.setSeed(System.currentTimeMillis());
        }
        return random;
    }
    
    /**
     * @return  a list of child Nodes
     */
    public static java.util.List
    listChildren(
        final Node parent
    ) {
        if (parent == null) {
            return java.util.Collections.EMPTY_LIST;
        }
        final java.util.List ret = new java.util.ArrayList();
        if (parent.hasChildNodes()) {
            final NodeList children = parent.getChildNodes();
            if (children != null) {
                for (int i = 0, n = children.getLength();  i < n;  ++i) {
                    ret.add(children.item(i));
                }
            }
        }
        return ret;
    }
    
    /**
     * @return a list of Nodes in b that are not in a 
     */
    public static java.util.List
    newNodes(
        final java.util.List a,
        final java.util.List b
    ) {
        if (a.size() == 0) {
            return b;
        }
        if (b.size() == 0) {
            return java.util.Collections.EMPTY_LIST;
        }
        final java.util.List ret = new java.util.ArrayList();
        for (
            final java.util.Iterator bpos = b.iterator();
            bpos.hasNext();
        ) {
            final Node bnode = (Node) bpos.next();
            final java.lang.String bns = bnode.getNamespaceURI();
            final java.lang.String bln = bnode.getLocalName();
            boolean found = false;
            for (
                final java.util.Iterator apos = a.iterator();
                apos.hasNext() && !found;
            ) {
                final Node anode = (Node) apos.next();
                final java.lang.String ans = anode.getNamespaceURI();
                final java.lang.String aln = anode.getLocalName();
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
    
}
