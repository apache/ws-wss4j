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

package org.apache.ws.security.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.SOAP11Constants;
import org.apache.ws.security.SOAP12Constants;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.xml.security.utils.Base64;
import org.apache.xpath.XPathAPI;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import java.util.Vector;
import java.security.InvalidKeyException;
import java.security.NoSuchProviderException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.namespace.QName;
import javax.xml.transform.TransformerException;

/**
 * WS-Security Utility methods.
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class WSSecurityUtil {
    private static Log log = LogFactory.getLog(WSSecurityUtil.class);
    private static boolean doDebug = false;
    
	static {
		doDebug = log.isDebugEnabled();
	}

    /**
     * Returns the first WS-Security header element for a given actor. 
     * Only one WS-Security header is allowed for an actor.
     * 
     * @param doc   
     * @param actor 
     * @return 	the <code>wsse:Security</code> element or 
     * 			<code>null</code> if not such element found
     */
    public static Element getSecurityHeader(Document doc, String actor, SOAPConstants sc) {
		Element soapHeaderElement =
			(Element) getDirectChild(doc.getFirstChild(),
				sc.getHeaderQName().getLocalPart(),
				sc.getEnvelopeURI());
        if (soapHeaderElement == null) { // no SOAP header at all
            return null;
        }

        // get all wsse:Security nodes
        NodeList list = soapHeaderElement.getElementsByTagNameNS(WSConstants.WSSE_NS, WSConstants.WSSE_LN);
        int len = list.getLength();
        Element elem;
        Attr attr;
        String hActor;
        for (int i = 0; i < len; i++) {
            elem = (Element) list.item(i);
            attr = elem.getAttributeNodeNS(sc.getEnvelopeURI(), sc.getRoleAttributeQName().getLocalPart());
            hActor = (attr != null) ? attr.getValue() : null;
            if (WSSecurityUtil.isActorEqual(actor, hActor)) {
                return elem;
            }
        }
        return null;
    }
 
 	/**
 	 * Compares two actor strings and returns true if these are equal.
 	 * Takes care of the null length strings and uses ignore case.
 	 *  
 	 * @param actor
 	 * @param hActor
 	 * @return
 	 */
    public static boolean isActorEqual(String actor, String hActor) {
		if ((((hActor == null) || (hActor.length() == 0))
			&& ((actor == null) || (actor.length() == 0)))
			|| ((hActor != null)
				&& (actor != null)
				&& hActor.equalsIgnoreCase(actor))) {
			return true;
		} else {
			return false;
		}
    }

    /**
     * Gets a direct child with specified localname and namespace.
     * <p/>
     * 
     * @param fNode     	the node where to start the search
     * @param localName 	local name of the child to get
     * @param namespace 	the namespace of the child to get
     * @return the node or <code>null</code> if not such node found
     */
    public static Node getDirectChild(Node fNode, String localName, String namespace) {
        for (Node currentChild = fNode.getFirstChild();
             currentChild != null;
             currentChild = currentChild.getNextSibling()) {
            if (localName.equals(currentChild.getLocalName()) &&
                    namespace.equals(currentChild.getNamespaceURI())) {
                return currentChild;
            }
        }
        return null;
    }

    /**
     * return the first soap "Body" element.
     * <p/>
     * 
     * @param doc 
     * @return 	the body element or <code>null</code> if document doe not
     * 			contain a SOAP body
     */
    public static Element findBodyElement(Document doc, SOAPConstants sc) {
		Element soapBodyElement =
			(Element) WSSecurityUtil.getDirectChild(
				doc.getFirstChild(),
				sc.getBodyQName().getLocalPart(),
				sc.getEnvelopeURI());
        return soapBodyElement;
    }

	/**
	 * Returns the first element that matches <code>name</code> and 
	 * <code>namespace</code>.
	 * <p/>
	 * This is a replacement for a XPath lookup <code>//name</code> with
	 * the given namespace. It's somewhat faster than XPath, and we do
	 * not deal with prefixes, just with the real namespace URI  
	 * 
	 * @param startNode		Where to start the search
	 * @param name			Local name of the element
	 * @param namespace		Namespace URI of the element
	 * @return				The found element or <code>null</code>
	 */
	public static Node findElement(Node startNode, String name, String namespace) {

		/*
		 * Replace the formely recursive implementation
		 * with a depth-first-loop lookup
		 */
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
     * set the namespace if it is not set already.
     * <p/>
     * 
     * @param element   
     * @param namespace 
     * @param prefix    
     * @return 
     */
    public static String setNamespace(Element element, String namespace, String prefix) {
        String pre = getPrefixNS(namespace, element);
        if (pre != null) {
            return pre;
        }
        element.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:" + prefix, namespace);
        return prefix;
    }

    /* ** The following methods were copied over from aixs.utils.XMLUtils and adapted */

    public static String getPrefixNS(String uri, Node e) {
        while (e != null && (e.getNodeType() == Element.ELEMENT_NODE)) {
            NamedNodeMap attrs = e.getAttributes();
            for (int n = 0; n < attrs.getLength(); n++) {
                Attr a = (Attr) attrs.item(n);
                String name;
                if ((name = a.getName()).startsWith("xmlns:") &&
                        a.getNodeValue().equals(uri)) {
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
                attr = ((Element) e).getAttributeNodeNS(WSConstants.XMLNS_NS,
                        prefix);
            }
            if (attr != null) return attr.getValue();
            e = e.getParentNode();
        }
        return null;
    }

    /**
     * Return a QName when passed a string like "foo:bar" by mapping
     * the "foo" prefix to a namespace in the context of the given Node.
     * 
     * @return a QName generated from the given string representation
     */
    public static QName getQNameFromString(String str, Node e) {
        return getQNameFromString(str, e, false);
    }

    /**
     * Return a QName when passed a string like "foo:bar" by mapping
     * the "foo" prefix to a namespace in the context of the given Node.
     * If default namespace is found it is returned as part of the QName.
     * 
     * @return a QName generated from the given string representation
     */
    public static QName getFullQNameFromString(String str, Node e) {
        return getQNameFromString(str, e, true);
    }

    private static QName getQNameFromString(String str, Node e, boolean defaultNS) {
        if (str == null || e == null)
            return null;
        int idx = str.indexOf(':');
        if (idx > -1) {
            String prefix = str.substring(0, idx);
            String ns = getNamespace(prefix, e);
            if (ns == null)
                return null;
            return new QName(ns, str.substring(idx + 1));
        } else {
            if (defaultNS) {
                String ns = getNamespace(null, e);
                if (ns != null)
                    return new QName(ns, str);
            }
            return new QName("", str);
        }
    }

    /**
     * Return a string for a particular QName, mapping a new prefix
     * if necessary.
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
            e.setAttributeNS(WSConstants.XMLNS_NS,
                    "xmlns:" + prefix, uri);
        }
        return prefix + ":" + qname.getLocalPart();
    }
    /* ** up to here */
    
    /**
     * Search for an element given its wsu:id.
     * <p/>
     * 
     * @param doc 
     * @param id  
     * @return 
     */
    public static Element getElementByWsuId(Document doc, String id) {
        if (id == null) {
            return null;
        }
        id = id.trim();
        if ((id.length() == 0) || (id.charAt(0) != '#')) {
            return null;
        }
        id = id.substring(1);
        try {
            Element nscontext = org.apache.xml.security.utils.XMLUtils.createDSctx(doc, "wsu", WSConstants.WSU_NS);
			Element element = (Element) XPathAPI.selectSingleNode(doc, "//*[@wsu:Id='" + id + "']", nscontext);
			return element;
        } catch (TransformerException ex) {
            log.error(ex);
        }
        return null;
    }

	/**
	 * Search for an element given its generic id.
	 * <p/>
	 * 
	 * @param doc 
	 * @param id  
	 * @return 
	 */
	public static Element getElementByGenId(Document doc, String id) {
		if (id == null) {
			return null;
		}
		id = id.trim();
		if ((id.length() == 0) || (id.charAt(0) != '#')) {
			return null;
		}
		id = id.substring(1);
		try {
			Element element = (Element) XPathAPI.selectSingleNode(doc, "//*[@Id='" + id + "']");
			return element;
		} catch (TransformerException ex) {
			log.error(ex);
		}
		return null;
	}
    /**
     * Create a BinarySecurityToken element
     * <p/>
     * 
     * @param doc      
     * @param wsuIdVal 
     * @return 
     */
    public static Element createBinarySecurityToken(Document doc, String wsuIdVal) {
        Element retVal = doc.createElementNS(WSConstants.WSSE_NS, "wsse:BinarySecurityToken");
        retVal.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:wsu", WSConstants.WSU_NS);
        retVal.setAttributeNS(WSConstants.WSU_NS, "wsu:Id", wsuIdVal);
        retVal.setAttributeNS(null, "ValueType", X509Security.TYPE);
        retVal.setAttributeNS(null, "EncodingType", BinarySecurity.BASE64_ENCODING);
        return retVal;
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

    /**
     * find a child element with given namespace and local name
     * <p/>
     * 
     * @param parent       
     * @param namespaceUri 
     * @param localName    
     * @return 
     */
    private static Element findChildElement(Element parent, String namespaceUri, String localName) {
        NodeList children = parent.getChildNodes();
        int len = children.getLength();
        for (int i = 0; i < len; i++) {
            Node child = children.item(i);
            if (child.getNodeType() == Node.ELEMENT_NODE) {
                Element elementChild = (Element) child;
                if (namespaceUri.equals(elementChild.getNamespaceURI()) && localName.equals(elementChild.getLocalName())) {
                    return elementChild;
                }
            }
        }
        return null;
    }

    /**
     * append a child element
     * <p/>
     * 
     * @param doc    
     * @param parent 
     * @param child  
     * @return 
     */
    public static Element appendChildElement(Document doc, Element parent, Element child) {
        Node whitespaceText = doc.createTextNode("\n");
        parent.appendChild(whitespaceText);
        parent.appendChild(child);
        return child;
    }

    /**
     * prepend a child element
     * <p/>
     * 
     * @param doc           
     * @param parent        
     * @param child         
     * @param addWhitespace 
     * @return 
     */
    public static Element prependChildElement(Document doc, Element parent, Element child, boolean addWhitespace) {
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
     * find the ws-security header block
     * <p/>
     * 
     * @param doc      
     * @param envelope 
     * @param doCreate 
     * @return 
     */
    public static Element findWsseSecurityHeaderBlock(Document doc, Element envelope, boolean doCreate) {
    	SOAPConstants sc = getSOAPConstants(envelope);
        Element header = findChildElement(envelope, sc.getEnvelopeURI(), sc.getHeaderQName().getLocalPart());
        if (header == null) {
            if (doCreate) {
                header = createElementInSameNamespace(envelope, sc.getHeaderQName().getLocalPart());
                header = prependChildElement(doc, envelope, header, true);
            }
        }
        Element wsseSecurity = findChildElement(header, WSConstants.WSSE_NS, "Security");
        if (wsseSecurity != null) {
            return wsseSecurity;
        }
        if (doCreate) {
            wsseSecurity = header.getOwnerDocument().createElementNS(WSConstants.WSSE_NS, "wsse:Security");
            wsseSecurity.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:wsse", WSConstants.WSSE_NS);
            return prependChildElement(doc, header, wsseSecurity, true);
        }
        return null;
    }

    /**
     * create a base64 test node
     * <p/>
     * 
     * @param doc  
     * @param data 
     * @return 
     */
    public static Text createBase64EncodedTextNode(Document doc, byte data[]) {
        return doc.createTextNode(Base64.encode(data));
    }

    /**
     * use xpath to find a node
     * <p/>
     * 
     * @param contextNode 
     * @param xpath       
     * @param nsContext   
     * @return 
     * @throws Exception 
     */
    public static Node selectSingleNode(Node contextNode, String xpath, Element nsContext) throws Exception {
        try {
            return XPathAPI.selectSingleNode(contextNode, xpath, nsContext);
        } catch (TransformerException e) {
            throw new Exception("Unable to resolve XPath");
        }
    }

    /**
     * Create a namespace context with namespaces of interest
     * 
     * @param doc 
     * @return 
     */
    public static Element createNamespaceContext(Document doc) {
		SOAPConstants sc = getSOAPConstants(doc.getDocumentElement());
        Element nsContext = doc.createElementNS(null, "namespaceContext");
        nsContext.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:env", sc.getEnvelopeURI());
        nsContext.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:wsse", WSConstants.WSSE_NS);
        nsContext.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:wsu", WSConstants.WSU_NS);
        nsContext.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:ds", WSConstants.SIG_NS);
        nsContext.setAttributeNS(WSConstants.XMLNS_NS, "xmlns:xenc", WSConstants.ENC_NS);
        return nsContext;
    }
    
    public static SecretKey prepareSecretKey (String symEncAlgo, byte[] rawKey) throws WSSecurityException {
    	SecretKey symmetricKey = null;
		if (symEncAlgo.equalsIgnoreCase(WSConstants.TRIPLE_DES)) {
			try {
				DESedeKeySpec keySpec = new DESedeKeySpec(rawKey);
				SecretKeyFactory keyFactory =
					SecretKeyFactory.getInstance("DESede");
				symmetricKey = keyFactory.generateSecret(keySpec);
			} catch (InvalidKeyException e) {
				throw new WSSecurityException(
					WSSecurityException.UNSUPPORTED_ALGORITHM,
					"unsupportedSymKey",
					new Object[] { "Invalid key for: " + symEncAlgo });
			} catch (NoSuchAlgorithmException e) {
				throw new WSSecurityException(
					WSSecurityException.UNSUPPORTED_ALGORITHM,
					"unsupportedSymKey",
					new Object[] { "No such algorithm: " + symEncAlgo });
			} catch (InvalidKeySpecException e) {
				throw new WSSecurityException(
					WSSecurityException.UNSUPPORTED_ALGORITHM,
					"unsupportedSymKey",
					new Object[] { "Invalid key spec for: " + symEncAlgo });
			}
		} else if (symEncAlgo.equalsIgnoreCase(WSConstants.AES_128)) {
			SecretKeySpec keySpec = new SecretKeySpec(rawKey, "AES128");
			symmetricKey = (SecretKey) keySpec;
		} else if (symEncAlgo.equalsIgnoreCase(WSConstants.AES_192)) {
			SecretKeySpec keySpec = new SecretKeySpec(rawKey, "AES192");
			symmetricKey = (SecretKey) keySpec;
		} else if (symEncAlgo.equalsIgnoreCase(WSConstants.AES_256)) {
			SecretKeySpec keySpec = new SecretKeySpec(rawKey, "AES256");
			symmetricKey = (SecretKey) keySpec;
		}
    	return symmetricKey;
    }
    	
    public static SOAPConstants getSOAPConstants(Element startElement) {
    	if (getPrefixNS(WSConstants.URI_SOAP12_ENV, startElement) != null) {
    		return new SOAP12Constants();
    	}
    	else {
    		return new SOAP11Constants();
    	}
    }

	public static Cipher getCiperInstance(String cipherAlgo)
		throws WSSecurityException {
		Cipher cipher = null;
		try {
			if (cipherAlgo.equalsIgnoreCase(WSConstants.KEYTRANSPORT_RSA15)) {
				cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING", "BC");
			} else if (
				cipherAlgo.equalsIgnoreCase(WSConstants.KEYTRANSPORT_RSAOEP)) {
				cipher = Cipher.getInstance("RSA/NONE/OAEPPADDING", "BC");
			} else {
				throw new WSSecurityException(
					WSSecurityException.UNSUPPORTED_ALGORITHM,
					"unsupportedKeyTransp",
					new Object[] { cipherAlgo });
			}
		} catch (NoSuchPaddingException ex) {
			throw new WSSecurityException(
				WSSecurityException.UNSUPPORTED_ALGORITHM,
				"unsupportedKeyTransp",
				new Object[] { "No such padding: " + cipherAlgo });
		} catch (NoSuchProviderException ex) {
			throw new WSSecurityException(
				WSSecurityException.UNSUPPORTED_ALGORITHM,
				"unsupportedKeyTransp",
				new Object[] { "no provider: "+ cipherAlgo });
		} catch (NoSuchAlgorithmException ex) {
			throw new WSSecurityException(
				WSSecurityException.UNSUPPORTED_ALGORITHM,
				"unsupportedKeyTransp",
				new Object[] { "No such algorithm: " + cipherAlgo });
		}
		return cipher;
	}

	/**
	 * Fetch the result of a given action from a given result vector 
	 * <p/>
	 * 
	 * @param wsResultVector    The result vector to fetch an action from
	 * @param action            The action to fetch 
	 * @return                  The result fetched from the result vector, null if the result could not be found 
	 */	
	public static WSSecurityEngineResult fetchActionResult(Vector wsResultVector, int action) {
		WSSecurityEngineResult wsResult = null;
		
		// Find the part of the security result that matches the given action
		
		for (int i = 0; i < wsResultVector.size(); i++) {
			// Check the result of every action whether it matches the given action
			if (((WSSecurityEngineResult)wsResultVector.get(i)).getAction() == action) {
				wsResult = (WSSecurityEngineResult)wsResultVector.get(i);
			}
		}
	
		return wsResult;
	}
}
