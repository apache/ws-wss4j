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

package org.apache.ws.security.message.token;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.keys.content.x509.XMLX509SKI;
import org.apache.xml.security.utils.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Text;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.namespace.QName;
import java.security.cert.X509Certificate;


/**
 * Security Token Reference.
 * <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class SecurityTokenReference {
	private static Log log = LogFactory.getLog(SecurityTokenReference.class.getName());
	private static Log tlog =
		LogFactory.getLog("org.apache.ws.security.TIME");

	
    public static final QName TOKEN = new QName(WSConstants.WSSE_NS, "SecurityTokenReference");
    protected Element element = null;
    
    private boolean doDebug = false;

    /**
     * Constructor.
     * <p/>
     * 
     * @param elem 
     * @throws WSSecurityException 
     */
    public SecurityTokenReference(Element elem) throws WSSecurityException {
		doDebug = log.isDebugEnabled();
        this.element = elem;
        QName el = new QName(this.element.getNamespaceURI(), this.element.getLocalName());
        if (!el.equals(TOKEN)) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "badElement", new Object[]{TOKEN, el});
        }
    }

    /**
     * Constructor.
     * <p/>
     * 
     * @param doc 
     */
    public SecurityTokenReference(Document doc) {
		doDebug = log.isDebugEnabled();
        this.element = doc.createElementNS(WSConstants.WSSE_NS, "wsse:SecurityTokenReference");
    }

    /**
     * set the reference.
     * <p/>
     * 
     * @param ref 
     */
    public void setReference(Reference ref) {
        Element elem = getFirstElement();
        if (elem != null) {
            this.element.replaceChild(ref.getElement(), elem);
        } else {
            this.element.appendChild(ref.getElement());
        }
    }

    /**
     * Gets the Reference.
     * 
     * @return	the <code>Reference</code> element contained in this
     * 			SecurityTokeneReference
     * @throws WSSecurityException 
     */
    public Reference getReference() throws WSSecurityException {
        Element elem = getFirstElement();
        return (elem == null) ? null : new Reference(elem);
    }

    /**
     * Sets the KeyIdentifer Element as a X509 certificate.
     * Takes a X509 certificate, converts its data into base 64 and inserts
     * it into a <code>wsse:KeyIdentifier</code> element, which is placed
     * in the <code>wsse:SecurityTokenReference</code> element.
     * 
     * @param cert is the X509 certficate to be inserted as key identifier
     */
    public void setKeyIdentifier(X509Certificate cert) throws Exception {
        Document doc = this.element.getOwnerDocument();
        byte data[] = cert.getEncoded();
        Text certText = doc.createTextNode(Base64.encode(data));
        Element keyId = doc.createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
		keyId.setAttributeNS(null, "ValueType", "wsse:X509v3");
		keyId.setAttributeNS(null, "EncodingType", "wsse:Base64Binary");
        keyId.appendChild(certText);
        Element elem = getFirstElement();
        if (elem != null) {
            this.element.replaceChild(keyId, elem);
        } else {
            this.element.appendChild(keyId);
        }
    }
	/**
	 * Sets the KeyIdentifer Element as a X509 Subject-Key-Identifier (SKI).
	 * Takes a X509 certificate, gets it SKI data, converts into base 64 and
	 * inserts it into a <code>wsse:KeyIdentifier</code> element, which is placed
	 * in the <code>wsse:SecurityTokenReference</code> element.
	 * 
	 * @param cert is the X509 certficate to get the SKI
	 */
	public void setKeyIdentifierSKI(X509Certificate cert) throws Exception {
		Document doc = this.element.getOwnerDocument();
		byte data[] = XMLX509SKI.getSKIBytesFromCert(cert);
		org.w3c.dom.Text skiText = doc.createTextNode(Base64.encode(data));
		Element keyId = doc.createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
		keyId.setAttributeNS(null, "ValueType", "wsse:X509SubjectKeyIdentifier");
		keyId.setAttributeNS(null, "EncodingType", "wsse:Base64Binary");
		keyId.appendChild(skiText);
		Element elem = getFirstElement();
		if (elem != null) {
			this.element.replaceChild(keyId, elem);
		} else {
			this.element.appendChild(keyId);
		}
	}

	/**
	 * Gets the KeyIdentifer.
	 * Only supports X509 certificates as key identifiers. Other
	 * types may follow, for example SKI (Subject Key Identifier)
	 * 
	 * @return the {@link BinarySecurity} containing the X509
	 * 			certificate or zero if a unknown key identifier
	 * 			type was detected.
	 */
	public BinarySecurity getKeyIdentifier(Crypto crypto) throws Exception {
		X509Security cert = null;
		Element elem = getFirstElement();
		String value = elem.getAttribute("ValueType");
		if (value.equals("wsse:X509v3")) {
			cert = new X509Security(elem);
		}
		else if (value.equals("wsse:X509SubjectKeyIdentifier")) {
			cert = getCertFromSKI(elem, crypto);
		}
		return cert;
	}
	
	private X509Security getCertFromSKI(Element elem, Crypto crypto) throws Exception {
		
		if (doDebug) {
			log.debug("getCertFromSKI: enter");
		}
		X509Security found = null;
		
		byte[] skiBytes = null;
		Node node = elem.getFirstChild();
		if (node == null) {
			return null;
		}
		if (node.getNodeType() == Node.TEXT_NODE) {
			try {
				skiBytes = Base64.decode(((Text) node).getData());
			} catch (Exception e) {
				return null;
			}
		}
		if (doDebug) {
			log.debug("Cert SKI: got SKI bytes");
		}
		NodeList nl =
			elem.getOwnerDocument().getElementsByTagNameNS(
				WSConstants.WSSE_NS,
				"BinarySecurityToken");

		int nlLength = nl.getLength();
		for (int i = 0; i < nlLength; i++) {
			if (doDebug) {
				log.debug("Cert SKI: processing BST " + i);
			}
			X509Security token = null;
			Element bstElement = (Element)nl.item(i);
			String value = bstElement.getAttribute("ValueType");
			if (!value.equals("wsse:X509v3")
				|| ((token = new X509Security(bstElement)) == null)) {
				continue;
			}
			X509Certificate cert = token.getX509Certificate(crypto);
			if (cert == null) {
				continue;
			}
			if (doDebug) {
				log.debug("Cert SKI: got cert from BST");
			}			
			byte data[] = XMLX509SKI.getSKIBytesFromCert(cert);
			if (data.length != skiBytes.length) {
				continue;
			}
			if (doDebug) {
				log.debug("Cert SKI: got SKI bytes from embedded cert");
			}			
			for (int ii = 0; ii < data.length; ii++) {
				if (data[ii] != skiBytes[ii]) {
					continue;
				}
			}
			if (doDebug) {
				log.debug("Cert SKI: found embedded BST");
			}
			found = token;
		}
		return found;
	}
	
    /**
     * Sets the X509 IssuerSerial data.
     * 
     * @param ref	the {@link XMLX509IssuerSerial} to put into this
     * 				SecurityTokenReference
     */
    public void setX509IssuerSerial(XMLX509IssuerSerial ref) {
        Element elem = getFirstElement();
        if (elem != null) {
            this.element.replaceChild(ref.getElement(), elem);
        } else {
            this.element.appendChild(ref.getElement());
        }
    }

    /**
     * Gets the X509 issuerSerial data.
     * 
     * @return a new {@link XMLX509IssuerSerial} initialized with serian number
     * 			and issuer name of the element
     * @throws WSSecurityException 
     */
    public XMLX509IssuerSerial getX509IssuerSerial() throws Exception {
        Element elem = getFirstElement();
        return (elem == null) ? null : new XMLX509IssuerSerial(elem, "");
    }

    /**
     * get the first child element.
     * 
     * @return the first <code>Element</code> child node
     */
    private Element getFirstElement() {
        for (Node currentChild = this.element.getFirstChild();
             currentChild != null;
             currentChild = currentChild.getNextSibling()) {
            if (currentChild instanceof Element) {
                return (Element) currentChild;
            }
        }
        return null;
    }

    /**
     * Method containsReference
     * 
     * @return 	true if the <code>SecurtityTokenReference</code> contains 
     * 			a <code>wsse:Reference</code> element
     */
    public boolean containsReference() {
        return this.lengthReference() > 0;
    }

    /**
     * Method lengthReference.
     * 
     * @return 	number of <code>wsse:Reference</code> elements in
	 *			the <code>SecurtityTokenReference</code> 
     */
    public int lengthReference() {
        return this.length(WSConstants.WSSE_NS, "Reference");
    }

   /**
    * Method containsX509IssuerSerial
    * 
	* @return 	true if the <code>SecurtityTokenReference</code> contains 
	* 			a <code>ds:IssuerSerial</code> element
	*/
    public boolean containsX509IssuerSerial() {
        return this.lengthX509IssuerSerial() > 0;
    }

    /**
     * Method lengthX509IssuerSerial.
     * 
 	* @return 	number of <code>ds:IssuerSerial</code> elements in
	* 			the <code>SecurtityTokenReference</code> 
    */
    public int lengthX509IssuerSerial() {
        return this.length(WSConstants.SIG_NS, "X509IssuerSerial");
    }

	/**
	 * Method containsKeyIdentifier.
	* 
	* @return 	true if the <code>SecurtityTokenReference</code> contains 
	* 			a <code>wsse:KeyIdentifier</code> element
	*/
	public boolean containsKeyIdentifier() {
		return this.lengthKeyIdentifier() > 0;
	}

	/**
	 * Method lengthKeyIdentifier.
	 * 
	* @return 	number of <code>wsse:KeyIdentifier</code> elements in
	* 			the <code>SecurtityTokenReference</code> 
	 */
	public int lengthKeyIdentifier() {
		return this.length(WSConstants.WSSE_NS, "KeyIdentifier");
	}

    /**
     * Method length.
     * 
     * @param namespace 
     * @param localname 
     * @return number of elements with matching localname and namespace
     */
    public int length(String namespace, String localname) {
        NodeList childNodes = this.element.getChildNodes();
        int maxLength = childNodes.getLength();
        int result = 0;
        for (int i = 0; i < maxLength; i++) {
            Node n = childNodes.item(i);
            if (n.getNodeType() == Node.ELEMENT_NODE) {
                String ns = n.getNamespaceURI();
                String name = n.getLocalName();
                if (((namespace != null) && (ns != null) && namespace.equals(ns))
                        || ((namespace == null) && (ns == null))) {
                    if (localname.equals(name)) {
                        result++;
                    }
                }
            }
        }
        return result;
    }

    /**
     * get the dom element.
     * <p/>
     * 
     * @return 
     */
    public Element getElement() {
        return this.element;
    }

    /**
     * get the id.
     * <p/>
     * 
     * @return 
     */
    public String getID() {
        return this.element.getAttributeNS(WSConstants.WSU_NS, "Id");
    }

    /**
     * set the id.
     * <p/>
     * 
     * @param id 
     */
    public void setID(String id) {
        this.element.setAttributeNS(WSConstants.WSU_NS, "wsu:Id", id);
    }

    /**
     * return the string representation.
     * <p/>
     * 
     * @return 
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }
}
