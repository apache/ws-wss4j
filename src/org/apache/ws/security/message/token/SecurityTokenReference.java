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
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
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
	private static Log log =
		LogFactory.getLog(SecurityTokenReference.class.getName());
	private static Log tlog = LogFactory.getLog("org.apache.ws.security.TIME");

	public static final QName TOKEN =
		new QName(WSConstants.WSSE_NS, "SecurityTokenReference");
	public static final String SKI_URI = WSConstants.X509TOKEN_NS + "#X509SubjectKeyIdentifier";
	protected Element element = null;
	private XMLX509IssuerSerial issuerSerial = null;
	private byte[] skiBytes = null;

	private static boolean doDebug = false;

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
		QName el =
			new QName(
				this.element.getNamespaceURI(),
				this.element.getLocalName());
		if (!el.equals(TOKEN)) {
			throw new WSSecurityException(
				WSSecurityException.FAILURE,
				"badElement",
				new Object[] { TOKEN, el });
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
		this.element =
			doc.createElementNS(
				WSConstants.WSSE_NS,
				"wsse:SecurityTokenReference");
	}

	/*
	 * Here the methods that handle the direct reference inside
	 * a SecurityTokenReference
	 */
	 
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
	 * Gets the signing token element, which usually is a <code>BinarySecurityToken
	 * </code>. 
	 * The method gets the URI attribute of the {@link Reference} contained in
	 * the {@link SecurityTokenReference} and tries to find the referenced
	 * Element in the document.
	 * 
	 * @param secRef 	<code>SecurityTokenReference</code> that contains a <code>Reference
	 * 					</code> to a binary security token
	 * @return Element 	containing the signing token, must be a BinarySecurityToken
	 * @throws Exception When either no <code>Reference</code> element, or the found
	 *                   reference contains no URI, or the referenced signing not found.
	 */
	public Element getTokenElement(SecurityTokenReference secRef, Document doc)
		throws WSSecurityException {
		Reference ref = secRef.getReference();
		if (ref == null) {
			throw new WSSecurityException(
				WSSecurityException.INVALID_SECURITY,
				"noReference");
		}
		String uri = ref.getURI();
		if (doDebug) {
			log.debug("Token reference uri: " + uri);
		}
		if (uri == null) {
			throw new WSSecurityException(
				WSSecurityException.INVALID_SECURITY,
				"badReferenceURI");
		}
		Element tokElement = WSSecurityUtil.getElementByWsuId(doc, uri);
		if (tokElement == null) {
			throw new WSSecurityException(
				WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
				"noToken",
				new Object[] { uri });
		}
		return tokElement;
	}

	/*
	 * Here the methods that handle the various key identifer types
	 * such as KeyIdentifier, SubjectKeyIdentifier (SKI)
	 */

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
		Element keyId =
			doc.createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
		keyId.setAttributeNS(null, "ValueType", X509Security.TYPE);
		keyId.setAttributeNS(null, "EncodingType",  BinarySecurity.BASE64_ENCODING);
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
	 * @param crypto is the Crypto implementation. Used to read SKI info bytes from certificate
	 */
	public void setKeyIdentifierSKI(X509Certificate cert, Crypto crypto) throws Exception {
		Document doc = this.element.getOwnerDocument();
		byte data[] = crypto.getSKIBytesFromCert(cert);
		org.w3c.dom.Text skiText = doc.createTextNode(Base64.encode(data));
		Element keyId =
			doc.createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
		keyId.setAttributeNS(null, "ValueType", SKI_URI);
		keyId.setAttributeNS(null, "EncodingType", BinarySecurity.BASE64_ENCODING);
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
	 * 
	 * @return the {@link BinarySecurity} containing the X509
	 * 			certificate or zero if a unknown key identifier
	 * 			type was detected.
	 */
	public X509Certificate[] getKeyIdentifier(Crypto crypto) throws Exception {
		X509Security token = null;
		Element elem = getFirstElement();
		String value = elem.getAttribute("ValueType");
		if (value.equals(X509Security.TYPE)) {
			token = new X509Security(elem);
			if (token != null) {
				X509Certificate cert = token.getX509Certificate(crypto);
				X509Certificate[] certs = new X509Certificate[1];
				certs[0] = cert;
				return certs;
			}
		} else if (value.equals(SKI_URI)) {
			token = getEmbeddedTokenFromSKI(element.getOwnerDocument(), crypto);
			if (token != null) {
				X509Certificate cert = token.getX509Certificate(crypto);
				X509Certificate[] certs = new X509Certificate[1];
				certs[0] = cert;
				return certs;
			}
			else {
				String alias = getX509SKIAlias(crypto);
				if (alias != null) {
					return crypto.getCertificates(alias);
				}
			}
		}
		return null;
	}
	
	public String getX509SKIAlias(Crypto crypto) throws Exception {
		if (skiBytes == null) {
			skiBytes = getSKIBytes();
			if (skiBytes == null) {
				return null;
			}
		}
		String alias =
			crypto.getAliasForX509Cert(skiBytes);
		if (doDebug) {
			log.info("X509 SKI alias: " + alias);
		}
		return alias;
	}

	public byte[] getSKIBytes() {
		if (skiBytes != null) {
			return skiBytes;
		} 
		Node node = getFirstElement().getFirstChild();
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
		return skiBytes;
	}

	public X509Security getEmbeddedTokenFromSKI(Document doc, Crypto crypto)
		throws Exception {

		if (doDebug) {
			log.debug("getCertFromSKI: enter");
		}
		X509Security found = null;

		if (skiBytes == null) {
			skiBytes = getSKIBytes();
			if (skiBytes == null) {
				return null;
			}
		}
		if (doDebug) {
			log.debug("Cert SKI: got SKI bytes");
		}
		NodeList nl =
			doc.getElementsByTagNameNS(
				WSConstants.WSSE_NS,
				"BinarySecurityToken");

		int nlLength = nl.getLength();
		for (int i = 0; i < nlLength && found == null; i++) {
			if (doDebug) {
				log.debug("Cert SKI: processing BST " + i);
			}
			Element bstElement = (Element) nl.item(i);
			String value = bstElement.getAttribute("ValueType");
			if (!value.equals(X509Security.TYPE)) {
				continue;
			}
			X509Security token = new X509Security(bstElement);
			X509Certificate cert = token.getX509Certificate(crypto);
			if (cert == null) {
				continue;
			}
			if (doDebug) {
				log.debug("Cert SKI: got cert from BST");
			}
			byte data[] = crypto.getSKIBytesFromCert(cert);
			if (data.length != skiBytes.length) {
				continue;
			}
			if (doDebug) {
				log.debug("Cert SKI: got SKI bytes from embedded cert");
			}
			for (int ii = 0; ii < data.length; ii++) {
				if (data[ii] != skiBytes[ii]) {
					token = null;
					break;
				}
			}
			if (doDebug && token != null) {
				log.debug("Cert SKI: found embedded BST");
			}
			found = token;
		}
		return found;
	}

	/*
	 * Here the methods that handle the IssuerSerial key identifiaton
	 */

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
	 * Gets the certificate identified with X509 issuerSerial data.
	 * This method first tries to get the embedded certificate.
	 * If this fails it checks if the certificate is  in the
	 * keystore.
	 * 
	 * @return a certificate array or null if nothing found
	 */
	public X509Certificate[] getX509IssuerSerial(Crypto crypto)
		throws Exception {
		X509Security token =
			getEmbeddedTokenFromIS(element.getOwnerDocument(), crypto);
		if (token != null) {
			X509Certificate cert = token.getX509Certificate(crypto);
			X509Certificate[] certs = new X509Certificate[1];
			certs[0] = cert;
			return certs;
		}
		String alias = getX509IssuerSerialAlias(crypto);
		if (alias != null) {
			return crypto.getCertificates(alias);
		}
		return null;
	}

	/**
	 * Gets the alias name of the certificate identified with X509 issuerSerial data.
	 * The keystore identifies the certificate and the key with this alias name. 
	 * 
	 * @return the alias name for the certificate or null if nothing found
	 */
	public String getX509IssuerSerialAlias(Crypto crypto) throws Exception {
		if (issuerSerial == null) {
			issuerSerial = getIssuerSerial();
			if (issuerSerial == null) {
				return null;
			}
		}
		String alias =
			crypto.getAliasForX509Cert(
				issuerSerial.getIssuerName(),
				issuerSerial.getSerialNumber());
		if (doDebug) {
			log.info("X509IssuerSerial alias: " + alias);
		}
		return alias;
	}

	public X509Security getEmbeddedTokenFromIS(
		Document doc,
		Crypto crypto)
		throws Exception {

		if (doDebug) {
			log.debug("getEmbeddedCertFromIS: enter");
		}

		if (issuerSerial == null) {
			issuerSerial = getIssuerSerial();
			if (issuerSerial == null) {
				return null;
			}
		}
		NodeList nl =
			doc.getElementsByTagNameNS(
				WSConstants.WSSE_NS,
				"BinarySecurityToken");

		int nlLength = nl.getLength();
		for (int i = 0; i < nlLength; i++) {
			if (doDebug) {
				log.debug("Cert IS: processing BST " + i);
			}
			Element bstElement = (Element) nl.item(i);
			String value = bstElement.getAttribute("ValueType");
			if (!value.equals(X509Security.TYPE)) {
				continue;
			}

			X509Security token = new X509Security(bstElement);
			X509Certificate cert = token.getX509Certificate(crypto);
			if (cert == null) {
				continue;
			}
			if (doDebug) {
				log.debug("Cert IS: got cert from BST: " + cert);
			}
			/*
			 * Note: the direct compar of IssuerName/Name may fail because
			 * of different name formats (addittional blanks). may be replaced
			 * with soultion in Merlin.java (getAliasForX509Cert(...) )
			 */
			if ((cert
				.getSerialNumber()
				.compareTo(issuerSerial.getSerialNumber())
				== 0)
				&& (cert
					.getIssuerDN()
					.getName()
					.equals(issuerSerial.getIssuerName()))) {
				if (doDebug) {
					log.debug("Cert IS: found embedded BST");
				}
				return token;
			}
		}
		if (doDebug) {
			log.debug("Cert IS: no embedded BST found");
		}
		return null;
	}

	private XMLX509IssuerSerial getIssuerSerial() throws Exception {
		if (issuerSerial != null) {
			return issuerSerial;
		} 
		Element elem = getFirstElement();
		if (elem == null) {
			return null;
		}
		return new XMLX509IssuerSerial(elem, "");
	}
	
	/*
	 * Several helper and utility mehtods.
	 */
	 
	/**
	 * get the first child element.
	 * 
	 * @return the first <code>Element</code> child node
	 */
	public Element getFirstElement() {
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
				if (((namespace != null)
					&& (ns != null)
					&& namespace.equals(ns))
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
		String prefix = WSSecurityUtil.setNamespace(this.element, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
		this.element.setAttributeNS(WSConstants.WSU_NS, prefix+":Id", id);
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
