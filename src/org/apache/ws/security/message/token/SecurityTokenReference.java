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
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.utils.Base64;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.*;

import java.security.cert.CertificateEncodingException;
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
    public static final String SECURITY_TOKEN_REFERENCE = "SecurityTokenReference";
    public static final String KEY_NAME = "KeyName";
    public static final String SKI_URI = WSConstants.X509TOKEN_NS + "#X509SubjectKeyIdentifier";
    protected Element element = null;
    private XMLX509IssuerSerial issuerSerial = null;
    private byte[] skiBytes = null;
    
    private static boolean doDebug = false;

    /**
     * Constructor.
     * <p/>
     *
     * @param wssConfig
     * @param elem
     * @throws WSSecurityException
     */
    public SecurityTokenReference(Element elem) throws WSSecurityException {
        doDebug = log.isDebugEnabled();
        this.element = elem;
        boolean goodElement = false;
        if (SECURITY_TOKEN_REFERENCE.equals(element.getLocalName())) {
            goodElement = WSConstants.WSSE_NS.equals(element.getNamespaceURI());
        } else if (KEY_NAME.equals(element.getLocalName())) {
            goodElement = WSConstants.SIG_NS.equals(element.getNamespaceURI());
        }
        if (!goodElement) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "badElement",
                    null);
        }
    }

    /**
     * Constructor.
     * <p/>
     *
     * @param wssConfig
     * @param doc
     */
    public SecurityTokenReference(Document doc) {
        doDebug = log.isDebugEnabled();
        this.element =
                doc.createElementNS(WSConstants.WSSE_NS,
                        "wsse:SecurityTokenReference");
        WSSecurityUtil.setNamespace(this.element, WSConstants.WSSE_NS, WSConstants.WSSE_PREFIX);        
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
     * @return the <code>Reference</code> element contained in this
     *         SecurityTokeneReference
     * @throws WSSecurityException
     */
    public Reference getReference() throws WSSecurityException {
        Element elem = getFirstElement();
        return new Reference(elem);
    }

    /**
     * Gets the signing token element, which maybe a <code>BinarySecurityToken
     * </code> or a SAML token.
     * 
     * The method gets the URI attribute of the {@link Reference} contained in
     * the {@link SecurityTokenReference} and tries to find the referenced
     * Element in the document.
     *
     * @param doc the document that contains the binary security token
     *            element. This could be different from the document
     *            that contains the SecurityTokenReference (STR). See
     *            STRTransform.derefenceBST() method
     * @return Element     containing the signing token, must be a BinarySecurityToken
     * @throws WSSecurityException When either no <code>Reference</code> element, or the found
     *                   reference contains no URI, or the referenced signing not found.
     */
    public Element getTokenElement(Document doc, WSDocInfo docInfo)
            throws WSSecurityException {
        Reference ref = getReference();
        String uri = ref.getURI();
        if (doDebug) {
            log.debug("Token reference uri: " + uri);
        }
        if (uri == null) {
            throw new WSSecurityException(WSSecurityException.INVALID_SECURITY,
                    "badReferenceURI");
        }
        Element tokElement = null;
        String tmpS = WSConstants.WSS_SAML_NS + WSConstants.WSS_SAML_ASSERTION;
        if (tmpS.equals(ref.getValueType())) {
            Element sa = docInfo.getAssertion();
            String saID = null;
            if (sa != null) {
                saID = sa.getAttribute("AssertionID");
            }
            if (doDebug) {
                log.debug("SAML token ID: " + saID);
            }
            String id = uri.substring(1);
            if (saID == null || !saID.equals(id)) {
                throw new WSSecurityException(WSSecurityException.INVALID_SECURITY,
                        "badReferenceURI",
                        new Object[]{"uri:" + uri + ", saID: " + saID});
            }
            tokElement = sa;
        } else {
            tokElement = WSSecurityUtil.getElementByWsuId(doc, uri);
        }
        if (tokElement == null) {
            throw new WSSecurityException(WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
                    "noToken",
                    new Object[]{uri});
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
    public void setKeyIdentifier(X509Certificate cert)
            throws WSSecurityException {
        Document doc = this.element.getOwnerDocument();
        byte data[] = null;
        try {
            data = cert.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new WSSecurityException(WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
                    "encodeError");
        }
        Text certText = doc.createTextNode(Base64.encode(data));
        Element keyId =
                doc.createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
        keyId.setAttributeNS(null, "ValueType", X509Security.getType());
        keyId.setAttributeNS(null, "EncodingType", BinarySecurity.BASE64_ENCODING);
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
     * @param cert   is the X509 certficate to get the SKI
     * @param crypto is the Crypto implementation. Used to read SKI info bytes from certificate
     */
    public void setKeyIdentifierSKI(X509Certificate cert, Crypto crypto)
            throws WSSecurityException {
        Document doc = this.element.getOwnerDocument();
        byte data[] = crypto.getSKIBytesFromCert(cert);
        org.w3c.dom.Text skiText = doc.createTextNode(Base64.encode(data));
        Element keyId =
                doc.createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
            keyId.setAttributeNS(null, "ValueType", SKI_URI);
            keyId.setAttributeNS(null,
                    "EncodingType",
                    BinarySecurity.BASE64_ENCODING);

        keyId.appendChild(skiText);
        Element elem = getFirstElement();
        if (elem != null) {
            this.element.replaceChild(keyId, elem);
        } else {
            this.element.appendChild(keyId);
        }
    }

	public void setSAMLKeyIdentifier(String keyIdVal)
			throws WSSecurityException {
		Document doc = this.element.getOwnerDocument();
		Element keyId =
				doc.createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
			keyId.setAttributeNS(WSConstants.WSSE_NS,
					"ValueType",
					"http://docs.oasis-open.org/wss/2004/XX/oasis-2004XX-wss-saml-token-profile-1.0#SAMLAssertionID");
		keyId.appendChild(doc.createTextNode(keyIdVal));
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
     *         certificate or zero if a unknown key identifier
     *         type was detected.
     */
    public X509Certificate[] getKeyIdentifier(Crypto crypto)
            throws WSSecurityException {
        X509Security token = null;
        Element elem = getFirstElement();
        String value = elem.getAttribute("ValueType");

        if (X509Security.getType().equals(value)) {
            token = new X509Security(elem);
            if (token != null) {
                X509Certificate cert = token.getX509Certificate(crypto);
                X509Certificate[] certs = new X509Certificate[1];
                certs[0] = cert;
                return certs;
            }
        } else if (SKI_URI.equals(value)) {
            String alias = getX509SKIAlias(crypto);
            if (alias != null) {
                return crypto.getCertificates(alias);
            }
        }
        return null;
    }

    public String getX509SKIAlias(Crypto crypto) throws WSSecurityException {
        if (skiBytes == null) {
            skiBytes = getSKIBytes();
            if (skiBytes == null) {
                return null;
            }
        }
        String alias = crypto.getAliasForX509Cert(skiBytes);
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

    /*
     * Here the methods that handle the IssuerSerial key identifiaton
     */

    /**
     * Sets the X509 IssuerSerial data.
     *
     * @param ref the {@link XMLX509IssuerSerial} to put into this
     *            SecurityTokenReference
     */
    public void setX509IssuerSerial(X509Data ref) {
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
            throws WSSecurityException {
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
    public String getX509IssuerSerialAlias(Crypto crypto)
            throws WSSecurityException {
        if (issuerSerial == null) {
            issuerSerial = getIssuerSerial();
            if (issuerSerial == null) {
                return null;
            }
        }

        String alias = crypto.getAliasForX509Cert(issuerSerial.getIssuerName(),
                issuerSerial.getSerialNumber());

        if (doDebug) {
            log.info("X509IssuerSerial alias: " + alias);
        }
        return alias;
    }

    private XMLX509IssuerSerial getIssuerSerial() throws WSSecurityException {
        if (issuerSerial != null) {
            return issuerSerial;
        }
        Element elem = getFirstElement();
        if (elem == null) {
            return null;
        }
        try {
            if (Constants._TAG_X509DATA.equals(elem.getLocalName())) {
                elem = (Element)WSSecurityUtil.findElement(elem, Constants._TAG_X509ISSUERSERIAL, Constants.SignatureSpecNS);
            }
            issuerSerial = new XMLX509IssuerSerial(elem, "");
        } catch (XMLSecurityException e) {
            throw new WSSecurityException(WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
                    "noToken",
                    new Object[]{"Issuer/Serial data element missing"});
        }
        return issuerSerial;
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
     * Method containsKeyName
     *
     * @return true if the <code>SecurtityTokenReference</code> contains
     *         a <code>wsse:KeyName</code> element
     */
    public boolean containsKeyName() {
        return element.getLocalName().equals(KEY_NAME);
    }

    public String getKeyNameValue() {
        return element.getFirstChild().getNodeValue();
    }

    /**
     * Method containsReference
     *
     * @return true if the <code>SecurtityTokenReference</code> contains
     *         a <code>wsse:Reference</code> element
     */
    public boolean containsReference() {
        return this.lengthReference() > 0;
    }

    /**
     * Method lengthReference.
     *
     * @return number of <code>wsse:Reference</code> elements in
     *         the <code>SecurtityTokenReference</code>
     */
    public int lengthReference() {
        return this.length(WSConstants.WSSE_NS, "Reference");
    }

    /**
     * Method containsX509IssuerSerial
     *
     * @return true if the <code>SecurtityTokenReference</code> contains
     *         a <code>ds:IssuerSerial</code> element
     */
    public boolean containsX509IssuerSerial() {
        return this.lengthX509IssuerSerial() > 0;
    }

    /**
     * Method containsX509Data
     *
     * @return true if the <code>SecurtityTokenReference</code> contains
     *         a <code>ds:X509Data</code> element
     */
    public boolean containsX509Data() {
        return this.lengthX509Data() > 0;
    }
    /**
     * Method lengthX509IssuerSerial.
     *
     * @return number of <code>ds:IssuerSerial</code> elements in
     *         the <code>SecurtityTokenReference</code>
     */
    public int lengthX509IssuerSerial() {
        return this.length(WSConstants.SIG_NS, Constants._TAG_X509ISSUERSERIAL);
    }

    /**
     * Method lengthX509Data.
     *
     * @return number of <code>ds:IssuerSerial</code> elements in
     *         the <code>SecurtityTokenReference</code>
     */
    public int lengthX509Data() {
        return this.length(WSConstants.SIG_NS, Constants._TAG_X509DATA);
    }
    /**
     * Method containsKeyIdentifier.
     *
     * @return true if the <code>SecurtityTokenReference</code> contains
     *         a <code>wsse:KeyIdentifier</code> element
     */
    public boolean containsKeyIdentifier() {
        return this.lengthKeyIdentifier() > 0;
    }

    /**
     * Method lengthKeyIdentifier.
     *
     * @return number of <code>wsse:KeyIdentifier</code> elements in
     *         the <code>SecurtityTokenReference</code>
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
     * set the id.
     * <p/>
     *
     * @param id
     */
    public void setID(String id) {
        String prefix =
                WSSecurityUtil.setNamespace(this.element,
                        WSConstants.WSU_NS,
                        WSConstants.WSU_PREFIX);
        this.element.setAttributeNS(WSConstants.WSU_NS, prefix + ":Id", id);
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
