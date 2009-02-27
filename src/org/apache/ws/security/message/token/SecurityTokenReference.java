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
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.util.DOM2Writer;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.content.x509.XMLX509IssuerSerial;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.ws.security.util.Base64;
import org.apache.xml.security.utils.Constants;
import org.w3c.dom.*;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Security Token Reference.
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class SecurityTokenReference {
    private static Log log =
            LogFactory.getLog(SecurityTokenReference.class.getName());
    public static final String SECURITY_TOKEN_REFERENCE = "SecurityTokenReference";
    public static final String KEY_NAME = "KeyName";
    public static final String SKI_URI = 
        WSConstants.X509TOKEN_NS + "#X509SubjectKeyIdentifier";
    public static final String THUMB_URI = 
        WSConstants.SOAPMESSAGE_NS11 + "#" + WSConstants.THUMBPRINT;
    public static final String SAML_ID_URI = 
        WSConstants.SAMLTOKEN_NS + "#" + WSConstants.SAML_ASSERTION_ID;
    public static final String ENC_KEY_SHA1_URI = 
        WSConstants.SOAPMESSAGE_NS11 + "#" + WSConstants.ENC_KEY_SHA1_URI;
    protected Element element = null;
    private XMLX509IssuerSerial issuerSerial = null;
    private byte[] skiBytes = null;
    private static boolean doDebug = false;

    /**
     * Constructor.
     *
     * @param elem TODO
     * @throws WSSecurityException
     */
    public SecurityTokenReference(Element elem) throws WSSecurityException {
        doDebug = log.isDebugEnabled();
        this.element = elem;
        boolean goodElement = false;
        if (SECURITY_TOKEN_REFERENCE.equals(element.getLocalName())) {
            goodElement = WSConstants.WSSE_NS.equals(element.getNamespaceURI());
//        } else if (KEY_NAME.equals(element.getLocalName())) {
//            goodElement = WSConstants.SIG_NS.equals(element.getNamespaceURI());
        }
        if (!goodElement) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "badElement", null);
        }
    }

    /**
     * Constructor.
     *
     * @param doc TODO
     */
    public SecurityTokenReference(Document doc) {
        doDebug = log.isDebugEnabled();
        this.element =
                doc.createElementNS(WSConstants.WSSE_NS, "wsse:SecurityTokenReference");
        WSSecurityUtil.setNamespace(this.element, WSConstants.WSSE_NS, WSConstants.WSSE_PREFIX);        
    }

    /**
     * set the reference.
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
     *         SecurityTokenReference
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
     * @return Element containing the signing token, must be a BinarySecurityToken
     * @throws WSSecurityException When either no <code>Reference</code> element, or the found
     *                   reference contains no URI, or the referenced signing not found.
     */
    public Element getTokenElement(Document doc, WSDocInfo docInfo, CallbackHandler cb)
        throws WSSecurityException {
        Reference ref = getReference();
        String uri = ref.getURI();
        if (doDebug) {
            log.debug("Token reference uri: " + uri);
        }
        if (uri == null) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "badReferenceURI"
            );
        }
        Element tokElement = null;
        String tmpS = WSConstants.WSS_SAML_NS + WSConstants.WSS_SAML_ASSERTION;
        String saml10 = WSConstants.WSS_SAML_NS + WSConstants.SAML_ASSERTION_ID;
        
        if (tmpS.equals(ref.getValueType())
            || saml10.equals(ref.getValueType())
            || WSConstants.WSC_SCT.equals(ref.getValueType())) {
            Element sa = docInfo.getAssertion();
            String saID = null;
            if (sa != null) {
                saID = sa.getAttribute("AssertionID");
            }
            if (doDebug) {
                log.debug("SAML token ID: " + saID);
            }
            String id = uri;
            if (id.charAt(0) == '#') {
                id = id.substring(1);
            }
            if (saID == null || !saID.equals(id)) {
                if (cb != null) {
                    //try to find a custom token
                    WSPasswordCallback pwcb = 
                        new WSPasswordCallback(id, WSPasswordCallback.CUSTOM_TOKEN);
                    try {
                        cb.handle(new Callback[]{pwcb});
                    } catch (Exception e) {
                        throw new WSSecurityException(
                            WSSecurityException.FAILURE,
                            "noPassword", 
                            new Object[] {id}, 
                            e
                        );
                    }
                    
                    Element assertionElem = pwcb.getCustomToken();
                    if (assertionElem != null) {
                        sa = (Element)doc.importNode(assertionElem, true);
                    }
                    else {
                        throw new WSSecurityException(
                            WSSecurityException.INVALID_SECURITY,
                            "badReferenceURI",
                            new Object[]{"uri:" + uri + ", saID: " + saID}
                        );
                    }
                } else {
                    throw new WSSecurityException(
                        WSSecurityException.INVALID_SECURITY,
                        "badReferenceURI",
                        new Object[]{"uri:" + uri + ", saID: " + saID}
                    );
                }
            }
            tokElement = sa;
        } else {
            tokElement = WSSecurityUtil.getElementByWsuId(doc, uri);
            
            // In some scenarios id is used rather than wsu:Id
            if (tokElement == null) {
                tokElement = WSSecurityUtil.getElementByGenId(doc, uri);
            }

        }
        if (tokElement == null) {
            throw new WSSecurityException(
                WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
                "noToken",
                new Object[]{uri}
            );
        }
        return tokElement;
    }


    /**
     * Sets the KeyIdentifier Element as a X509 certificate.
     * Takes a X509 certificate, converts its data into base 64 and inserts
     * it into a <code>wsse:KeyIdentifier</code> element, which is placed
     * in the <code>wsse:SecurityTokenReference</code> element.
     *
     * @param cert is the X509 certificate to be inserted as key identifier
     */
    public void setKeyIdentifier(X509Certificate cert)
        throws WSSecurityException {
        Document doc = this.element.getOwnerDocument();
        byte data[] = null;
        try {
            data = cert.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new WSSecurityException(
                WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, "encodeError", null, e
            );
        }
        Text text = doc.createTextNode(Base64.encode(data));
        
        createKeyIdentifier(doc, X509Security.X509_V3_TYPE, text);
    }

    /**
     * Sets the KeyIdentifier Element as a X509 Subject-Key-Identifier (SKI).
     * Takes a X509 certificate, gets it SKI data, converts into base 64 and
     * inserts it into a <code>wsse:KeyIdentifier</code> element, which is placed
     * in the <code>wsse:SecurityTokenReference</code> element.
     *
     * @param cert   is the X509 certificate to get the SKI
     * @param crypto is the Crypto implementation. Used to read SKI info bytes from certificate
     */
    public void setKeyIdentifierSKI(X509Certificate cert, Crypto crypto)
        throws WSSecurityException {
        //
        // As per the 1.1 specification, SKI can only be used for a V3 certificate
        //
        if (cert.getVersion() != 3) {
            throw new WSSecurityException(
                WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
                "invalidCertForSKI",
                new Object[]{new Integer(cert.getVersion())}
            );
        }
        
        Document doc = this.element.getOwnerDocument();
        byte data[] = crypto.getSKIBytesFromCert(cert);
        
        org.w3c.dom.Text text = doc.createTextNode(Base64.encode(data));
        createKeyIdentifier(doc, SKI_URI, text);        
    }

    /**
     * Sets the KeyIdentifier Element as a Thumbprint.
     * 
     * Takes a X509 certificate, computes its thumbprint using SHA-1, converts
     * into base 64 and inserts it into a <code>wsse:KeyIdentifier</code>
     * element, which is placed in the <code>wsse:SecurityTokenReference</code>
     * element.
     * 
     * @param cert is the X509 certificate to get the thumbprint
     */
    public void setKeyIdentifierThumb(X509Certificate cert) throws WSSecurityException {
        Document doc = this.element.getOwnerDocument();
        MessageDigest sha = null;
        try {
            sha = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e1) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "noSHA1availabe", null, e1
            );
        }
        sha.reset();
        try {
            sha.update(cert.getEncoded());
        } catch (CertificateEncodingException e1) {
            throw new WSSecurityException(
                WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, "encodeError", null, e1
            );
        }
        byte[] data = sha.digest();

        org.w3c.dom.Text text = doc.createTextNode(Base64.encode(data));
        createKeyIdentifier(doc, THUMB_URI, text);
    }
    

    public void setKeyIdentifierEncKeySHA1(String value) throws WSSecurityException {
        Document doc = this.element.getOwnerDocument();
        org.w3c.dom.Text text = doc.createTextNode(value);
        createKeyIdentifier(doc, ENC_KEY_SHA1_URI, text);
    }
    
    public void setSAMLKeyIdentifier(String keyIdVal) throws WSSecurityException {
        Document doc = this.element.getOwnerDocument();
        createKeyIdentifier(doc, SAML_ID_URI, doc.createTextNode(keyIdVal));
    }

    private void createKeyIdentifier(Document doc, String uri, Node node) {
        Element keyId = doc.createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
        keyId.setAttributeNS(null, "ValueType", uri);
        keyId.setAttributeNS(null, "EncodingType", BinarySecurity.BASE64_ENCODING);

        keyId.appendChild(node);
        Element elem = getFirstElement();
        if (elem != null) {
            this.element.replaceChild(keyId, elem);
        } else {
            this.element.appendChild(keyId);
        }
    }

    
    /**
     * get the first child element.
     *
     * @return the first <code>Element</code> child node
     */
    public Element getFirstElement() {
        for (Node currentChild = this.element.getFirstChild();
             currentChild != null;
             currentChild = currentChild.getNextSibling()
        ) {
            if (currentChild instanceof Element) {
                return (Element) currentChild;
            }
        }
        return null;
    }

    /**
     * Gets the KeyIdentifier.
     *
     * @return the the X509 certificate or zero if a unknown key identifier
     *         type was detected.
     */
    public X509Certificate[] getKeyIdentifier(Crypto crypto) throws WSSecurityException {
        Element elem = getFirstElement();
        String value = elem.getAttribute("ValueType");
        String alias = null;

        if (X509Security.X509_V3_TYPE.equals(value)) {
            X509Security token = new X509Security(elem);
            if (token != null) {
                X509Certificate cert = token.getX509Certificate(crypto);
                X509Certificate[] certs = new X509Certificate[1];
                certs[0] = cert;
                return certs;
            }
        } else if (SKI_URI.equals(value)) {
            alias = getX509SKIAlias(crypto);
        } else if (THUMB_URI.equals(value)) {
            Node node = getFirstElement().getFirstChild();
            if (node == null) {
                return null;
            }
            if (node.getNodeType() == Node.TEXT_NODE) {
                byte[] thumb = Base64.decode(((Text) node).getData());
                alias = crypto.getAliasForX509CertThumb(thumb);
            }
        }
        
        if (alias != null) {
            return crypto.getCertificates(alias);
        }
        return null;
    }
    
    public String getKeyIdentifierValue() {
        if (containsKeyIdentifier()) {
            Node node = getFirstElement().getFirstChild();
            if (node == null) {
                return null;
            }
            if (node.getNodeType() == Node.TEXT_NODE) {
                return ((Text) node).getData();
            }
        } 
        return null;
    }
    
    public String getKeyIdentifierValueType() {
        if (containsKeyIdentifier()) {
            Element elem = getFirstElement();
            return elem.getAttribute("ValueType");
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
            } catch (WSSecurityException e) {
                return null;
            }
        }
        return skiBytes;
    }


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
    public X509Certificate[] getX509IssuerSerial(Crypto crypto) throws WSSecurityException {
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
    public String getX509IssuerSerialAlias(Crypto crypto) throws WSSecurityException {
        if (issuerSerial == null) {
            issuerSerial = getIssuerSerial();
            if (issuerSerial == null) {
                return null;
            }
        }

        String alias = 
            crypto.getAliasForX509Cert(issuerSerial.getIssuerName(), issuerSerial.getSerialNumber());
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
                elem = 
                    (Element)WSSecurityUtil.findElement(
                        elem, Constants._TAG_X509ISSUERSERIAL, Constants.SignatureSpecNS
                    );
            }
            issuerSerial = new XMLX509IssuerSerial(elem, "");
        } catch (XMLSecurityException e) {
            throw new WSSecurityException(
                WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
                "noToken",
                new Object[]{"Issuer/Serial data element missing"},
                e
            );
        }
        return issuerSerial;
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
        int result = 0;
        for (int i = 0; i < childNodes.getLength(); i++) {
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
     *
     * @return TODO
     */
    public Element getElement() {
        return this.element;
    }

    /**
     * set the id.
     *
     * @param id
     */
    public void setID(String id) {
        String prefix =
                WSSecurityUtil.setNamespace(
                    this.element, WSConstants.WSU_NS, WSConstants.WSU_PREFIX
                );
        this.element.setAttributeNS(WSConstants.WSU_NS, prefix + ":Id", id);
    }

    /**
     * return the string representation.
     *
     * @return TODO
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) this.element);
    }
}
