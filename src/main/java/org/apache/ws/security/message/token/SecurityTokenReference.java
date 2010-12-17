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
import org.apache.ws.security.util.Base64;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.Text;

import javax.xml.namespace.QName;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

/**
 * Security Token Reference.
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class SecurityTokenReference {
    public static final String SECURITY_TOKEN_REFERENCE = "SecurityTokenReference";
    public static final QName STR_QNAME = 
        new QName(WSConstants.WSSE_NS, SECURITY_TOKEN_REFERENCE);
    public static final String KEY_NAME = "KeyName";
    public static final String SKI_URI = 
        WSConstants.X509TOKEN_NS + "#X509SubjectKeyIdentifier";
    public static final String THUMB_URI = 
        WSConstants.SOAPMESSAGE_NS11 + "#" + WSConstants.THUMBPRINT;
    public static final String SAML_ID_URI = 
        WSConstants.SAMLTOKEN_NS + "#" + WSConstants.SAML_ASSERTION_ID;
    public static final String ENC_KEY_SHA1_URI = 
        WSConstants.SOAPMESSAGE_NS11 + "#" + WSConstants.ENC_KEY_SHA1_URI;
    private static Log log =
        LogFactory.getLog(SecurityTokenReference.class.getName());
    protected Element element = null;
    private DOMX509IssuerSerial issuerSerial = null;
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
        element = elem;
        QName el = new QName(element.getNamespaceURI(), element.getLocalName());
        if (!STR_QNAME.equals(el)) {
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
        element = doc.createElementNS(WSConstants.WSSE_NS, "wsse:SecurityTokenReference");
    }
    
    /**
     * Add the WSSE Namespace to this STR. The namespace is not added by default for
     * efficiency purposes.
     */
    public void addWSSENamespace() {
        WSSecurityUtil.setNamespace(element, WSConstants.WSSE_NS, WSConstants.WSSE_PREFIX);
    }
    
    /**
     * Add the WSU Namespace to this STR. The namespace is not added by default for
     * efficiency purposes.
     */
    public void addWSUNamespace() {
        WSSecurityUtil.setNamespace(element, WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
    }

    /**
     * set the reference.
     *
     * @param ref
     */
    public void setReference(Reference ref) {
        Element elem = getFirstElement();
        if (elem != null) {
            element.replaceChild(ref.getElement(), elem);
        } else {
            element.appendChild(ref.getElement());
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
     * Gets the signing token element, which may be a <code>BinarySecurityToken
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
        
        Element tokElement = findTokenElement(doc, docInfo, cb, uri, ref.getValueType());
        
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
     * Gets the signing token element, which may be a <code>BinarySecurityToken
     * </code> or a SAML token.
     * 
     * The method gets the value of the KeyIdentifier contained in
     * the {@link SecurityTokenReference} and tries to find the referenced
     * Element in the document.
     *
     * @param doc the document that contains the binary security token
     *            element. This could be different from the document
     *            that contains the SecurityTokenReference (STR). See
     *            STRTransform.derefenceBST() method
     * @return Element containing the signing token
     */
    public Element getKeyIdentifierTokenElement(
        Document doc, WSDocInfo docInfo, CallbackHandler cb
    ) throws WSSecurityException {
        String value = getKeyIdentifierValue();
        String type = getKeyIdentifierValueType();
        if (doDebug) {
            log.debug("Token reference uri: " + value);
        }
        if (value == null) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "badReferenceURI"
            );
        }
        
        Element tokElement = findTokenElement(doc, docInfo, cb, value, type);
        
        if (tokElement == null) {
            throw new WSSecurityException(
                WSSecurityException.SECURITY_TOKEN_UNAVAILABLE,
                "noToken",
                new Object[]{value}
            );
        }
        return tokElement;
    }
    
    
    private Element findTokenElement(
        Document doc,
        WSDocInfo docInfo,
        CallbackHandler cb,
        String uri,
        String type
    ) {
        String id = uri;
        if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        //
        // If the token type is a SAML Token or BinarySecurityToken, try to find it from the
        // WSDocInfo instance first, to avoid searching the DOM element for it
        //
        if (docInfo != null) {
            Element token = docInfo.getTokenElement(id);
            if (token != null) {
                return token;
            }
        }
        
        //
        // Try to find a SAML Assertion by searching the DOM tree
        //
        String assertionStr = WSConstants.WSS_SAML_NS + WSConstants.ASSERTION_LN;
        if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(type) || assertionStr.equals(type)) {
            Element assertion = 
                WSSecurityUtil.findSAMLAssertionElementById(
                    doc.getDocumentElement(),
                    id
                );
            if (assertion != null) {
                if (doDebug) {
                    log.debug("SAML token ID: " + assertion.getAttribute("AssertionID"));
                }
                docInfo.addTokenElement(assertion);
                return assertion;
            }
        }
        
        // 
        // Try to find a custom token
        //
        if (WSConstants.WSC_SCT.equals(type) && cb != null) {
            //try to find a custom token
            WSPasswordCallback pwcb = 
                new WSPasswordCallback(id, WSPasswordCallback.CUSTOM_TOKEN);
            try {
                cb.handle(new Callback[]{pwcb});
                Element assertionElem = pwcb.getCustomToken();
                if (assertionElem != null) {
                    return (Element)doc.importNode(assertionElem, true);
                }
            } catch (Exception e) {
                log.debug(e.getMessage(), e);
                // Consume this failure
            }
        }
        
        //
        // Finally try to find the element by its (wsu) Id
        //
        return WSSecurityUtil.findElementById(doc.getDocumentElement(), uri, true);
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
        Document doc = element.getOwnerDocument();
        byte data[] = null;
        try {
            data = cert.getEncoded();
        } catch (CertificateEncodingException e) {
            throw new WSSecurityException(
                WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, "encodeError", null, e
            );
        }
        Text text = doc.createTextNode(Base64.encode(data));
        
        createKeyIdentifier(doc, X509Security.X509_V3_TYPE, text, true);
    }

    /**
     * Sets the KeyIdentifier Element as a X509 Subject-Key-Identifier (SKI).
     * Takes a X509 certificate, gets the SKI data, converts it into base 64 and
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
        
        Document doc = element.getOwnerDocument();
        byte data[] = crypto.getSKIBytesFromCert(cert);
        
        Text text = doc.createTextNode(Base64.encode(data));
        createKeyIdentifier(doc, SKI_URI, text, true);        
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
        Document doc = element.getOwnerDocument();
        byte[] encodedCert = null;
        try {
            encodedCert = cert.getEncoded();
        } catch (CertificateEncodingException e1) {
            throw new WSSecurityException(
                WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, "encodeError", null, e1
            );
        }
        try {
            byte[] encodedBytes = WSSecurityUtil.generateDigest(encodedCert);
            org.w3c.dom.Text text = doc.createTextNode(Base64.encode(encodedBytes));
            createKeyIdentifier(doc, THUMB_URI, text, true);
        } catch (WSSecurityException e1) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE, "noSHA1availabe", null, e1
            );
        }
    }
    

    public void setKeyIdentifierEncKeySHA1(String value) throws WSSecurityException {
        Document doc = element.getOwnerDocument();
        org.w3c.dom.Text text = doc.createTextNode(value);
        createKeyIdentifier(doc, ENC_KEY_SHA1_URI, text, true);
    }
    
    public void setSAMLKeyIdentifier(String keyIdVal) throws WSSecurityException {
        Document doc = element.getOwnerDocument();
        createKeyIdentifier(doc, SAML_ID_URI, doc.createTextNode(keyIdVal), false);
    }
    public void setKeyIdentifier(String valueType, String keyIdVal) throws WSSecurityException {
        Document doc = element.getOwnerDocument();
        createKeyIdentifier(doc, valueType, doc.createTextNode(keyIdVal), false);
    }

    private void createKeyIdentifier(Document doc, String uri, Node node, boolean base64) {
        Element keyId = doc.createElementNS(WSConstants.WSSE_NS, "wsse:KeyIdentifier");
        keyId.setAttributeNS(null, "ValueType", uri);
        if (base64) {
            keyId.setAttributeNS(null, "EncodingType", BinarySecurity.BASE64_ENCODING);
        }

        keyId.appendChild(node);
        Element elem = getFirstElement();
        if (elem != null) {
            element.replaceChild(keyId, elem);
        } else {
            element.appendChild(keyId);
        }
    }

    
    /**
     * get the first child element.
     *
     * @return the first <code>Element</code> child node
     */
    public Element getFirstElement() {
        for (Node currentChild = element.getFirstChild();
             currentChild != null;
             currentChild = currentChild.getNextSibling()
        ) {
            if (Node.ELEMENT_NODE == currentChild.getNodeType()) {
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
                return new X509Certificate[]{cert};
            }
        } else if (SKI_URI.equals(value)) {
            alias = getX509SKIAlias(crypto);
        } else if (THUMB_URI.equals(value)) {
            Node node = getFirstElement().getFirstChild();
            if (node == null) {
                return null;
            }
            if (Node.TEXT_NODE == node.getNodeType()) {
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
     * Sets the X509Data.
     *
     * @param domX509Data the {@link DOMX509Data} to put into this
     *            SecurityTokenReference
     */
    public void setX509Data(DOMX509Data domX509Data) {
        Element elem = getFirstElement();
        if (elem != null) {
            element.replaceChild(domX509Data.getElement(), elem);
        } else {
            element.appendChild(domX509Data.getElement());
        }
    }
    
    
    /**
     * Set an unknown element.
     *
     * @param unknownElement the org.w3c.dom.Element to put into this
     *        SecurityTokenReference
     */
    public void setUnknownElement(Element unknownElement) {
        Element elem = getFirstElement();
        if (elem != null) {
            element.replaceChild(unknownElement, elem);
        } else {
            element.appendChild(unknownElement);
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
            crypto.getAliasForX509Cert(issuerSerial.getIssuer(), issuerSerial.getSerialNumber());
        if (doDebug) {
            log.debug("X509IssuerSerial alias: " + alias);
        }
        return alias;
    }

    private DOMX509IssuerSerial getIssuerSerial() throws WSSecurityException {
        if (issuerSerial != null) {
            return issuerSerial;
        }
        Element elem = getFirstElement();
        if (elem == null) {
            return null;
        }
        if (WSConstants.X509_DATA_LN.equals(elem.getLocalName())) {
            elem = 
                (Element)WSSecurityUtil.findElement(
                    elem, WSConstants.X509_ISSUER_SERIAL_LN, WSConstants.SIG_NS
                );
        }
        issuerSerial = new DOMX509IssuerSerial(elem);

        return issuerSerial;
    }

    /**
     * Method containsReference
     *
     * @return true if the <code>SecurtityTokenReference</code> contains
     *         a <code>wsse:Reference</code> element
     */
    public boolean containsReference() {
        return lengthReference() > 0;
    }

    /**
     * Method lengthReference.
     *
     * @return number of <code>wsse:Reference</code> elements in
     *         the <code>SecurtityTokenReference</code>
     */
    public int lengthReference() {
        return length(WSConstants.WSSE_NS, "Reference");
    }

    /**
     * Method containsX509IssuerSerial
     *
     * @return true if the <code>SecurtityTokenReference</code> contains
     *         a <code>ds:IssuerSerial</code> element
     */
    public boolean containsX509IssuerSerial() {
        return lengthX509IssuerSerial() > 0;
    }

    /**
     * Method containsX509Data
     *
     * @return true if the <code>SecurtityTokenReference</code> contains
     *         a <code>ds:X509Data</code> element
     */
    public boolean containsX509Data() {
        return lengthX509Data() > 0;
    }
    
    /**
     * Method lengthX509IssuerSerial.
     *
     * @return number of <code>ds:IssuerSerial</code> elements in
     *         the <code>SecurtityTokenReference</code>
     */
    public int lengthX509IssuerSerial() {
        return length(WSConstants.SIG_NS, WSConstants.X509_ISSUER_SERIAL_LN);
    }

    /**
     * Method lengthX509Data.
     *
     * @return number of <code>ds:IssuerSerial</code> elements in
     *         the <code>SecurtityTokenReference</code>
     */
    public int lengthX509Data() {
        return length(WSConstants.SIG_NS, WSConstants.X509_DATA_LN);
    }
    
    /**
     * Method containsKeyIdentifier.
     *
     * @return true if the <code>SecurtityTokenReference</code> contains
     *         a <code>wsse:KeyIdentifier</code> element
     */
    public boolean containsKeyIdentifier() {
        return lengthKeyIdentifier() > 0;
    }

    /**
     * Method lengthKeyIdentifier.
     *
     * @return number of <code>wsse:KeyIdentifier</code> elements in
     *         the <code>SecurtityTokenReference</code>
     */
    public int lengthKeyIdentifier() {
        return length(WSConstants.WSSE_NS, "KeyIdentifier");
    }

    /**
     * Method length.
     *
     * @param namespace
     * @param localname
     * @return number of elements with matching localname and namespace
     */
    public int length(String namespace, String localname) {
        int result = 0;
        Node node = element.getFirstChild();
        while (node != null) {
            if (Node.ELEMENT_NODE == node.getNodeType()) {
                String ns = node.getNamespaceURI();
                String name = node.getLocalName();
                if ((((namespace != null) && namespace.equals(ns))
                    || ((namespace == null) && (ns == null)))
                    && (localname.equals(name))
                ) {
                    result++;
                }
            }
            node = node.getNextSibling();
        }
        return result;
    }

    /**
     * get the dom element.
     *
     * @return TODO
     */
    public Element getElement() {
        return element;
    }

    /**
     * set the id.
     *
     * @param id
     */
    public void setID(String id) {
        element.setAttributeNS(WSConstants.WSU_NS, WSConstants.WSU_PREFIX + ":Id", id);
    }

    /**
     * return the string representation.
     *
     * @return TODO
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) element);
    }
}
