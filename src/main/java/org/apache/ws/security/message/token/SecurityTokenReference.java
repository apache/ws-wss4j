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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.components.crypto.Merlin;
import org.apache.ws.security.message.CallbackLookup;
import org.apache.ws.security.message.DOMCallbackLookup;
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

import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Security Token Reference.
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public class SecurityTokenReference {
    public static final String SECURITY_TOKEN_REFERENCE = "SecurityTokenReference";
    public static final QName STR_QNAME = 
        new QName(WSConstants.WSSE_NS, SECURITY_TOKEN_REFERENCE);
    public static final String SKI_URI = 
        WSConstants.X509TOKEN_NS + "#X509SubjectKeyIdentifier";
    public static final String THUMB_URI = 
        WSConstants.SOAPMESSAGE_NS11 + "#" + WSConstants.THUMBPRINT;
    public static final String ENC_KEY_SHA1_URI = 
        WSConstants.SOAPMESSAGE_NS11 + "#" + WSConstants.ENC_KEY_SHA1_URI;
    private static org.apache.commons.logging.Log log =
        org.apache.commons.logging.LogFactory.getLog(SecurityTokenReference.class);
    protected Element element = null;
    private DOMX509IssuerSerial issuerSerial = null;
    private byte[] skiBytes = null;
    private Reference reference = null;

    /**
     * Constructor.
     *
     * @param elem A SecurityTokenReference element
     * @throws WSSecurityException
     */
    public SecurityTokenReference(Element elem) throws WSSecurityException {
        this(elem, true);
    }
    
    /**
     * Constructor.
     *
     * @param elem A SecurityTokenReference element
     * @param bspCompliant whether the SecurityTokenReference processing complies with the 
     * BSP spec
     * @throws WSSecurityException
     */
    public SecurityTokenReference(Element elem, boolean bspCompliant) throws WSSecurityException {
        element = elem;
        QName el = new QName(element.getNamespaceURI(), element.getLocalName());
        if (!STR_QNAME.equals(el)) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "badElement", null);
        }
        if (bspCompliant) {
            checkBSPCompliance();
        }
        if (containsReference()) {
            Node node = element.getFirstChild();
            while (node != null) {
                if (Node.ELEMENT_NODE == node.getNodeType()
                    && WSConstants.WSSE_NS.equals(node.getNamespaceURI())
                    && "Reference".equals(node.getLocalName())) {
                    reference = new Reference((Element)node);
                    break;
                }
                node = node.getNextSibling();
            }
        }
    }

    /**
     * Constructor.
     *
     * @param doc The Document
     */
    public SecurityTokenReference(Document doc) {
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
     * Add a wsse11:TokenType attribute to this SecurityTokenReference
     * @param tokenType the wsse11:TokenType attribute to add
     */
    public void addTokenType(String tokenType) {
        WSSecurityUtil.setNamespace(element, WSConstants.WSSE11_NS, WSConstants.WSSE11_PREFIX);
        element.setAttributeNS(
            WSConstants.WSSE11_NS, 
            WSConstants.WSSE11_PREFIX + ":" + WSConstants.TOKEN_TYPE, 
            tokenType
        );
    }
    
    /**
     * Get the wsse11:TokenType attribute of this SecurityTokenReference
     * @return the value of the wsse11:TokenType attribute
     */
    public String getTokenType() {
        return element.getAttributeNS(
            WSConstants.WSSE11_NS, WSConstants.TOKEN_TYPE
        );
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
        this.reference = ref;
    }

    /**
     * Gets the Reference.
     *
     * @return the <code>Reference</code> element contained in this
     *         SecurityTokenReference
     * @throws WSSecurityException
     */
    public Reference getReference() throws WSSecurityException {
        return reference;
    }

    /**
     * Gets the signing token element, which may be a <code>BinarySecurityToken
     * </code> or a SAML token.
     * 
     * The method gets the URI attribute of the {@link Reference} contained in
     * the {@link SecurityTokenReference} and tries to find the referenced
     * Element in the document. Alternatively, it gets the value of the KeyIdentifier 
     * contained in the {@link SecurityTokenReference} and tries to find the referenced
     * Element in the document.
     *
     * @param doc the document that contains the binary security token
     *            element. This could be different from the document
     *            that contains the SecurityTokenReference (STR). See
     *            STRTransform.derefenceBST() method
     * @param docInfo A WSDocInfo object containing previous results
     * @param cb A CallbackHandler object to obtain tokens that are not in the message
     * @return Element containing the signing token, must be a BinarySecurityToken
     * @throws WSSecurityException if the referenced element is not found.
     */
    public Element getTokenElement(
        Document doc, WSDocInfo docInfo, CallbackHandler cb
    ) throws WSSecurityException {
        Reference ref = getReference();
        String uri = null;
        String valueType = null;
        if (ref != null) {
            uri = ref.getURI();
            valueType = ref.getValueType();
        } else {
            uri = getKeyIdentifierValue();
            valueType = getKeyIdentifierValueType();
        }
        if (log.isDebugEnabled()) {
            log.debug("Token reference uri: " + uri);
        }
        
        if (uri == null) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "badReferenceURI"
            );
        }
        
        Element tokElement = 
            findProcessedTokenElement(doc, docInfo, cb, uri, valueType);
        if (tokElement == null) {
            tokElement = findUnprocessedTokenElement(doc, docInfo, cb, uri, valueType);
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
     * Find a token that has not been processed already - in other words, it searches for
     * the element, rather than trying to access previous results to find the element
     * @param doc Parent Document
     * @param docInfo WSDocInfo instance
     * @param cb CallbackHandler instance
     * @param uri URI of the element
     * @param type Type of the element
     * @return A DOM element
     * @throws WSSecurityException
     */
    public Element findUnprocessedTokenElement(
        Document doc,
        WSDocInfo docInfo,
        CallbackHandler cb,
        String uri,
        String type
    ) throws WSSecurityException {
        String id = uri;
        if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        //
        // Delegate finding the element to the CallbackLookup instance
        //
        CallbackLookup callbackLookup = null;
        if (docInfo != null) {
            callbackLookup = docInfo.getCallbackLookup();
        }
        if (callbackLookup == null) {
            callbackLookup = new DOMCallbackLookup(doc);
        }
        return callbackLookup.getElement(id, type, true);
    }
    
    /**
     * Find a token that has been processed already - in other words, it access previous
     * results to find the element, rather than conducting a general search
     * @param doc Parent Document
     * @param docInfo WSDocInfo instance
     * @param cb CallbackHandler instance
     * @param uri URI of the element
     * @param type Type of the element
     * @return A DOM element
     * @throws WSSecurityException
     */
    public Element findProcessedTokenElement(
        Document doc,
        WSDocInfo docInfo,
        CallbackHandler cb,
        String uri,
        String type
    ) throws WSSecurityException {
        String id = uri;
        if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        //
        // Try to find it from the WSDocInfo instance first
        //
        if (docInfo != null) {
            Element token = docInfo.getTokenElement(id);
            if (token != null) {
                return token;
            }
        }

        // 
        // Try to find a custom token
        //
        if (cb != null && (WSConstants.WSC_SCT.equals(type)
            || WSConstants.WSC_SCT_05_12.equals(type)
            || WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(type) 
            || WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(type)
            || KerberosSecurity.isKerberosToken(type))) {
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
        return null;
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
                new Object[]{Integer.valueOf(cert.getVersion())}
            );
        }
        
        Document doc = element.getOwnerDocument();
        // Fall back to Merlin if crypto parameter is null
        Crypto skiCrypto = crypto;
        if (skiCrypto == null) {
            skiCrypto = new Merlin();
        }
        byte data[] = skiCrypto.getSKIBytesFromCert(cert);
        
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
    
    public void setKeyIdentifier(String valueType, String keyIdVal) throws WSSecurityException {
        setKeyIdentifier(valueType, keyIdVal, false);
    }
    
    public void setKeyIdentifier(String valueType, String keyIdVal, boolean base64) 
        throws WSSecurityException {
        Document doc = element.getOwnerDocument();
        createKeyIdentifier(doc, valueType, doc.createTextNode(keyIdVal), base64);
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

        if (X509Security.X509_V3_TYPE.equals(value)) {
            X509Security token = new X509Security(elem);
            if (token != null) {
                X509Certificate cert = token.getX509Certificate(crypto);
                return new X509Certificate[]{cert};
            }
        } else if (SKI_URI.equals(value)) {
            X509Certificate cert = getX509SKIAlias(crypto);
            if (cert != null) {
                return new X509Certificate[]{cert};
            }
        } else if (THUMB_URI.equals(value)) {
            Node node = getFirstElement().getFirstChild();
            if (node == null) {
                return null;
            }
            if (Node.TEXT_NODE == node.getNodeType()) {
                byte[] thumb = Base64.decode(((Text) node).getData());
                CryptoType cryptoType = new CryptoType(CryptoType.TYPE.THUMBPRINT_SHA1);
                cryptoType.setBytes(thumb);
                X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
                if (certs != null) {
                    return new X509Certificate[]{certs[0]};
                }
            }
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
    
    public String getKeyIdentifierEncodingType() {
        if (containsKeyIdentifier()) {
            Element elem = getFirstElement();
            return elem.getAttribute("EncodingType");
        } 
        return null;
    }
    
    public X509Certificate getX509SKIAlias(Crypto crypto) throws WSSecurityException {
        if (skiBytes == null) {
            skiBytes = getSKIBytes();
            if (skiBytes == null) {
                return null;
            }
        }
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.SKI_BYTES);
        cryptoType.setBytes(skiBytes);
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        if (certs != null) {
            return certs[0];
        }
        return null;
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
     *
     * @return a certificate array or null if nothing found
     */
    public X509Certificate[] getX509IssuerSerial(Crypto crypto) throws WSSecurityException {
        if (issuerSerial == null) {
            issuerSerial = getIssuerSerial();
            if (issuerSerial == null) {
                return null;
            }
        }
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ISSUER_SERIAL);
        cryptoType.setIssuerSerial(issuerSerial.getIssuer(), issuerSerial.getSerialNumber());
        return crypto.getX509Certificates(cryptoType);
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
                WSSecurityUtil.findElement(
                    elem, WSConstants.X509_ISSUER_SERIAL_LN, WSConstants.SIG_NS
                );
        }
        issuerSerial = new DOMX509IssuerSerial(elem);

        return issuerSerial;
    }

    /**
     * Method containsReference
     *
     * @return true if the <code>SecurityTokenReference</code> contains
     *         a <code>wsse:Reference</code> element
     */
    public boolean containsReference() {
        return lengthReference() > 0;
    }

    /**
     * Method lengthReference.
     *
     * @return number of <code>wsse:Reference</code> elements in
     *         the <code>SecurityTokenReference</code>
     */
    public int lengthReference() {
        return length(WSConstants.WSSE_NS, "Reference");
    }

    /**
     * Method containsX509IssuerSerial
     *
     * @return true if the <code>SecurityTokenReference</code> contains
     *         a <code>ds:IssuerSerial</code> element
     */
    public boolean containsX509IssuerSerial() {
        return lengthX509IssuerSerial() > 0;
    }

    /**
     * Method containsX509Data
     *
     * @return true if the <code>SecurityTokenReference</code> contains
     *         a <code>ds:X509Data</code> element
     */
    public boolean containsX509Data() {
        return lengthX509Data() > 0;
    }
    
    /**
     * Method lengthX509IssuerSerial.
     *
     * @return number of <code>ds:IssuerSerial</code> elements in
     *         the <code>SecurityTokenReference</code>
     */
    public int lengthX509IssuerSerial() {
        return length(WSConstants.SIG_NS, WSConstants.X509_ISSUER_SERIAL_LN);
    }

    /**
     * Method lengthX509Data.
     *
     * @return number of <code>ds:IssuerSerial</code> elements in
     *         the <code>SecurityTokenReference</code>
     */
    public int lengthX509Data() {
        return length(WSConstants.SIG_NS, WSConstants.X509_DATA_LN);
    }
    
    /**
     * Method containsKeyIdentifier.
     *
     * @return true if the <code>SecurityTokenReference</code> contains
     *         a <code>wsse:KeyIdentifier</code> element
     */
    public boolean containsKeyIdentifier() {
        return lengthKeyIdentifier() > 0;
    }
    
    /**
     * Method lengthKeyIdentifier.
     *
     * @return number of <code>wsse:KeyIdentifier</code> elements in
     *         the <code>SecurityTokenReference</code>
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
     * Get the DOM element.
     *
     * @return the DOM element
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
     * Get the id
     * @return the wsu ID of the element
     */
    public String getID() {
        return element.getAttributeNS(WSConstants.WSU_NS, "Id");
    }

    /**
     * return the string representation.
     *
     * @return a representation of this SecurityTokenReference element as a String
     */
    public String toString() {
        return DOM2Writer.nodeToString((Node) element);
    }
    
    /**
     * A method to check that the SecurityTokenReference is compliant with the BSP spec.
     * @throws WSSecurityException
     */
    private void checkBSPCompliance() throws WSSecurityException {
        // We can only have one token reference
        int result = 0;
        Node node = element.getFirstChild();
        Element child = null;
        while (node != null) {
            if (Node.ELEMENT_NODE == node.getNodeType()) {
                result++;
                child = (Element)node;
            }
            node = node.getNextSibling();
        }
        if (result != 1) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, "invalidDataRef"
            );
        }
        if ("KeyIdentifier".equals(child.getLocalName()) 
            && WSConstants.WSSE_NS.equals(child.getNamespaceURI())) {
            
            String valueType = getKeyIdentifierValueType();
            // ValueType cannot be null
            if (valueType == null || "".equals(valueType)) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY, "invalidValueType"
                );
            }
            String encodingType = getFirstElement().getAttribute("EncodingType");
            // Encoding Type must be equal to Base64Binary if it's specified
            if (encodingType != null && !"".equals(encodingType)
                && !BinarySecurity.BASE64_ENCODING.equals(encodingType)) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY, 
                    "badEncodingType", 
                    new Object[] {encodingType}
                );
            }
            // Encoding type must be specified other than for a SAML Assertion
            if (!WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(valueType) 
                && !WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(valueType)
                && (encodingType == null || "".equals(encodingType))) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY, "noEncodingType"
                );
            }
        } else if ("Embedded".equals(child.getLocalName())) {
            result = 0;
            node = child.getFirstChild();
            while (node != null) {
                if (Node.ELEMENT_NODE == node.getNodeType()) {
                    result++;
                    // We cannot have a SecurityTokenReference child element
                    if ("SecurityTokenReference".equals(node.getLocalName())
                        && WSConstants.WSSE_NS.equals(node.getNamespaceURI())) {
                        throw new WSSecurityException(
                            WSSecurityException.INVALID_SECURITY, "invalidEmbeddedRef"
                        );
                    }
                }
                node = node.getNextSibling();
            }
            // We can only have one embedded child
            if (result != 1) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY, "invalidEmbeddedRef"
                );
            }
        }
    }
    
    @Override
    public int hashCode() {
        int result = 17;
        try {
            Reference reference = getReference();
            if (reference != null) {
                result = 31 * result + reference.hashCode();
            }
        } catch (WSSecurityException e) {
            log.error(e);
        }
        String keyIdentifierEncodingType = getKeyIdentifierEncodingType();
        if (keyIdentifierEncodingType != null) {
            result = 31 * result + keyIdentifierEncodingType.hashCode();
        }
        String keyIdentifierValueType = getKeyIdentifierValueType();
        if (keyIdentifierValueType != null) {
            result = 31 * result + keyIdentifierValueType.hashCode();
        }
        String keyIdentifierValue = getKeyIdentifierValue();
        if (keyIdentifierValue != null) {
            result = 31 * result + keyIdentifierValue.hashCode();
        }
        String tokenType = getTokenType();
        if (tokenType != null) {
            result = 31 * result + tokenType.hashCode();
        }
        byte[] skiBytes = getSKIBytes();
        if (skiBytes != null) {
            result = 31 * result + Arrays.hashCode(skiBytes);
        }
        String issuer = null;
        BigInteger serialNumber = null;
        
        try {
            issuer = getIssuerSerial().getIssuer();
            serialNumber = getIssuerSerial().getSerialNumber();
        } catch (WSSecurityException e) {
           log.error(e);
        }
        if (issuer != null) {
            result = 31 * result + issuer.hashCode();
        }
        if (serialNumber != null) {
            result = 31 * result + serialNumber.hashCode();
        }
        return result;
    }
    
    @Override
    public boolean equals(Object object) {
        if (!(object instanceof SecurityTokenReference)) {
            return false;
        }
        SecurityTokenReference tokenReference = (SecurityTokenReference)object;
        try {
            if (!getReference().equals(tokenReference.getReference())) {
                return false;
            }
        } catch (WSSecurityException e) {
           log.error(e);
           return false;
        }
        if (!compare(getKeyIdentifierEncodingType(), tokenReference.getKeyIdentifierEncodingType())) {
            return false;
        }
        if (!compare(getKeyIdentifierValueType(), tokenReference.getKeyIdentifierValueType())) {
            return false;
        }
        if (!compare(getKeyIdentifierValue(), tokenReference.getKeyIdentifierValue())) {
            return false;
        }
        if (!compare(getTokenType(), tokenReference.getTokenType())) {
            return false;
        }
        if (!Arrays.equals(getSKIBytes(), tokenReference.getSKIBytes())) {
            return false;
        }
        try {
            if (getIssuerSerial() != null && tokenReference.getIssuerSerial() != null) {
                if (!compare(getIssuerSerial().getIssuer(), tokenReference.getIssuerSerial().getIssuer())) {
                    return false;
                }
                if (!compare(getIssuerSerial().getSerialNumber(), tokenReference.getIssuerSerial().getSerialNumber())) {
                    return false;
                } 
            }
        } catch (WSSecurityException e) {
           log.error(e);
           return false;
        }
            
        return true;
    }
    
    private boolean compare(String item1, String item2) {
        if (item1 == null && item2 != null) { 
            return false;
        } else if (item1 != null && !item1.equals(item2)) {
            return false;
        }
        return true;
    }
    
    private boolean compare(BigInteger item1, BigInteger item2) {
        if (item1 == null && item2 != null) { 
            return false;
        } else if (item1 != null && !item1.equals(item2)) {
            return false;
        }
        return true;
    }
}
