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

package org.apache.ws.security.str;

import org.apache.ws.security.CustomTokenPrincipal;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.DerivedKeyToken;
import org.apache.ws.security.message.token.PKIPathSecurity;
import org.apache.ws.security.message.token.SecurityContextToken;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.processor.EncryptedKeyProcessor;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.SAMLUtil;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Element;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

/**
 * This implementation of STRParser is for parsing a SecurityTokenReference element, found in the
 * KeyInfo element associated with a Signature element.
 */
public class SignatureSTRParser implements STRParser {
    
    /**
     * The Signature method. This is used when deriving a key to use for verifying the signature.
     */
    public static final String SIGNATURE_METHOD = "signature_method";
    
    /**
     * The secret key length. This is used when deriving a key from a Username token for the
     * non-standard WSE implementation.
     */
    public static final String SECRET_KEY_LENGTH = "secret_key_length";
    
    private X509Certificate[] certs;
    
    private byte[] secretKey;
    
    private PublicKey publicKey;
    
    private Principal principal;
    
    /**
     * Parse a SecurityTokenReference element and extract credentials.
     * 
     * @param strElement The SecurityTokenReference element
     * @param crypto The crypto instance used to extract credentials
     * @param cb The CallbackHandler instance to supply passwords
     * @param wsDocInfo The WSDocInfo object to access previous processing results
     * @param parameters A set of implementation-specific parameters
     * @throws WSSecurityException
     */
    public void parseSecurityTokenReference(
        Element strElement,
        Crypto crypto,
        CallbackHandler cb,
        WSDocInfo wsDocInfo,
        Map<String, Object> parameters
    ) throws WSSecurityException {
        SecurityTokenReference secRef = new SecurityTokenReference(strElement);
        //
        // Here we get some information about the document that is being
        // processed, in particular the crypto implementation, and already
        // detected BST that may be used later during dereferencing.
        //
        if (secRef.containsReference()) {
            org.apache.ws.security.message.token.Reference ref = secRef.getReference();

            String uri = ref.getURI();
            if (uri.charAt(0) == '#') {
                uri = uri.substring(1);
            }
            WSSecurityEngineResult result = wsDocInfo.getResult(uri);
            if (result == null) {
                Element token = 
                    secRef.getTokenElement(strElement.getOwnerDocument(), wsDocInfo, cb);
                QName el = new QName(token.getNamespaceURI(), token.getLocalName());
                if (el.equals(WSSecurityEngine.BINARY_TOKEN)) {
                    certs = getCertificatesTokenReference(token, crypto);
                } else if (el.equals(WSSecurityEngine.SAML_TOKEN) 
                    || el.equals(WSSecurityEngine.SAML2_TOKEN)) {
                    if (crypto == null) {
                        throw new WSSecurityException(
                                WSSecurityException.FAILURE, "noSigCryptoFile"
                        );
                    }
                    AssertionWrapper assertion = new AssertionWrapper(token);
                    SAMLKeyInfo samlKi = SAMLUtil.getCredentialFromSubject(assertion, crypto, cb);
                    X509Certificate[] foundCerts = samlKi.getCerts();
                    if (foundCerts != null) {
                        certs = new X509Certificate[]{foundCerts[0]};
                    }
                    secretKey = samlKi.getSecret();
                    principal = createPrincipalFromSAMLKeyInfo(samlKi, assertion);
                } else if (el.equals(WSSecurityEngine.ENCRYPTED_KEY)){
                    EncryptedKeyProcessor proc = 
                        new EncryptedKeyProcessor();
                    WSDocInfo docInfo = new WSDocInfo(token.getOwnerDocument());
                    List<WSSecurityEngineResult> encrResult =
                        proc.handleToken(token, null, crypto, cb, docInfo, null);
                    secretKey = 
                        (byte[])encrResult.get(0).get(
                            WSSecurityEngineResult.TAG_SECRET
                        );
                    principal = new CustomTokenPrincipal(token.getAttribute("Id"));
                } else {
                    String id = secRef.getReference().getURI();
                    secretKey = getSecretKeyFromCustomToken(id, cb);
                    principal = new CustomTokenPrincipal(id);
                }
            } else {
                int action = ((Integer)result.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
                if (WSConstants.UT == action) {
                    UsernameToken usernameToken = 
                        (UsernameToken)result.get(WSSecurityEngineResult.TAG_USERNAME_TOKEN);

                    if (usernameToken.isDerivedKey()) {
                        secretKey = usernameToken.getDerivedKey();
                    } else {
                        int keyLength = ((Integer)parameters.get(SECRET_KEY_LENGTH)).intValue();
                        secretKey = usernameToken.getSecretKey(keyLength);
                    }
                    principal = usernameToken.createPrincipal();
                } else if (WSConstants.BST == action) {
                    certs = 
                        (X509Certificate[])result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATES);
                } else if (WSConstants.ENCR == action) {
                    secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
                    String id = (String)result.get(WSSecurityEngineResult.TAG_ID);
                    principal = new CustomTokenPrincipal(id);
                } else if (WSConstants.SCT == action) {
                    secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
                    SecurityContextToken sct = 
                        (SecurityContextToken)result.get(
                                WSSecurityEngineResult.TAG_SECURITY_CONTEXT_TOKEN
                        );
                    principal = new CustomTokenPrincipal(sct.getIdentifier());
                } else if (WSConstants.DKT == action) {
                    DerivedKeyToken dkt = 
                        (DerivedKeyToken)result.get(WSSecurityEngineResult.TAG_DERIVED_KEY_TOKEN);
                    int keyLength = dkt.getLength();
                    if (keyLength <= 0) {
                        String algorithm = (String)parameters.get(SIGNATURE_METHOD);
                        keyLength = WSSecurityUtil.getKeyLength(algorithm);
                    }
                    byte[] secret = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
                    secretKey = dkt.deriveKey(keyLength, secret); 
                    principal = dkt.createPrincipal();
                } else if (WSConstants.ST_UNSIGNED == action || WSConstants.ST_SIGNED == action) {
                    if (crypto == null) {
                        throw new WSSecurityException(
                            WSSecurityException.FAILURE, "noSigCryptoFile"
                        );
                    }
                    AssertionWrapper assertion = 
                        (AssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
                    SAMLKeyInfo keyInfo = assertion.getSubjectKeyInfo();
                    X509Certificate[] foundCerts = keyInfo.getCerts();
                    if (foundCerts != null) {
                        certs = new X509Certificate[]{foundCerts[0]};
                    }
                    secretKey = keyInfo.getSecret();
                    publicKey = keyInfo.getPublicKey();
                    principal = createPrincipalFromSAMLKeyInfo(keyInfo, assertion);
                }
            }
        } else if (secRef.containsX509Data() || secRef.containsX509IssuerSerial()) {
            X509Certificate[] foundCerts = secRef.getX509IssuerSerial(crypto);
            if (foundCerts != null) {
                certs = new X509Certificate[]{foundCerts[0]};
            }
        } else if (secRef.containsKeyIdentifier()) {
            if (secRef.getKeyIdentifierValueType().equals(SecurityTokenReference.ENC_KEY_SHA1_URI)) {
                String id = secRef.getKeyIdentifierValue();
                secretKey = getSecretKeyFromEncKeySHA1KI(id, cb);
                principal = new CustomTokenPrincipal(id);
            } else if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())
                || WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())) {
                AssertionWrapper assertion = 
                    SAMLUtil.getAssertionFromKeyIdentifier(
                        secRef, strElement, crypto, cb, wsDocInfo
                    );
                SAMLKeyInfo samlKi = SAMLUtil.getCredentialFromSubject(assertion, crypto, cb);
                X509Certificate[] foundCerts = samlKi.getCerts();
                if (foundCerts != null) {
                    certs = new X509Certificate[]{foundCerts[0]};
                }
                secretKey = samlKi.getSecret();
                publicKey = samlKi.getPublicKey();
                principal = createPrincipalFromSAMLKeyInfo(samlKi, assertion);
            } else {
                X509Certificate[] foundCerts = secRef.getKeyIdentifier(crypto);
                if (foundCerts != null) {
                    certs = new X509Certificate[]{foundCerts[0]};
                }
            }
        } else {
            throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY,
                    "unsupportedKeyInfo", 
                    new Object[]{strElement.toString()}
            );
        }
        
        if (certs != null && principal == null) {
            principal = certs[0].getSubjectX500Principal();
        }
    }
    
    /**
     * Get the X509Certificates associated with this SecurityTokenReference
     * @return the X509Certificates associated with this SecurityTokenReference
     */
    public X509Certificate[] getCertificates() {
        return certs;
    }
    
    /**
     * Get the Principal associated with this SecurityTokenReference
     * @return the Principal associated with this SecurityTokenReference
     */
    public Principal getPrincipal() {
        return principal;
    }
    
    /**
     * Get the PublicKey associated with this SecurityTokenReference
     * @return the PublicKey associated with this SecurityTokenReference
     */
    public PublicKey getPublicKey() {
        return publicKey;
    }
    
    /**
     * Get the Secret Key associated with this SecurityTokenReference
     * @return the Secret Key associated with this SecurityTokenReference
     */
    public byte[] getSecretKey() {
        return secretKey;
    }
    
    
    /**
     * Extracts the certificate(s) from the Binary Security token reference.
     *
     * @param elem The element containing the binary security token. This is
     *             either X509 certificate(s) or a PKIPath.
     * @return an array of X509 certificates
     * @throws WSSecurityException
     */
    private static X509Certificate[] getCertificatesTokenReference(Element elem, Crypto crypto)
        throws WSSecurityException {
        if (crypto == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noSigCryptoFile");
        }
        BinarySecurity token = createSecurityToken(elem);
        if (token instanceof PKIPathSecurity) {
            return ((PKIPathSecurity) token).getX509Certificates(crypto);
        } else {
            X509Certificate cert = ((X509Security) token).getX509Certificate(crypto);
            return new X509Certificate[]{cert};
        }
    }


    /**
     * Checks the <code>element</code> and creates appropriate binary security object.
     *
     * @param element The XML element that contains either a <code>BinarySecurityToken
     *                </code> or a <code>PKIPath</code> element. Other element types a not
     *                supported
     * @return the BinarySecurity object, either a <code>X509Security</code> or a
     *         <code>PKIPathSecurity</code> object.
     * @throws WSSecurityException
     */
    private static BinarySecurity createSecurityToken(Element element) throws WSSecurityException {

        String type = element.getAttribute("ValueType");
        if (X509Security.X509_V3_TYPE.equals(type)) {
            X509Security x509 = new X509Security(element);
            return (BinarySecurity) x509;
        } else if (PKIPathSecurity.getType().equals(type)) {
            PKIPathSecurity pkiPath = new PKIPathSecurity(element);
            return (BinarySecurity) pkiPath;
        }
        throw new WSSecurityException(
            WSSecurityException.UNSUPPORTED_SECURITY_TOKEN,
            "unsupportedBinaryTokenType", 
            new Object[]{type}
        );
    }
    
    /**
     * A method to create a Principal from a SAML KeyInfo
     * @param samlKeyInfo The SAML KeyInfo object
     * @param assertion An AssertionWrapper object
     * @return A principal
     */
    private static Principal createPrincipalFromSAMLKeyInfo(
        SAMLKeyInfo samlKeyInfo,
        AssertionWrapper assertion
    ) {
        X509Certificate[] samlCerts = samlKeyInfo.getCerts();
        Principal principal = null;
        if (samlCerts != null && samlCerts.length > 0) {
            principal = samlCerts[0].getSubjectX500Principal();
        } else {
            principal = new CustomTokenPrincipal(assertion.getId());
            ((CustomTokenPrincipal)principal).setTokenObject(assertion);
        }
        return principal;
    }
    
    /**
     * Get the Secret Key from a CallbackHandler for a custom token
     * @param id The id of the element
     * @param cb The CallbackHandler object
     * @return A Secret Key
     * @throws WSSecurityException
     */
    private byte[] getSecretKeyFromCustomToken(
        String id,
        CallbackHandler cb
    ) throws WSSecurityException {
        if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        WSPasswordCallback pwcb = 
            new WSPasswordCallback(id, WSPasswordCallback.CUSTOM_TOKEN);
        try {
            Callback[] callbacks = new Callback[]{pwcb};
            cb.handle(callbacks);
        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword", 
                new Object[] {id}, 
                e
            );
        }

        return pwcb.getKey();
    }
    
    /**
     * Get the Secret Key from a CallbackHandler for the Encrypted Key SHA1 case.
     * @param id The id of the element
     * @param cb The CallbackHandler object
     * @return A Secret Key
     * @throws WSSecurityException
     */
    private byte[] getSecretKeyFromEncKeySHA1KI(
        String id,
        CallbackHandler cb
    ) throws WSSecurityException {
        WSPasswordCallback pwcb = 
            new WSPasswordCallback(
                id,
                null,
                SecurityTokenReference.ENC_KEY_SHA1_URI,
                WSPasswordCallback.ENCRYPTED_KEY_TOKEN
            );
        try {
            Callback[] callbacks = new Callback[]{pwcb};
            cb.handle(callbacks);
        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword", 
                new Object[] {id}, 
                e
            );
        }
        return pwcb.getKey();
    }
    
}
