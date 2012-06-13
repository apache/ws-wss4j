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
import org.apache.ws.security.SAMLTokenPrincipal;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDerivedKeyTokenPrincipal;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.BinarySecurity;
import org.apache.ws.security.message.token.DerivedKeyToken;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityContextToken;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.processor.Processor;
import org.apache.ws.security.saml.SAMLKeyInfo;
import org.apache.ws.security.saml.SAMLUtil;
import org.apache.ws.security.saml.ext.AssertionWrapper;
import org.apache.ws.security.saml.ext.OpenSAMLUtil;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Element;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
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
    
    private boolean trustedCredential;
    
    private REFERENCE_TYPE referenceType;
    
    /**
     * Parse a SecurityTokenReference element and extract credentials.
     * 
     * @param strElement The SecurityTokenReference element
     * @param data the RequestData associated with the request
     * @param wsDocInfo The WSDocInfo object to access previous processing results
     * @param parameters A set of implementation-specific parameters
     * @throws WSSecurityException
     */
    public void parseSecurityTokenReference(
        Element strElement,
        RequestData data,
        WSDocInfo wsDocInfo,
        Map<String, Object> parameters
    ) throws WSSecurityException {
        boolean bspCompliant = true;
        Crypto crypto = data.getSigCrypto();
        if (data.getWssConfig() != null) {
            bspCompliant = data.getWssConfig().isWsiBSPCompliant();
        }
        SecurityTokenReference secRef = new SecurityTokenReference(strElement, bspCompliant);
        //
        // Here we get some information about the document that is being
        // processed, in particular the crypto implementation, and already
        // detected BST that may be used later during dereferencing.
        //
        String uri = null;
        if (secRef.containsReference()) {
            uri = secRef.getReference().getURI();
            if (uri.charAt(0) == '#') {
                uri = uri.substring(1);
            }
            referenceType = REFERENCE_TYPE.DIRECT_REF;
        } else if (secRef.containsKeyIdentifier()) {
            uri = secRef.getKeyIdentifierValue();
            if (SecurityTokenReference.THUMB_URI.equals(secRef.getKeyIdentifierValueType())) {
                referenceType = REFERENCE_TYPE.THUMBPRINT_SHA1;
            } else {
                referenceType = REFERENCE_TYPE.KEY_IDENTIFIER;
            }
        }
        
        WSSecurityEngineResult result = wsDocInfo.getResult(uri);
        if (result != null) {
            processPreviousResult(result, secRef, data, parameters, bspCompliant);
        } else if (secRef.containsReference()) {
            Reference reference = secRef.getReference();
            // Try asking the CallbackHandler for the secret key
            secretKey = getSecretKeyFromToken(uri, reference.getValueType(), data);
            principal = new CustomTokenPrincipal(uri);
            
            if (secretKey == null) {
                Element token = 
                    secRef.getTokenElement(strElement.getOwnerDocument(), wsDocInfo, data.getCallbackHandler());
                QName el = new QName(token.getNamespaceURI(), token.getLocalName());
                if (el.equals(WSSecurityEngine.BINARY_TOKEN)) {
                    Processor proc = data.getWssConfig().getProcessor(WSSecurityEngine.BINARY_TOKEN);
                    List<WSSecurityEngineResult> bstResult =
                        proc.handleToken(token, data, wsDocInfo);
                    BinarySecurity bstToken = 
                        (BinarySecurity)bstResult.get(0).get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
                    if (bspCompliant) {
                        BSPEnforcer.checkBinarySecurityBSPCompliance(secRef, bstToken);
                    }
                    certs = (X509Certificate[])bstResult.get(0).get(WSSecurityEngineResult.TAG_X509_CERTIFICATES);
                    secretKey = (byte[])bstResult.get(0).get(WSSecurityEngineResult.TAG_SECRET);
                    principal = (Principal)bstResult.get(0).get(WSSecurityEngineResult.TAG_PRINCIPAL);
                } else if (el.equals(WSSecurityEngine.SAML_TOKEN) 
                    || el.equals(WSSecurityEngine.SAML2_TOKEN)) {
                    Processor proc = data.getWssConfig().getProcessor(WSSecurityEngine.SAML_TOKEN);
                    //
                    // Just check to see whether the token was processed or not
                    //
                    Element processedToken = 
                        secRef.findProcessedTokenElement(
                            strElement.getOwnerDocument(), wsDocInfo, 
                            data.getCallbackHandler(), uri, secRef.getReference().getValueType()
                        );
                    AssertionWrapper assertion = null;
                    if (processedToken == null) {
                        List<WSSecurityEngineResult> samlResult =
                            proc.handleToken(token, data, wsDocInfo);
                        assertion = 
                            (AssertionWrapper)samlResult.get(0).get(
                                WSSecurityEngineResult.TAG_SAML_ASSERTION
                            );
                    } else {
                        assertion = new AssertionWrapper(processedToken);
                        assertion.parseHOKSubject(data, wsDocInfo);
                    }
                    if (bspCompliant) {
                        BSPEnforcer.checkSamlTokenBSPCompliance(secRef, assertion);
                    }
                    SAMLKeyInfo keyInfo = assertion.getSubjectKeyInfo();
                    X509Certificate[] foundCerts = keyInfo.getCerts();
                    if (foundCerts != null && foundCerts.length > 0) {
                        certs = new X509Certificate[]{foundCerts[0]};
                    }
                    secretKey = keyInfo.getSecret();
                    principal = createPrincipalFromSAML(assertion);
                } else if (el.equals(WSSecurityEngine.ENCRYPTED_KEY)) {
                    if (bspCompliant) {
                        BSPEnforcer.checkEncryptedKeyBSPCompliance(secRef);
                    }
                    Processor proc = data.getWssConfig().getProcessor(WSSecurityEngine.ENCRYPTED_KEY);
                    List<WSSecurityEngineResult> encrResult =
                        proc.handleToken(token, data, wsDocInfo);
                    secretKey = 
                        (byte[])encrResult.get(0).get(WSSecurityEngineResult.TAG_SECRET);
                    principal = new CustomTokenPrincipal(token.getAttribute("Id"));
                }
            }
        } else if (secRef.containsX509Data() || secRef.containsX509IssuerSerial()) {
            referenceType = REFERENCE_TYPE.ISSUER_SERIAL;
            X509Certificate[] foundCerts = secRef.getX509IssuerSerial(crypto);
            if (foundCerts != null && foundCerts.length > 0) {
                certs = new X509Certificate[]{foundCerts[0]};
            }
        } else if (secRef.containsKeyIdentifier()) {
            if (secRef.getKeyIdentifierValueType().equals(SecurityTokenReference.ENC_KEY_SHA1_URI)) {
                if (bspCompliant) {
                    BSPEnforcer.checkEncryptedKeyBSPCompliance(secRef);
                }
                String id = secRef.getKeyIdentifierValue();
                secretKey = 
                    getSecretKeyFromToken(id, SecurityTokenReference.ENC_KEY_SHA1_URI, data);
                principal = new CustomTokenPrincipal(id);
            } else if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())
                || WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())) {
                parseSAMLKeyIdentifier(secRef, wsDocInfo, data, bspCompliant);
            } else {
                parseBSTKeyIdentifier(secRef, crypto, wsDocInfo, data, bspCompliant);
            }
        } else {
            throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY,
                    "unsupportedKeyInfo", 
                    new Object[]{strElement.toString()}
            );
        }
        
        if (certs != null && certs.length > 0 && principal == null) {
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
     * Get whether the returned credential is already trusted or not. This is currently
     * applicable in the case of a credential extracted from a trusted HOK SAML Assertion,
     * and a BinarySecurityToken that has been processed by a Validator. In these cases,
     * the SignatureProcessor does not need to verify trust on the credential.
     * @return true if trust has already been verified on the returned Credential
     */
    public boolean isTrustedCredential() {
        return trustedCredential;
    }
    
    /**
     * Get how the certificates were referenced
     * @return how the certificates were referenced
     */
    public REFERENCE_TYPE getCertificatesReferenceType() {
        return referenceType;
    }
    
    /**
     * A method to create a Principal from a SAML Assertion
     * @param assertion An AssertionWrapper object
     * @return A principal
     */
    private Principal createPrincipalFromSAML(
        AssertionWrapper assertion
    ) {
        SAMLTokenPrincipal samlPrincipal = new SAMLTokenPrincipal(assertion);
        String confirmMethod = null;
        List<String> methods = assertion.getConfirmationMethods();
        if (methods != null && methods.size() > 0) {
            confirmMethod = methods.get(0);
        }
        if (OpenSAMLUtil.isMethodHolderOfKey(confirmMethod) && assertion.isSigned()) {
            trustedCredential = true;
        }
        return samlPrincipal;
    }
    
    /**
     * Get the Secret Key from a CallbackHandler
     * @param id The id of the element
     * @param type The type of the element (can be null)
     * @param cb The CallbackHandler object
     * @return A Secret Key
     * @throws WSSecurityException
     */
    private byte[] getSecretKeyFromToken(
        String id,
        String type,
        RequestData data
    ) throws WSSecurityException {
        if (id.charAt(0) == '#') {
            id = id.substring(1);
        }
        WSPasswordCallback pwcb = 
            new WSPasswordCallback(id, null, type, WSPasswordCallback.SECRET_KEY, data);
        try {
            Callback[] callbacks = new Callback[]{pwcb};
            if (data.getCallbackHandler() != null) {
                data.getCallbackHandler().handle(callbacks);
                return pwcb.getKey();
            }
        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.FAILURE,
                "noPassword", 
                new Object[] {id}, 
                e
            );
        }

        return null;
    }
    
    /**
     * Parse the KeyIdentifier for a SAML Assertion
     */
    private void parseSAMLKeyIdentifier(
        SecurityTokenReference secRef,
        WSDocInfo wsDocInfo,
        RequestData data,
        boolean bspCompliant
    ) throws WSSecurityException {
        String valueType = secRef.getKeyIdentifierValueType();
        secretKey = getSecretKeyFromToken(secRef.getKeyIdentifierValue(), valueType, data);
        if (secretKey == null) {
            AssertionWrapper assertion = 
                SAMLUtil.getAssertionFromKeyIdentifier(
                    secRef, secRef.getElement(), data, wsDocInfo
                );
            if (bspCompliant) {
                BSPEnforcer.checkSamlTokenBSPCompliance(secRef, assertion);
            }
            SAMLKeyInfo samlKi = 
                SAMLUtil.getCredentialFromSubject(assertion, data, wsDocInfo, bspCompliant);
            X509Certificate[] foundCerts = samlKi.getCerts();
            if (foundCerts != null && foundCerts.length > 0) {
                certs = new X509Certificate[]{foundCerts[0]};
            }
            secretKey = samlKi.getSecret();
            publicKey = samlKi.getPublicKey();
            principal = createPrincipalFromSAML(assertion);
        }
    }
    
    /**
     * Parse the KeyIdentifier for a BinarySecurityToken
     */
    private void parseBSTKeyIdentifier(
        SecurityTokenReference secRef,
        Crypto crypto,
        WSDocInfo wsDocInfo,
        RequestData data,
        boolean bspCompliant
    ) throws WSSecurityException {
        if (bspCompliant) {
            BSPEnforcer.checkBinarySecurityBSPCompliance(secRef, null);
        }
        String valueType = secRef.getKeyIdentifierValueType();
        if (WSConstants.WSS_KRB_KI_VALUE_TYPE.equals(valueType)) {
            secretKey = 
                getSecretKeyFromToken(secRef.getKeyIdentifierValue(), valueType, data);
            if (secretKey == null) {
                byte[] keyBytes = secRef.getSKIBytes();
                List<WSSecurityEngineResult> resultsList = 
                    wsDocInfo.getResultsByTag(WSConstants.BST);
                for (WSSecurityEngineResult bstResult : resultsList) {
                    BinarySecurity bstToken = 
                        (BinarySecurity)bstResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
                    byte[] tokenDigest = WSSecurityUtil.generateDigest(bstToken.getToken());
                    if (Arrays.equals(tokenDigest, keyBytes)) {
                        secretKey = (byte[])bstResult.get(WSSecurityEngineResult.TAG_SECRET);
                        principal = (Principal)bstResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
                        break;
                    }
                }
            } else {
                principal = new CustomTokenPrincipal(secRef.getKeyIdentifierValue());
            }
        } else {
            X509Certificate[] foundCerts = secRef.getKeyIdentifier(crypto);
            if (foundCerts == null) {
                // The reference may be to a BST in the security header rather than in the keystore
                if (SecurityTokenReference.SKI_URI.equals(valueType)) {
                    byte[] skiBytes = secRef.getSKIBytes();
                    List<WSSecurityEngineResult> resultsList = 
                        wsDocInfo.getResultsByTag(WSConstants.BST);
                    for (WSSecurityEngineResult bstResult : resultsList) {
                        X509Certificate[] certs = 
                            (X509Certificate[])bstResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATES);
                        if (certs != null
                            && Arrays.equals(skiBytes, crypto.getSKIBytesFromCert(certs[0]))) {
                            principal = (Principal)bstResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
                            foundCerts = certs;
                            break;
                        }
                    }
                } else if (SecurityTokenReference.THUMB_URI.equals(valueType)) {
                    String kiValue = secRef.getKeyIdentifierValue();
                    List<WSSecurityEngineResult> resultsList = 
                        wsDocInfo.getResultsByTag(WSConstants.BST);
                    for (WSSecurityEngineResult bstResult : resultsList) {
                        X509Certificate[] certs = 
                            (X509Certificate[])bstResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATES);
                        if (certs != null) {
                            try {
                                byte[] digest = WSSecurityUtil.generateDigest(certs[0].getEncoded());
                                if (Arrays.equals(Base64.decode(kiValue), digest)) {
                                    principal = (Principal)bstResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
                                    foundCerts = certs;
                                    break;
                                }
                            } catch (CertificateEncodingException ex) {
                                throw new WSSecurityException(
                                    WSSecurityException.SECURITY_TOKEN_UNAVAILABLE, "encodeError",
                                    null, ex
                                );
                            }
                        }
                    }
                }
            }
            if (foundCerts != null) {
                certs = new X509Certificate[]{foundCerts[0]};
            }
        }
    }
    
    /**
     * Process a previous security result
     */
    private void processPreviousResult(
        WSSecurityEngineResult result,
        SecurityTokenReference secRef,
        RequestData data,
        Map<String, Object> parameters,
        boolean bspCompliant
    ) throws WSSecurityException {
        int action = ((Integer)result.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
        if (WSConstants.UT_NOPASSWORD == action || WSConstants.UT == action) {
            if (bspCompliant) {
                BSPEnforcer.checkUsernameTokenBSPCompliance(secRef);
            }
            UsernameToken usernameToken = 
                (UsernameToken)result.get(WSSecurityEngineResult.TAG_USERNAME_TOKEN);

            usernameToken.setRawPassword(data);
            if (usernameToken.isDerivedKey()) {
                secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
            } else {
                int keyLength = ((Integer)parameters.get(SECRET_KEY_LENGTH)).intValue();
                secretKey = usernameToken.getSecretKey(keyLength);
            }
            principal = usernameToken.createPrincipal();
        } else if (WSConstants.BST == action) {
            if (bspCompliant) {
                BinarySecurity token = 
                    (BinarySecurity)result.get(
                        WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN
                    );
                BSPEnforcer.checkBinarySecurityBSPCompliance(secRef, token);
            }
            certs = 
                (X509Certificate[])result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATES);
            secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
            Boolean validatedToken = 
                (Boolean)result.get(WSSecurityEngineResult.TAG_VALIDATED_TOKEN);
            if (validatedToken.booleanValue()) {
                trustedCredential = true;
            }
        } else if (WSConstants.ENCR == action) {
            if (bspCompliant) {
                BSPEnforcer.checkEncryptedKeyBSPCompliance(secRef);
            }
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
            ((WSDerivedKeyTokenPrincipal)principal).setSecret(secret);
        } else if (WSConstants.ST_UNSIGNED == action || WSConstants.ST_SIGNED == action) {
            AssertionWrapper assertion = 
                (AssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
            if (bspCompliant) {
                BSPEnforcer.checkSamlTokenBSPCompliance(secRef, assertion);
            }
            SAMLKeyInfo keyInfo = assertion.getSubjectKeyInfo();
            if (keyInfo == null) {
                throw new WSSecurityException(
                    WSSecurityException.FAILURE, "invalidSAMLsecurity"
                );
            }
            X509Certificate[] foundCerts = keyInfo.getCerts();
            if (foundCerts != null) {
                certs = new X509Certificate[]{foundCerts[0]};
            }
            secretKey = keyInfo.getSecret();
            publicKey = keyInfo.getPublicKey();
            principal = createPrincipalFromSAML(assertion);
        }
    }
    
    
}
