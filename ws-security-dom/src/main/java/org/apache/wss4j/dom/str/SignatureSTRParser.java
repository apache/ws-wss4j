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

package org.apache.wss4j.dom.str;

import java.security.Principal;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.xml.namespace.QName;

import org.apache.wss4j.common.principal.SAMLTokenPrincipalImpl;
import org.w3c.dom.Element;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.principal.CustomTokenPrincipal;
import org.apache.wss4j.common.principal.WSDerivedKeyTokenPrincipal;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.WSSecurityEngine;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.BinarySecurity;
import org.apache.wss4j.dom.message.token.DerivedKeyToken;
import org.apache.wss4j.dom.message.token.Reference;
import org.apache.wss4j.dom.message.token.SecurityContextToken;
import org.apache.wss4j.dom.message.token.SecurityTokenReference;
import org.apache.wss4j.dom.message.token.UsernameToken;
import org.apache.wss4j.dom.processor.Processor;
import org.apache.wss4j.dom.saml.WSSSAMLKeyInfoProcessor;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;

/**
 * This implementation of STRParser is for parsing a SecurityTokenReference element, found in the
 * KeyInfo element associated with a Signature element.
 */
public class SignatureSTRParser implements STRParser {
    
    /**
     * The Signature method. This is used when deriving a key to use for verifying the signature.
     */
    public static final String SIGNATURE_METHOD = "signature_method";
    
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
        Crypto crypto = data.getSigVerCrypto();
        SecurityTokenReference secRef = 
            new SecurityTokenReference(strElement, data.getBSPEnforcer());
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
            processPreviousResult(result, secRef, data, parameters);
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
                    STRParserUtil.checkBinarySecurityBSPCompliance(
                        secRef, bstToken, data.getBSPEnforcer()
                    );
                    
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
                    SamlAssertionWrapper samlAssertion = null;
                    if (processedToken == null) {
                        List<WSSecurityEngineResult> samlResult =
                            proc.handleToken(token, data, wsDocInfo);
                        samlAssertion =
                            (SamlAssertionWrapper)samlResult.get(0).get(
                                WSSecurityEngineResult.TAG_SAML_ASSERTION
                            );
                    } else {
                        samlAssertion = new SamlAssertionWrapper(processedToken);
                        samlAssertion.parseSubject(
                            new WSSSAMLKeyInfoProcessor(data, wsDocInfo), 
                            data.getSigVerCrypto(), data.getCallbackHandler()
                        );
                    }
                    STRParserUtil.checkSamlTokenBSPCompliance(secRef, samlAssertion, data.getBSPEnforcer());
                    
                    SAMLKeyInfo keyInfo = samlAssertion.getSubjectKeyInfo();
                    X509Certificate[] foundCerts = keyInfo.getCerts();
                    if (foundCerts != null && foundCerts.length > 0) {
                        certs = new X509Certificate[]{foundCerts[0]};
                    }
                    secretKey = keyInfo.getSecret();
                    principal = createPrincipalFromSAML(samlAssertion);
                } else if (el.equals(WSSecurityEngine.ENCRYPTED_KEY)) {
                    STRParserUtil.checkEncryptedKeyBSPCompliance(secRef, data.getBSPEnforcer());
                    Processor proc = data.getWssConfig().getProcessor(WSSecurityEngine.ENCRYPTED_KEY);
                    List<WSSecurityEngineResult> encrResult =
                        proc.handleToken(token, data, wsDocInfo);
                    secretKey = 
                        (byte[])encrResult.get(0).get(WSSecurityEngineResult.TAG_SECRET);
                    principal = new CustomTokenPrincipal(token.getAttributeNS(null, "Id"));
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
                STRParserUtil.checkEncryptedKeyBSPCompliance(secRef, data.getBSPEnforcer());
                
                String id = secRef.getKeyIdentifierValue();
                secretKey = 
                    getSecretKeyFromToken(id, SecurityTokenReference.ENC_KEY_SHA1_URI, data);
                principal = new CustomTokenPrincipal(id);
            } else if (WSConstants.WSS_SAML_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())
                || WSConstants.WSS_SAML2_KI_VALUE_TYPE.equals(secRef.getKeyIdentifierValueType())) {
                parseSAMLKeyIdentifier(secRef, wsDocInfo, data);
            } else {
                parseBSTKeyIdentifier(secRef, crypto, wsDocInfo, data);
            }
        } else {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.INVALID_SECURITY,
                    "unsupportedKeyInfo", strElement.toString());
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
     * @param samlAssertion An SamlAssertionWrapper object
     * @return A principal
     */
    private Principal createPrincipalFromSAML(
        SamlAssertionWrapper samlAssertion
    ) {
        SAMLTokenPrincipalImpl samlPrincipal = new SAMLTokenPrincipalImpl(samlAssertion);
        String confirmMethod = null;
        List<String> methods = samlAssertion.getConfirmationMethods();
        if (methods != null && methods.size() > 0) {
            confirmMethod = methods.get(0);
        }
        if (OpenSAMLUtil.isMethodHolderOfKey(confirmMethod) && samlAssertion.isSigned()) {
            trustedCredential = true;
        }
        return samlPrincipal;
    }
    
    /**
     * Get the Secret Key from a CallbackHandler
     * @param id The id of the element
     * @param type The type of the element (can be null)
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
            new WSPasswordCallback(id, null, type, WSPasswordCallback.SECRET_KEY);
        try {
            Callback[] callbacks = new Callback[]{pwcb};
            if (data.getCallbackHandler() != null) {
                data.getCallbackHandler().handle(callbacks);
                return pwcb.getKey();
            }
        } catch (Exception e) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE,
                "noPassword", 
                e, id);
        }

        return null;
    }
    
    /**
     * Parse the KeyIdentifier for a SAML Assertion
     */
    private void parseSAMLKeyIdentifier(
        SecurityTokenReference secRef,
        WSDocInfo wsDocInfo,
        RequestData data
    ) throws WSSecurityException {
        String valueType = secRef.getKeyIdentifierValueType();
        secretKey = getSecretKeyFromToken(secRef.getKeyIdentifierValue(), valueType, data);
        if (secretKey == null) {
            SamlAssertionWrapper samlAssertion =
                STRParserUtil.getAssertionFromKeyIdentifier(
                    secRef, secRef.getElement(), data, wsDocInfo
                );
            STRParserUtil.checkSamlTokenBSPCompliance(secRef, samlAssertion, data.getBSPEnforcer());
            
            SAMLKeyInfo samlKi = 
                SAMLUtil.getCredentialFromSubject(samlAssertion,
                        new WSSSAMLKeyInfoProcessor(data, wsDocInfo), 
                        data.getSigVerCrypto(), data.getCallbackHandler());
            X509Certificate[] foundCerts = samlKi.getCerts();
            if (foundCerts != null && foundCerts.length > 0) {
                certs = new X509Certificate[]{foundCerts[0]};
            }
            secretKey = samlKi.getSecret();
            publicKey = samlKi.getPublicKey();
            principal = createPrincipalFromSAML(samlAssertion);
        }
    }
    
    /**
     * Parse the KeyIdentifier for a BinarySecurityToken
     */
    private void parseBSTKeyIdentifier(
        SecurityTokenReference secRef,
        Crypto crypto,
        WSDocInfo wsDocInfo,
        RequestData data
    ) throws WSSecurityException {
        STRParserUtil.checkBinarySecurityBSPCompliance(secRef, null, data.getBSPEnforcer());
        
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
                                try {
                                    if (Arrays.equals(Base64.decode(kiValue), digest)) {
                                        principal = (Principal)bstResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
                                        foundCerts = certs;
                                        break;
                                    }
                                } catch (Base64DecodingException e) {
                                    throw new WSSecurityException(
                                        WSSecurityException.ErrorCode.FAILURE, "decoding.general", e
                                    );
                                }
                            } catch (CertificateEncodingException ex) {
                                throw new WSSecurityException(
                                    WSSecurityException.ErrorCode.SECURITY_TOKEN_UNAVAILABLE, "encodeError",
                                    ex
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
        Map<String, Object> parameters
    ) throws WSSecurityException {
        int action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
        if (WSConstants.UT_NOPASSWORD == action || WSConstants.UT == action) {
            STRParserUtil.checkUsernameTokenBSPCompliance(secRef, data.getBSPEnforcer());
            
            UsernameToken usernameToken = 
                (UsernameToken)result.get(WSSecurityEngineResult.TAG_USERNAME_TOKEN);

            usernameToken.setRawPassword(data);
            secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
           
            principal = usernameToken.createPrincipal();
        } else if (WSConstants.BST == action) {
            BinarySecurity token = 
                (BinarySecurity)result.get(
                    WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN
                );
            STRParserUtil.checkBinarySecurityBSPCompliance(secRef, token, data.getBSPEnforcer());
            
            certs = 
                (X509Certificate[])result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATES);
            secretKey = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
            Boolean validatedToken = 
                (Boolean)result.get(WSSecurityEngineResult.TAG_VALIDATED_TOKEN);
            if (validatedToken) {
                trustedCredential = true;
            }
        } else if (WSConstants.ENCR == action) {
            STRParserUtil.checkEncryptedKeyBSPCompliance(secRef, data.getBSPEnforcer());
            
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
                keyLength = KeyUtils.getKeyLength(algorithm);
            }
            byte[] secret = (byte[])result.get(WSSecurityEngineResult.TAG_SECRET);
            secretKey = dkt.deriveKey(keyLength, secret); 
            principal = dkt.createPrincipal();
            ((WSDerivedKeyTokenPrincipal)principal).setSecret(secret);
        } else if (WSConstants.ST_UNSIGNED == action || WSConstants.ST_SIGNED == action) {
            SamlAssertionWrapper samlAssertion =
                (SamlAssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
            STRParserUtil.checkSamlTokenBSPCompliance(secRef, samlAssertion, data.getBSPEnforcer());
            
            SAMLKeyInfo keyInfo = samlAssertion.getSubjectKeyInfo();
            if (keyInfo == null) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity"
                );
            }
            X509Certificate[] foundCerts = keyInfo.getCerts();
            if (foundCerts != null) {
                certs = new X509Certificate[]{foundCerts[0]};
            }
            secretKey = keyInfo.getSecret();
            publicKey = keyInfo.getPublicKey();
            principal = createPrincipalFromSAML(samlAssertion);
        }
    }
    
    
}
