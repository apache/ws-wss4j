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

package org.apache.wss4j.common.saml;

import java.io.IOException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.crypto.XMLStructure;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.keyinfo.X509IssuerSerial;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.w3c.dom.Element;

/**
 * Utility methods for SAML stuff
 */
public final class SAMLUtil {
    
    private static final String SIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    
    private SAMLUtil() {
        // Complete
    }

    /**
     * Parse a SAML Assertion to obtain a SAMLKeyInfo object from
     * the Subject of the assertion
     * 
     * @param samlAssertion The SAML Assertion
     * @param keyInfoProcessor A pluggable way to parse the KeyInfo
     * @return a SAMLKeyInfo object
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getCredentialFromSubject(
        SamlAssertionWrapper samlAssertion,
        SAMLKeyInfoProcessor keyInfoProcessor,
        Crypto sigCrypto,
        CallbackHandler callbackHandler
    ) throws WSSecurityException {
        if (samlAssertion.getSaml1() != null) {
            return getCredentialFromSubject(
                samlAssertion.getSaml1(), keyInfoProcessor, sigCrypto, callbackHandler
            );
        } else {
            return getCredentialFromSubject(
                samlAssertion.getSaml2(), keyInfoProcessor, sigCrypto, callbackHandler
            );
        }
    }
    
    /**
     * Try to get the secret key from a CallbackHandler implementation
     * @param cb a CallbackHandler implementation
     * @return An array of bytes corresponding to the secret key (can be null)
     * @throws WSSecurityException
     */
    public static byte[] getSecretKeyFromCallbackHandler(
        String id,
        CallbackHandler cb
    ) throws WSSecurityException {
        if (cb != null) {
            WSPasswordCallback pwcb = 
                new WSPasswordCallback(id, WSPasswordCallback.Usage.SECRET_KEY);
            try {
                cb.handle(new Callback[]{pwcb});
            } catch (Exception e1) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noKey",
                        new Object[] { id }, e1);
            }
            return pwcb.getKey();
        }
        return null;
    }
    
    /**
     * Get the SAMLKeyInfo object corresponding to the credential stored in the Subject of a 
     * SAML 1.1 assertion
     * @param assertion The SAML 1.1 assertion
     * @param keyInfoProcessor A pluggable way to parse the KeyInfo
     * @param sigCrypto A Crypto instance
     * @param callbackHandler A CallbackHandler instance
     * @return The SAMLKeyInfo object obtained from the Subject
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getCredentialFromSubject(
        org.opensaml.saml1.core.Assertion assertion,
        SAMLKeyInfoProcessor keyInfoProcessor,
        Crypto sigCrypto,
        CallbackHandler callbackHandler
    ) throws WSSecurityException {
        // First try to get the credential from a CallbackHandler
        byte[] key = getSecretKeyFromCallbackHandler(assertion.getID(), callbackHandler);
        if (key != null && key.length > 0) {
            return new SAMLKeyInfo(key);
        }
        
        for (org.opensaml.saml1.core.Statement stmt : assertion.getStatements()) {
            org.opensaml.saml1.core.Subject samlSubject = null;
            if (stmt instanceof org.opensaml.saml1.core.AttributeStatement) {
                org.opensaml.saml1.core.AttributeStatement attrStmt = 
                    (org.opensaml.saml1.core.AttributeStatement) stmt;
                samlSubject = attrStmt.getSubject();
            } else if (stmt instanceof org.opensaml.saml1.core.AuthenticationStatement) {
                org.opensaml.saml1.core.AuthenticationStatement authStmt = 
                    (org.opensaml.saml1.core.AuthenticationStatement) stmt;
                samlSubject = authStmt.getSubject();
            } else {
                org.opensaml.saml1.core.AuthorizationDecisionStatement authzStmt =
                    (org.opensaml.saml1.core.AuthorizationDecisionStatement)stmt;
                samlSubject = authzStmt.getSubject();
            }
            
            if (samlSubject == null) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "invalidSAMLToken", 
                    "for Signature (no Subject)"
                );
            }

            Element sub = samlSubject.getSubjectConfirmation().getDOM();
            Element keyInfoElement = 
                XMLUtils.getDirectChildElement(sub, "KeyInfo", SIG_NS);
            if (keyInfoElement != null) {
                return getCredentialFromKeyInfo(
                    keyInfoElement, keyInfoProcessor, sigCrypto
                );
            }
        }

        return null;
    }
    
    /**
     * Get the SAMLKeyInfo object corresponding to the credential stored in the Subject of a 
     * SAML 2 assertion
     * @param assertion The SAML 2 assertion
     * @param keyInfoProcessor A pluggable way to parse the KeyInfo
     * @param sigCrypto A Crypto instance
     * @param callbackHandler A CallbackHandler instance
     * @return The SAMLKeyInfo object obtained from the Subject
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getCredentialFromSubject(
        org.opensaml.saml2.core.Assertion assertion,
        SAMLKeyInfoProcessor keyInfoProcessor,
        Crypto sigCrypto,
        CallbackHandler callbackHandler
    ) throws WSSecurityException {
        // First try to get the credential from a CallbackHandler
        byte[] key = getSecretKeyFromCallbackHandler(assertion.getID(), callbackHandler);
        if (key != null && key.length > 0) {
            return new SAMLKeyInfo(key);
        }
        
        org.opensaml.saml2.core.Subject samlSubject = assertion.getSubject();
        if (samlSubject == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE, "invalidSAMLToken", 
                "for Signature (no Subject)"
            );
        }
        List<org.opensaml.saml2.core.SubjectConfirmation> subjectConfList = 
            samlSubject.getSubjectConfirmations();
        for (org.opensaml.saml2.core.SubjectConfirmation subjectConfirmation : subjectConfList) {
            SubjectConfirmationData subjConfData = 
                subjectConfirmation.getSubjectConfirmationData();
            Element sub = subjConfData.getDOM();
            Element keyInfoElement = 
                XMLUtils.getDirectChildElement(sub, "KeyInfo", SIG_NS);
            if (keyInfoElement != null) {
                return getCredentialFromKeyInfo(
                    keyInfoElement, keyInfoProcessor, sigCrypto
                );
            }
        }

        return null;
    }
    
    /**
     * This method returns a SAMLKeyInfo corresponding to the credential found in the
     * KeyInfo (DOM Element) argument.
     * @param keyInfoElement The KeyInfo as a DOM Element
     * @param keyInfoProcessor A pluggable way to parse the KeyInfo
     * @param sigCrypto A Crypto instance
     * @return The credential (as a SAMLKeyInfo object)
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getCredentialFromKeyInfo(
        Element keyInfoElement,
        SAMLKeyInfoProcessor keyInfoProcessor,
        Crypto sigCrypto
    ) throws WSSecurityException {
        //
        // First try to find an EncryptedKey, BinarySecret or a SecurityTokenReference via DOM
        //
        if (keyInfoProcessor != null) {
            SAMLKeyInfo samlKeyInfo = keyInfoProcessor.processSAMLKeyInfo(keyInfoElement);
            if (samlKeyInfo != null) {
                return samlKeyInfo;
            }
        }
        
        return getCredentialDirectlyFromKeyInfo(keyInfoElement, sigCrypto);
    }
    
    /**
     * This method returns a SAMLKeyInfo corresponding to the credential found in the
     * KeyInfo (DOM Element) argument.
     * @param keyInfoElement The KeyInfo as a DOM Element
     * @param sigCrypto A Crypto instance
     * @return The credential (as a SAMLKeyInfo object)
     * @throws WSSecurityException
     */
    public static SAMLKeyInfo getCredentialDirectlyFromKeyInfo(
        Element keyInfoElement,
        Crypto sigCrypto
    ) throws WSSecurityException {
        //
        // Next marshal the KeyInfo DOM element into a javax KeyInfo object and get the
        // (public key) credential
        //
        X509Certificate[] certs = null;
        KeyInfoFactory keyInfoFactory = null;
        try {
            keyInfoFactory = KeyInfoFactory.getInstance("DOM", "ApacheXMLDSig");
        } catch (NoSuchProviderException ex) {
            keyInfoFactory = KeyInfoFactory.getInstance("DOM");
        }
        XMLStructure keyInfoStructure = new DOMStructure(keyInfoElement);

        try {
            javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = 
                keyInfoFactory.unmarshalKeyInfo(keyInfoStructure);
            List<?> list = keyInfo.getContent();

            for (int i = 0; i < list.size(); i++) {
                XMLStructure xmlStructure = (XMLStructure) list.get(i);
                if (xmlStructure instanceof KeyValue) {
                    PublicKey publicKey = ((KeyValue)xmlStructure).getPublicKey();
                    return new SAMLKeyInfo(publicKey);
                } else if (xmlStructure instanceof X509Data) {
                    List<?> x509Data = ((X509Data)xmlStructure).getContent();
                    for (int j = 0; j < x509Data.size(); j++) {
                        Object x509obj = x509Data.get(j);
                        if (x509obj instanceof X509Certificate) {
                            certs = new X509Certificate[1];
                            certs[0] = (X509Certificate)x509obj;
                            return new SAMLKeyInfo(certs);
                        } else if (x509obj instanceof X509IssuerSerial) {
                            if (sigCrypto == null) {
                                throw new WSSecurityException(
                                    WSSecurityException.ErrorCode.FAILURE, "noSigCryptoFile"
                                );
                            }
                            CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ISSUER_SERIAL);
                            cryptoType.setIssuerSerial(
                                ((X509IssuerSerial)x509obj).getIssuerName(), 
                                ((X509IssuerSerial)x509obj).getSerialNumber()
                            );
                            certs = sigCrypto.getX509Certificates(cryptoType);
                            if (certs == null || certs.length < 1) {
                                throw new WSSecurityException(
                                    WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity",
                                    "cannot get certificate or key"
                                );
                            }
                            return new SAMLKeyInfo(certs);
                        }
                    }
                }
            }
        } catch (Exception ex) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity",
                new Object[]{"cannot get certificate or key"}, ex
            );
        }
        return null;
    }
    
    public static void doSAMLCallback(
        CallbackHandler callbackHandler, SAMLCallback callback
    ) {
        // Create a new SAMLCallback with all of the information from the properties file.
        try {
            // Get the SAML source data using the currently configured callback implementation.
            callbackHandler.handle(new SAMLCallback[]{callback});
        } catch (IOException e) {
            throw new IllegalStateException(
                "IOException while creating SAML assertion wrapper", e
            );
        } catch (UnsupportedCallbackException e) {
            throw new IllegalStateException(
                "UnsupportedCallbackException while creating SAML assertion wrapper", e
            );
        }
    }

}
