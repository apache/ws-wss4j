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

package org.apache.wss4j.dom.saml.ext;

import java.io.InputStream;
import java.security.KeyStore;

import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.saml.SAMLCallback;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.apache.wss4j.common.saml.builder.SAML2Constants;
import org.apache.wss4j.common.util.DOM2Writer;
import org.apache.wss4j.common.util.Loader;
import org.apache.wss4j.dom.common.SAML2CallbackHandler;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.junit.Assert;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * A list of test-cases to test the functionality of signing with
 * SamlAssertionWrapper class implementation.
 */

public class AssertionSigningTest extends org.junit.Assert {

    private Crypto issuerCrypto = null;
    // Default Canonicalization algorithm used by SamlAssertionWrapper class.
    private final String defaultCanonicalizationAlgorithm = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
    // Default RSA Signature algorithm used by SamlAssertionWrapper class.
    private final String defaultRSASignatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
    // Default DSA Signature algorithm used by SamlAssertionWrapper class.
    private final String defaultDSASignatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_DSA;
    // Custom Signature algorithm
    private final String customSignatureAlgorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
    // Custom Canonicalization algorithm
    private final String customCanonicalizationAlgorithm = SignatureConstants.ALGO_ID_C14N_OMIT_COMMENTS;
    // Custom Signature Digest algorithm
    private final String customSignatureDigestAlgorithm = SignatureConstants.ALGO_ID_DIGEST_SHA256;
    private final DocumentBuilderFactory dbf;

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }
    
    public AssertionSigningTest() throws Exception {
        WSSConfig.init();
        // Load the issuer keystore
        issuerCrypto = new Merlin();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(AssertionSigningTest.class);
        InputStream input = Merlin.loadInputStream(loader,
                "keys/client_keystore.jks");
        keyStore.load(input, "password".toCharArray());
        ((Merlin) issuerCrypto).setKeyStore(keyStore);
        
        dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
    }

    /**
     * Test that creates an SamlAssertionWrapper object and signs using default
     * signature and canonicalization algorithms. The defaults should match
     * otherwise the test-case fails.
     */
    @org.junit.Test
    public void testSigningWithDefaultAlgorithms() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler
                .setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
        
        samlAssertion.signAssertion("client_certchain", "password", issuerCrypto,
                false);
        Signature signature = samlAssertion.getSaml2().getSignature();
        Assert.assertTrue(signature.getSignatureAlgorithm().equalsIgnoreCase(
                defaultRSASignatureAlgorithm)
                || signature.getSignatureAlgorithm().equalsIgnoreCase(
                        defaultDSASignatureAlgorithm));
        Assert.assertEquals(defaultCanonicalizationAlgorithm,
                signature.getCanonicalizationAlgorithm());
        
        // Verify Signature
        SAMLKeyInfo keyInfo = new SAMLKeyInfo();
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("client_certchain");
        keyInfo.setCerts(issuerCrypto.getX509Certificates(cryptoType));
        
        Document doc = dbf.newDocumentBuilder().newDocument();
        
        Element assertionElement = samlAssertion.toDOM(doc);
        doc.appendChild(assertionElement);
        
        samlAssertion = new SamlAssertionWrapper(assertionElement);
        samlAssertion.verifySignature(keyInfo);
    }

    /**
     * Test that creates an SamlAssertionWrapper object and signs using custom
     * signature and canonicalization algorithms.
     */
    @org.junit.Test
    public void testSigningWithCustomAlgorithms() throws Exception {
        SAML2CallbackHandler callbackHandler = new SAML2CallbackHandler();
        callbackHandler.setStatement(SAML2CallbackHandler.Statement.AUTHN);
        callbackHandler
                .setConfirmationMethod(SAML2Constants.CONF_SENDER_VOUCHES);
        callbackHandler.setIssuer("www.example.com");
        
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(callbackHandler, samlCallback);
        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
        
        samlAssertion.signAssertion("client_certchain", "password", issuerCrypto,
                false, customCanonicalizationAlgorithm,
                customSignatureAlgorithm, customSignatureDigestAlgorithm);
        Signature signature = samlAssertion.getSaml2().getSignature();
        Assert.assertEquals(customSignatureAlgorithm,
                signature.getSignatureAlgorithm());
        Assert.assertEquals(customCanonicalizationAlgorithm,
                signature.getCanonicalizationAlgorithm());
        
        Document doc = dbf.newDocumentBuilder().newDocument();
        
        Element assertionElement = samlAssertion.toDOM(doc);
        doc.appendChild(assertionElement);
        String assertionString = DOM2Writer.nodeToString(assertionElement);
        Assert.assertTrue(assertionString.contains(customSignatureDigestAlgorithm));

        // Verify Signature
        SAMLKeyInfo keyInfo = new SAMLKeyInfo();
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("client_certchain");
        keyInfo.setCerts(issuerCrypto.getX509Certificates(cryptoType));
        
        samlAssertion = new SamlAssertionWrapper(assertionElement);
        samlAssertion.verifySignature(keyInfo);
    }
    
}
