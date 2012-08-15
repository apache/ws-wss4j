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

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.common.SOAPUtil;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.spnego.SpnegoTokenContext;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.util.WSSecurityUtil;
// import org.apache.ws.security.validate.KerberosTokenDecoderImpl;
import org.apache.ws.security.validate.KerberosTokenValidator;
import org.w3c.dom.Document;

import java.security.Principal;
import java.util.List;

import javax.crypto.SecretKey;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.xml.crypto.dsig.SignatureMethod;

/**
 * This is a test for a WSS4J client retrieving a service ticket from a KDC, and inserting
 * it into the security header of a request, to be processed by WSS4J. The tests are @Ignored by
 * default, as a KDC is needed. To replicate the test scenario, set up a KDC with user principal
 * "alice" (keytab in "/etc/alice.keytab"), and host service "bob@service.ws.apache.org" 
 * (keytab in "/etc/bob.keytab").
 * The test can be run with:
 * 
 * mvn -Djava.security.auth.login.config=src/test/resources/kerberos.jaas test -Dtest=KerberosTest
 * 
 * To see the Kerberos stuff add "-Dsun.security.krb5.debug=true".
 */
public class KerberosTest extends org.junit.Assert {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(KerberosTest.class);
    
    public KerberosTest() throws Exception {
        WSSConfig.init();
    }

    /**
     * Test using the KerberosSecurity class to retrieve a service ticket from a KDC, wrap it
     * in a BinarySecurityToken, and process it.
     */
    @org.junit.Test
    @org.junit.Ignore
    public void testKerberosCreationAndProcessing() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        KerberosSecurity bst = new KerberosSecurity(doc);
        bst.retrieveServiceTicket("alice", null, "bob@service.ws.apache.org");
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        
        // Configure the Validator
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        KerberosTokenValidator validator = new KerberosTokenValidator();
        validator.setContextName("bob");
        validator.setServiceName("bob@service.ws.apache.org");
        wssConfig.setValidator(WSSecurityEngine.BINARY_TOKEN, validator);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);
        
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, null, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertTrue(token != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof KerberosPrincipal);
        assertTrue(principal.getName().contains("alice"));
    }
    
    /**
     * Get and validate a SPNEGO token.
     */
    @org.junit.Test
    @org.junit.Ignore
    public void testSpnego() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        SpnegoTokenContext spnegoToken = new SpnegoTokenContext();
        spnegoToken.retrieveServiceTicket("alice", null, "bob@service.ws.apache.org");
        
        byte[] token = spnegoToken.getToken();
        assertNotNull(token);
        
        spnegoToken = new SpnegoTokenContext();
        spnegoToken.validateServiceTicket("bob", null, "bob@service.ws.apache.org", token);
        assertTrue(spnegoToken.isEstablished());
    }
    
    /**
     * Various unit tests for a kerberos client
     */
    @org.junit.Test
    @org.junit.Ignore
    public void testKerberosClient() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        
        try {
            KerberosSecurity bst = new KerberosSecurity(doc);
            bst.retrieveServiceTicket("alice2", null, "bob@service");
            fail("Failure expected on an unknown user");
        } catch (WSSecurityException ex) {
            // expected
        }
        
        
        try {
            KerberosSecurity bst = new KerberosSecurity(doc);
            bst.retrieveServiceTicket("alice", null, "bob2@service");
            fail("Failure expected on an unknown user");
        } catch (WSSecurityException ex) {
            // expected
        }
        
    }
    
    /**
     * Test using the KerberosSecurity class to retrieve a service ticket from a KDC, wrap it
     * in a BinarySecurityToken, and use the session key to sign the SOAP Body.
     */
    @org.junit.Test
    @org.junit.Ignore
    public void testKerberosSignature() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        KerberosSecurity bst = new KerberosSecurity(doc);
        bst.retrieveServiceTicket("alice", null, "bob@service.ws.apache.org");
        bst.setID("Id-" + bst.hashCode());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        WSSecSignature sign = new WSSecSignature();
        sign.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);
        sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
        sign.setCustomTokenId(bst.getID());
        sign.setCustomTokenValueType(WSConstants.WSS_GSS_KRB_V5_AP_REQ);
        
        SecretKey secretKey = bst.getSecretKey();
        sign.setSecretKey(secretKey.getEncoded());
        
        Document signedDoc = sign.build(doc, null, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // Configure the Validator
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        KerberosTokenValidator validator = new KerberosTokenValidator();
        validator.setContextName("bob");
        validator.setServiceName("bob@service.ws.apache.org");
        // validator.setKerberosTokenDecoder(new KerberosTokenDecoderImpl());
        wssConfig.setValidator(WSSecurityEngine.BINARY_TOKEN, validator);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);
        
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, null, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertTrue(token != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof KerberosPrincipal);
        assertTrue(principal.getName().contains("alice"));
    }
    
    
    /**
     * Test using the KerberosSecurity class to retrieve a service ticket from a KDC, wrap it
     * in a BinarySecurityToken, and use the session key to sign the SOAP Body.
     */
    @org.junit.Test
    @org.junit.Ignore
    public void testKerberosSignatureKI() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        KerberosSecurity bst = new KerberosSecurity(doc);
        bst.retrieveServiceTicket("alice", null, "bob@service.ws.apache.org");
        bst.setID("Id-" + bst.hashCode());
        
        WSSecSignature sign = new WSSecSignature();
        sign.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);
        sign.setKeyIdentifierType(WSConstants.CUSTOM_KEY_IDENTIFIER);
        sign.setCustomTokenValueType(WSConstants.WSS_KRB_KI_VALUE_TYPE);
        
        SecretKey secretKey = bst.getSecretKey();
        byte[] keyData = secretKey.getEncoded();
        sign.setSecretKey(keyData);
        
        byte[] digestBytes = WSSecurityUtil.generateDigest(bst.getToken());
        sign.setCustomTokenId(Base64.encode(digestBytes));
        
        Document signedDoc = sign.build(doc, null, secHeader);
        
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        
        // Configure the Validator
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        KerberosTokenValidator validator = new KerberosTokenValidator();
        validator.setContextName("bob");
        validator.setServiceName("bob@service.ws.apache.org");
        // validator.setKerberosTokenDecoder(new KerberosTokenDecoderImpl());
        wssConfig.setValidator(WSSecurityEngine.BINARY_TOKEN, validator);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);
        
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(doc, null, null, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertTrue(token != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof KerberosPrincipal);
        assertTrue(principal.getName().contains("alice"));
    }
    
    
    /**
     * Test using the KerberosSecurity class to retrieve a service ticket from a KDC, wrap it
     * in a BinarySecurityToken, and use the session key to encrypt the SOAP Body.
     */
    @org.junit.Test
    @org.junit.Ignore
    public void testKerberosEncryption() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        KerberosSecurity bst = new KerberosSecurity(doc);
        bst.retrieveServiceTicket("alice", null, "bob@service.ws.apache.org");
        bst.setID("Id-" + bst.hashCode());
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        SecretKey secretKey = bst.getSecretKey();
        builder.setSymmetricKey(secretKey);
        builder.setEncryptSymmKey(false);
        builder.setCustomReferenceValue(WSConstants.WSS_GSS_KRB_V5_AP_REQ);
        builder.setEncKeyId(bst.getID());

        Document encryptedDoc = builder.build(doc, null, secHeader);
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        
        // Configure the Validator
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        KerberosTokenValidator validator = new KerberosTokenValidator();
        validator.setContextName("bob");
        validator.setServiceName("bob@service.ws.apache.org");
        // validator.setKerberosTokenDecoder(new KerberosTokenDecoderImpl());
        wssConfig.setValidator(WSSecurityEngine.BINARY_TOKEN, validator);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);
        
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(encryptedDoc, null, null, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertTrue(token != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof KerberosPrincipal);
        assertTrue(principal.getName().contains("alice"));
    }
    
    /**
     * Test using the KerberosSecurity class to retrieve a service ticket from a KDC, wrap it
     * in a BinarySecurityToken, and use the session key to encrypt the SOAP Body.
     */
    @org.junit.Test
    @org.junit.Ignore
    public void testKerberosEncryptionBSTFirst() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        KerberosSecurity bst = new KerberosSecurity(doc);
        bst.retrieveServiceTicket("alice", null, "bob@service.ws.apache.org");
        bst.setID("Id-" + bst.hashCode());
        
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        SecretKey secretKey = bst.getSecretKey();
        builder.setSymmetricKey(secretKey);
        builder.setEncryptSymmKey(false);
        builder.setCustomReferenceValue(WSConstants.WSS_GSS_KRB_V5_AP_REQ);
        builder.setEncKeyId(bst.getID());

        Document encryptedDoc = builder.build(doc, null, secHeader);
        
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        
        // Configure the Validator
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        KerberosTokenValidator validator = new KerberosTokenValidator();
        validator.setContextName("bob");
        validator.setServiceName("bob@service.ws.apache.org");
        // validator.setKerberosTokenDecoder(new KerberosTokenDecoderImpl());
        wssConfig.setValidator(WSSecurityEngine.BINARY_TOKEN, validator);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);
        
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(encryptedDoc, null, null, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertTrue(token != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof KerberosPrincipal);
        assertTrue(principal.getName().contains("alice"));
    }
    
    /**
     * Test using the KerberosSecurity class to retrieve a service ticket from a KDC, wrap it
     * in a BinarySecurityToken, and use the session key to encrypt the SOAP Body.
     */
    @org.junit.Test
    @org.junit.Ignore
    public void testKerberosEncryptionKI() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        KerberosSecurity bst = new KerberosSecurity(doc);
        bst.retrieveServiceTicket("alice", null, "bob@service.ws.apache.org");
        bst.setID("Id-" + bst.hashCode());
        
        WSSecEncrypt builder = new WSSecEncrypt();
        builder.setSymmetricEncAlgorithm(WSConstants.AES_128);
        SecretKey secretKey = bst.getSecretKey();
        builder.setSymmetricKey(secretKey);
        builder.setEncryptSymmKey(false);
        builder.setCustomReferenceValue(WSConstants.WSS_KRB_KI_VALUE_TYPE);

        byte[] digestBytes = WSSecurityUtil.generateDigest(bst.getToken());
        builder.setEncKeyId(Base64.encode(digestBytes));
        
        Document encryptedDoc = builder.build(doc, null, secHeader);
        
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }
        
        // Configure the Validator
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        KerberosTokenValidator validator = new KerberosTokenValidator();
        validator.setContextName("bob");
        validator.setServiceName("bob@service.ws.apache.org");
        // validator.setKerberosTokenDecoder(new KerberosTokenDecoderImpl());
        wssConfig.setValidator(WSSecurityEngine.BINARY_TOKEN, validator);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);
        
        List<WSSecurityEngineResult> results = 
            secEngine.processSecurityHeader(encryptedDoc, null, null, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        assertTrue(token != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof KerberosPrincipal);
        assertTrue(principal.getName().contains("alice"));
    
    }
    
    
}
