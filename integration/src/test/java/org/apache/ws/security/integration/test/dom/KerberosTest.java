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

package org.apache.ws.security.integration.test.dom;

import org.apache.ws.security.dom.WSSConfig;
import org.apache.ws.security.dom.WSSecurityEngine;
import org.apache.ws.security.dom.WSConstants;
import org.apache.ws.security.dom.WSSecurityEngineResult;
import org.apache.ws.security.dom.common.SOAPUtil;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.common.util.XMLUtils;
import org.apache.ws.security.dom.message.WSSecEncrypt;
import org.apache.ws.security.dom.message.WSSecHeader;
import org.apache.ws.security.dom.message.WSSecSignature;
import org.apache.ws.security.dom.message.token.BinarySecurity;
import org.apache.ws.security.dom.message.token.KerberosSecurity;
import org.apache.ws.security.dom.spnego.SpnegoTokenContext;
import org.apache.ws.security.dom.util.WSSecurityUtil;
import org.apache.ws.security.dom.validate.KerberosTokenValidator;
import org.apache.ws.security.integration.test.common.KerberosServiceStarter;
import org.apache.xml.security.utils.Base64;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;
import org.w3c.dom.Document;

import java.io.File;
import java.io.IOException;
import java.security.Principal;
import java.util.List;

import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.xml.crypto.dsig.SignatureMethod;


/**
 * This is a test for a WSS4J client retrieving a service ticket from a KDC, and inserting
 * it into the security header of a request, to be processed by WSS4J.
 * To see the Kerberos stuff add "-Dsun.security.krb5.debug=true".
 */
public class KerberosTest {
    private static final org.apache.commons.logging.Log LOG = 
        org.apache.commons.logging.LogFactory.getLog(KerberosTest.class);

    private static boolean kerberosServerStarted = false;

    @BeforeClass
    public static void setUp() throws Exception {

        WSSConfig.init();

        kerberosServerStarted = KerberosServiceStarter.startKerberosServer();

        String basedir = System.getProperty("basedir");
        if (basedir == null) {
            basedir = new File(".").getCanonicalPath();
        } else {
            basedir += "/..";
        }

        //System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("java.security.auth.login.config", basedir + "/integration/src/test/resources/kerberos/kerberos.jaas");
        System.setProperty("java.security.krb5.conf", basedir + "/integration/src/test/resources/kerberos/krb5.conf");

    }

    @AfterClass
    public static void tearDown() throws Exception {
        if (kerberosServerStarted) {
            KerberosServiceStarter.stopKerberosServer();
        }
    }

    /**
     * Test using the KerberosSecurity class to retrieve a service ticket from a KDC, wrap it
     * in a BinarySecurityToken, and process it.
     */
    @Test
    public void testKerberosCreationAndProcessing() throws Exception {
        if (!kerberosServerStarted) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        KerberosSecurity bst = new KerberosSecurity(doc);
        CallbackHandler callbackHandler = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                PasswordCallback passwordCallback = (PasswordCallback)callbacks[0];
                if (passwordCallback.getPrompt().contains("alice")) {
                    passwordCallback.setPassword("alice".toCharArray());
                } else if (passwordCallback.getPrompt().contains("bob")) {
                    passwordCallback.setPassword("bob".toCharArray());
                }
            }
        };
        bst.retrieveServiceTicket("alice", callbackHandler, "bob@service.ws.apache.org");
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());
        
        if (LOG.isDebugEnabled()) {
            String outputString = 
                XMLUtils.PrettyDocumentToString(doc);
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
            secEngine.processSecurityHeader(doc, null, callbackHandler, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        Assert.assertTrue(token != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        Assert.assertTrue(principal instanceof KerberosPrincipal);
        Assert.assertTrue(principal.getName().contains("alice"));
    }
    
    /**
     * Get and validate a SPNEGO token.
     */
    @Test
    public void testSpnego() throws Exception {
        if (!kerberosServerStarted) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        SpnegoTokenContext spnegoToken = new SpnegoTokenContext();
        CallbackHandler callbackHandler = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                PasswordCallback passwordCallback = (PasswordCallback)callbacks[0];
                if (passwordCallback.getPrompt().contains("alice")) {
                    passwordCallback.setPassword("alice".toCharArray());
                } else if (passwordCallback.getPrompt().contains("bob")) {
                    passwordCallback.setPassword("bob".toCharArray());
                }
            }
        };
        spnegoToken.retrieveServiceTicket("alice", callbackHandler, "bob@service.ws.apache.org");
        
        byte[] token = spnegoToken.getToken();
        Assert.assertNotNull(token);
        
        spnegoToken = new SpnegoTokenContext();
        spnegoToken.validateServiceTicket("bob", callbackHandler, "bob@service.ws.apache.org", token);
        Assert.assertTrue(spnegoToken.isEstablished());
    }
    
    /**
     * Various unit tests for a kerberos client
     */
    @Test
    public void testKerberosClient() throws Exception {
        if (!kerberosServerStarted) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        CallbackHandler callbackHandler = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                PasswordCallback passwordCallback = (PasswordCallback)callbacks[0];
                if (passwordCallback.getPrompt().contains("alice")) {
                    passwordCallback.setPassword("alice".toCharArray());
                } else if (passwordCallback.getPrompt().contains("bob")) {
                    passwordCallback.setPassword("bob".toCharArray());
                }
            }
        };

        try {
            KerberosSecurity bst = new KerberosSecurity(doc);
            bst.retrieveServiceTicket("alice2", callbackHandler, "bob@service");
            Assert.fail("Failure expected on an unknown user");
        } catch (WSSecurityException ex) {
            Assert.assertEquals(ex.getMessage(), "An error occurred in trying to obtain a TGT: No LoginModules configured for alice2");
        }
        
        
        try {
            KerberosSecurity bst = new KerberosSecurity(doc);
            bst.retrieveServiceTicket("alice", callbackHandler, "bob2@service");
            Assert.fail("Failure expected on an unknown user");
        } catch (WSSecurityException ex) {
            Assert.assertEquals(ex.getMessage(), "An error occurred in trying to obtain a service ticket");
        }
        
    }
    
    /**
     * Test using the KerberosSecurity class to retrieve a service ticket from a KDC, wrap it
     * in a BinarySecurityToken, and use the session key to sign the SOAP Body.
     */
    @Test
    public void testKerberosSignature() throws Exception {
        if (!kerberosServerStarted) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        KerberosSecurity bst = new KerberosSecurity(doc);
        CallbackHandler callbackHandler = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                if (callbacks[0] instanceof PasswordCallback) {
                    PasswordCallback passwordCallback = (PasswordCallback)callbacks[0];
                    if (passwordCallback.getPrompt().contains("alice")) {
                        passwordCallback.setPassword("alice".toCharArray());
                    } else if (passwordCallback.getPrompt().contains("bob")) {
                        passwordCallback.setPassword("bob".toCharArray());
                    }
                }
            }
        };
        bst.retrieveServiceTicket("alice", callbackHandler, "bob@service.ws.apache.org");
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
                XMLUtils.PrettyDocumentToString(signedDoc);
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
            secEngine.processSecurityHeader(doc, null, callbackHandler, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        Assert.assertTrue(token != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        Assert.assertTrue(principal instanceof KerberosPrincipal);
        Assert.assertTrue(principal.getName().contains("alice"));
    }
    
    
    /**
     * Test using the KerberosSecurity class to retrieve a service ticket from a KDC, wrap it
     * in a BinarySecurityToken, and use the session key to sign the SOAP Body.
     */
    @Test
    public void testKerberosSignatureKI() throws Exception {
        if (!kerberosServerStarted) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        KerberosSecurity bst = new KerberosSecurity(doc);
        CallbackHandler callbackHandler = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                if (callbacks[0] instanceof PasswordCallback) {
                    PasswordCallback passwordCallback = (PasswordCallback)callbacks[0];
                    if (passwordCallback.getPrompt().contains("alice")) {
                        passwordCallback.setPassword("alice".toCharArray());
                    } else if (passwordCallback.getPrompt().contains("bob")) {
                        passwordCallback.setPassword("bob".toCharArray());
                    }
                }
            }
        };
        bst.retrieveServiceTicket("alice", callbackHandler, "bob@service.ws.apache.org");
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
                XMLUtils.PrettyDocumentToString(signedDoc);
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
            secEngine.processSecurityHeader(doc, null, callbackHandler, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        Assert.assertTrue(token != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        Assert.assertTrue(principal instanceof KerberosPrincipal);
        Assert.assertTrue(principal.getName().contains("alice"));
    }
    
    
    /**
     * Test using the KerberosSecurity class to retrieve a service ticket from a KDC, wrap it
     * in a BinarySecurityToken, and use the session key to encrypt the SOAP Body.
     */
    @Test
    public void testKerberosEncryption() throws Exception {
        if (!kerberosServerStarted) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        KerberosSecurity bst = new KerberosSecurity(doc);
        CallbackHandler callbackHandler = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                if (callbacks[0] instanceof PasswordCallback) {
                    PasswordCallback passwordCallback = (PasswordCallback)callbacks[0];
                    if (passwordCallback.getPrompt().contains("alice")) {
                        passwordCallback.setPassword("alice".toCharArray());
                    } else if (passwordCallback.getPrompt().contains("bob")) {
                        passwordCallback.setPassword("bob".toCharArray());
                    }
                }
            }
        };
        bst.retrieveServiceTicket("alice", callbackHandler, "bob@service.ws.apache.org");
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
                XMLUtils.PrettyDocumentToString(encryptedDoc);
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
            secEngine.processSecurityHeader(encryptedDoc, null, callbackHandler, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        Assert.assertTrue(token != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        Assert.assertTrue(principal instanceof KerberosPrincipal);
        Assert.assertTrue(principal.getName().contains("alice"));
    }
    
    /**
     * Test using the KerberosSecurity class to retrieve a service ticket from a KDC, wrap it
     * in a BinarySecurityToken, and use the session key to encrypt the SOAP Body.
     */
    @Test
    public void testKerberosEncryptionBSTFirst() throws Exception {
        if (!kerberosServerStarted) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        KerberosSecurity bst = new KerberosSecurity(doc);
        CallbackHandler callbackHandler = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                if (callbacks[0] instanceof PasswordCallback) {
                    PasswordCallback passwordCallback = (PasswordCallback)callbacks[0];
                    if (passwordCallback.getPrompt().contains("alice")) {
                        passwordCallback.setPassword("alice".toCharArray());
                    } else if (passwordCallback.getPrompt().contains("bob")) {
                        passwordCallback.setPassword("bob".toCharArray());
                    }
                }
            }
        };
        bst.retrieveServiceTicket("alice", callbackHandler, "bob@service.ws.apache.org");
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
                XMLUtils.PrettyDocumentToString(encryptedDoc);
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
            secEngine.processSecurityHeader(encryptedDoc, null, callbackHandler, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        Assert.assertTrue(token != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        Assert.assertTrue(principal instanceof KerberosPrincipal);
        Assert.assertTrue(principal.getName().contains("alice"));
    }
    
    /**
     * Test using the KerberosSecurity class to retrieve a service ticket from a KDC, wrap it
     * in a BinarySecurityToken, and use the session key to encrypt the SOAP Body.
     */
    @Test
    public void testKerberosEncryptionKI() throws Exception {
        if (!kerberosServerStarted) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        
        KerberosSecurity bst = new KerberosSecurity(doc);
        CallbackHandler callbackHandler = new CallbackHandler() {
            @Override
            public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                if (callbacks[0] instanceof PasswordCallback) {
                    PasswordCallback passwordCallback = (PasswordCallback)callbacks[0];
                    if (passwordCallback.getPrompt().contains("alice")) {
                        passwordCallback.setPassword("alice".toCharArray());
                    } else if (passwordCallback.getPrompt().contains("bob")) {
                        passwordCallback.setPassword("bob".toCharArray());
                    }
                }
            }
        };
        bst.retrieveServiceTicket("alice", callbackHandler, "bob@service.ws.apache.org");
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
                XMLUtils.PrettyDocumentToString(encryptedDoc);
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
            secEngine.processSecurityHeader(encryptedDoc, null, callbackHandler, null);
        WSSecurityEngineResult actionResult =
            WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        Assert.assertTrue(token != null);
        
        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        Assert.assertTrue(principal instanceof KerberosPrincipal);
        Assert.assertTrue(principal.getName().contains("alice"));
    }
}
