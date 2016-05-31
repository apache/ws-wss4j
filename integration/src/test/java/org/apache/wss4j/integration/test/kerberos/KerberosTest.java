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
package org.apache.wss4j.integration.test.kerberos;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Principal;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import javax.crypto.SecretKey;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.kerberos.KerberosPrincipal;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.directory.server.annotations.CreateKdcServer;
import org.apache.directory.server.annotations.CreateLdapServer;
import org.apache.directory.server.annotations.CreateTransport;
import org.apache.directory.server.core.annotations.ApplyLdifFiles;
import org.apache.directory.server.core.annotations.CreateDS;
import org.apache.directory.server.core.annotations.CreateIndex;
import org.apache.directory.server.core.annotations.CreatePartition;
import org.apache.directory.server.core.integ.AbstractLdapTestUnit;
import org.apache.directory.server.core.integ.FrameworkRunner;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.kerberos.KerberosContextAndServiceNameCallback;
import org.apache.wss4j.common.spnego.SpnegoTokenContext;
import org.apache.wss4j.common.token.BinarySecurity;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.dom.message.token.KerberosSecurity;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.dom.validate.KerberosTokenValidator;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.securityEvent.KerberosTokenSecurityEvent;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.utils.SOAPUtil;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventListener;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

@RunWith(FrameworkRunner.class)

//Define the DirectoryService
@CreateDS(name = "KerberosTest-class",
    enableAccessControl = false,
    allowAnonAccess = false,
    enableChangeLog = true,
    partitions = {
        @CreatePartition(
            name = "example",
            suffix = "dc=example,dc=com",
            indexes = {
                @CreateIndex(attribute = "objectClass"),
                @CreateIndex(attribute = "dc"),
                @CreateIndex(attribute = "ou")
            } )
        },
    additionalInterceptors = {
       KeyDerivationInterceptor.class
    }
)

@CreateLdapServer(
    transports = {
        @CreateTransport(protocol = "LDAP")
    }
)

@CreateKdcServer(
    transports = {
        @CreateTransport(protocol = "KRB", address = "127.0.0.1") //NOPMD
    },
    primaryRealm = "service.ws.apache.org",
    kdcPrincipal = "krbtgt/service.ws.apache.org@service.ws.apache.org"
)

//Inject an file containing entries
@ApplyLdifFiles("kerberos/kerberos.ldif")

public class KerberosTest extends AbstractLdapTestUnit {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(KerberosTest.class);

    private static final XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
    private static final TransformerFactory TRANSFORMER_FACTORY = TransformerFactory.newInstance();
    private static DocumentBuilderFactory dbf;

    private static boolean runTests;
    private static boolean portUpdated;

    @BeforeClass
    public static void setUp() throws Exception {

        WSSConfig.init();

        //
        // This test fails with the IBM JDK
        //
        if (!"IBM Corporation".equals(System.getProperty("java.vendor"))) {
            runTests = true;
            String basedir = System.getProperty("basedir");
            if (basedir == null) {
                basedir = new File(".").getCanonicalPath();
            }

            // System.setProperty("sun.security.krb5.debug", "true");
            System.setProperty("java.security.auth.login.config", basedir + "/src/test/resources/kerberos/kerberos.jaas");

        }

        dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setIgnoringComments(false);
        dbf.setCoalescing(false);
        dbf.setIgnoringElementContentWhitespace(false);

        xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, false);
        xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
    }

    @AfterClass
    public static void tearDown() throws Exception {
        SecurityTestUtil.cleanup();
    }

    @Before
    public void updatePort() throws Exception {
        if (!portUpdated) {
            String basedir = System.getProperty("basedir");
            if (basedir == null) {
                basedir = new File(".").getCanonicalPath();
            }

            // Read in krb5.conf and substitute in the correct port
            Path path = FileSystems.getDefault().getPath(basedir, "/src/test/resources/kerberos/krb5.conf");
            String content = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
            content = content.replaceAll("port", "" + super.getKdcServer().getTransports()[0].getPort());

            Path path2 = FileSystems.getDefault().getPath(basedir, "/target/test-classes/kerberos/krb5.conf");
            Files.write(path2, content.getBytes());

            System.setProperty("java.security.krb5.conf", path2.toString());

            portUpdated = true;
        }
    }

    //
    // DOM tests
    //

    /**
     * Test using the KerberosSecurity class to retrieve a service ticket from a KDC, wrap it
     * in a BinarySecurityToken, and process it.
     */
    @Test
    public void testKerberosCreationAndProcessing() throws Exception {
        if (!runTests) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

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
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }

        // Configure the Validator
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        KerberosTokenValidator validator = new KerberosTokenValidator();
        validator.setContextName("bob");
        validator.setServiceName("bob@service.ws.apache.org");
        wssConfig.setValidator(WSConstants.BINARY_TOKEN, validator);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);

        WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, callbackHandler, null);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.BST).get(0);
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
        if (!runTests) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

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
        if (!runTests) {
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
            Assert.assertTrue(ex.getMessage().startsWith("An error occurred in trying to obtain a TGT:"));
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
        if (!runTests) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

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
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        // Configure the Validator
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        KerberosTokenValidator validator = new KerberosTokenValidator();
        validator.setContextName("bob");
        validator.setServiceName("bob@service.ws.apache.org");
        wssConfig.setValidator(WSConstants.BINARY_TOKEN, validator);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);

        WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, callbackHandler, null);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.BST).get(0);
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
        if (!runTests) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

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

        byte[] digestBytes = KeyUtils.generateDigest(bst.getToken());
        sign.setCustomTokenId(Base64.getMimeEncoder().encodeToString(digestBytes));

        Document signedDoc = sign.build(doc, null, secHeader);

        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        // Configure the Validator
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        KerberosTokenValidator validator = new KerberosTokenValidator();
        validator.setContextName("bob");
        validator.setServiceName("bob@service.ws.apache.org");
        wssConfig.setValidator(WSConstants.BINARY_TOKEN, validator);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);

        WSHandlerResult results =
            secEngine.processSecurityHeader(doc, null, callbackHandler, null);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.BST).get(0);
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
        if (!runTests) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

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
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        // Configure the Validator
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        KerberosTokenValidator validator = new KerberosTokenValidator();
        validator.setContextName("bob");
        validator.setServiceName("bob@service.ws.apache.org");
        wssConfig.setValidator(WSConstants.BINARY_TOKEN, validator);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);

        WSHandlerResult results =
            secEngine.processSecurityHeader(encryptedDoc, null, callbackHandler, null);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.BST).get(0);
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
        if (!runTests) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

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
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        // Configure the Validator
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        KerberosTokenValidator validator = new KerberosTokenValidator();
        validator.setContextName("bob");
        validator.setServiceName("bob@service.ws.apache.org");
        wssConfig.setValidator(WSConstants.BINARY_TOKEN, validator);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);

        WSHandlerResult results =
            secEngine.processSecurityHeader(encryptedDoc, null, callbackHandler, null);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.BST).get(0);
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
        if (!runTests) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

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

        byte[] digestBytes = KeyUtils.generateDigest(bst.getToken());
        builder.setEncKeyId(Base64.getMimeEncoder().encodeToString(digestBytes));

        Document encryptedDoc = builder.build(doc, null, secHeader);

        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(encryptedDoc);
            LOG.debug(outputString);
        }

        // Configure the Validator
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        KerberosTokenValidator validator = new KerberosTokenValidator();
        validator.setContextName("bob");
        validator.setServiceName("bob@service.ws.apache.org");
        wssConfig.setValidator(WSConstants.BINARY_TOKEN, validator);
        WSSecurityEngine secEngine = new WSSecurityEngine();
        secEngine.setWssConfig(wssConfig);

        WSHandlerResult results =
            secEngine.processSecurityHeader(encryptedDoc, null, callbackHandler, null);
        WSSecurityEngineResult actionResult =
            results.getActionResults().get(WSConstants.BST).get(0);
        BinarySecurity token =
            (BinarySecurity)actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
        Assert.assertTrue(token != null);

        Principal principal = (Principal)actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
        Assert.assertTrue(principal instanceof KerberosPrincipal);
        Assert.assertTrue(principal.getName().contains("alice"));
    }

    //
    // Streaming tests
    //
    @Test
    public void testKerberosSignatureOutbound() throws Exception {
        if (!runTests) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document document;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.SIGNATURE_WITH_KERBEROS_TOKEN);
            securityProperties.setActions(actions);
            securityProperties.setCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof KerberosContextAndServiceNameCallback) {
                        KerberosContextAndServiceNameCallback kerberosContextAndServiceNameCallback =
                                (KerberosContextAndServiceNameCallback) callbacks[0];
                        kerberosContextAndServiceNameCallback.setContextName("alice");
                        kerberosContextAndServiceNameCallback.setServiceName("bob@service.ws.apache.org");
                    } else if (callbacks[0] instanceof PasswordCallback) {
                        PasswordCallback passwordCallback = (PasswordCallback) callbacks[0];
                        if (passwordCallback.getPrompt().contains("alice")) {
                            passwordCallback.setPassword("alice".toCharArray());
                        }
                    }
                }
            });

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            document = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
        }

        //done signature; now test sig-verification:
        {
            // Configure the Validator
            WSSConfig wssConfig = WSSConfig.getNewInstance();
            KerberosTokenValidator validator = new KerberosTokenValidator();
            validator.setContextName("bob");
            validator.setServiceName("bob@service.ws.apache.org");
            wssConfig.setValidator(WSConstants.BINARY_TOKEN, validator);
            WSSecurityEngine secEngine = new WSSecurityEngine();
            secEngine.setWssConfig(wssConfig);

            CallbackHandler callbackHandler = new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof PasswordCallback) {
                        PasswordCallback passwordCallback = (PasswordCallback) callbacks[0];
                        if (passwordCallback.getPrompt().contains("bob")) {
                            passwordCallback.setPassword("bob".toCharArray());
                        }
                    }
                }
            };

            WSHandlerResult results =
                    secEngine.processSecurityHeader(document, null, callbackHandler, null);
            WSSecurityEngineResult actionResult =
                    results.getActionResults().get(WSConstants.BST).get(0);
            BinarySecurity token =
                    (BinarySecurity) actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
            Assert.assertTrue(token != null);

            Principal principal = (Principal) actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
            Assert.assertTrue(principal instanceof KerberosPrincipal);
            Assert.assertTrue(principal.getName().contains("alice"));
        }
    }

    @Test
    public void testKerberosSignatureInbound() throws Exception {
        if (!runTests) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            KerberosSecurity bst = new KerberosSecurity(doc);
            CallbackHandler callbackHandler = new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof PasswordCallback) {
                        PasswordCallback passwordCallback = (PasswordCallback) callbacks[0];
                        if (passwordCallback.getPrompt().contains("alice")) {
                            passwordCallback.setPassword("alice".toCharArray());
                        }
                    }
                }
            };
            bst.retrieveServiceTicket("alice", callbackHandler, "bob@service.ws.apache.org");
            bst.setID("Id-" + bst.hashCode());

            WSSecSignature sign = new WSSecSignature();
            sign.setSignatureAlgorithm(SignatureMethod.HMAC_SHA1);
            sign.setKeyIdentifierType(WSConstants.CUSTOM_SYMM_SIGNING);
            sign.setCustomTokenId(bst.getID());
            sign.setCustomTokenValueType(WSConstants.WSS_GSS_KRB_V5_AP_REQ);

            SecretKey secretKey = bst.getSecretKey();
            sign.setSecretKey(secretKey.getEncoded());

            sign.build(doc, null, secHeader);
            WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof PasswordCallback) {
                        PasswordCallback passwordCallback = (PasswordCallback) callbacks[0];
                        if (passwordCallback.getPrompt().contains("bob")) {
                            passwordCallback.setPassword("bob".toCharArray());
                        }
                    } else if (callbacks[0] instanceof KerberosContextAndServiceNameCallback) {
                        KerberosContextAndServiceNameCallback cb = (KerberosContextAndServiceNameCallback) callbacks[0];
                        cb.setContextName("bob");
                        cb.setServiceName("bob@service.ws.apache.org");
                    }
                }
            });

            final List<KerberosTokenSecurityEvent> kerberosTokenSecurityEvents = new ArrayList<KerberosTokenSecurityEvent>();

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            SecurityEventListener securityEventListener = new SecurityEventListener() {
                @Override
                public void registerSecurityEvent(SecurityEvent securityEvent) throws XMLSecurityException {
                    if (securityEvent instanceof KerberosTokenSecurityEvent) {
                        kerberosTokenSecurityEvents.add((KerberosTokenSecurityEvent) securityEvent);
                    }
                }
            };
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(
                    new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            Document document = StAX2DOM.readDoc(dbf.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            Assert.assertEquals(kerberosTokenSecurityEvents.size(), 1);
            final KerberosTokenSecurityEvent kerberosTokenSecurityEvent = kerberosTokenSecurityEvents.get(0);
            Assert.assertNotNull(kerberosTokenSecurityEvent.getSecurityToken().getSubject());
            Assert.assertTrue(kerberosTokenSecurityEvent.getSecurityToken().getPrincipal() instanceof KerberosPrincipal);
            Assert.assertEquals(kerberosTokenSecurityEvent.getSecurityToken().getPrincipal().getName(), "alice@service.ws.apache.org");
        }
    }

    @Test
    public void testKerberosSignatureKIInbound() throws Exception {
        if (!runTests) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            KerberosSecurity bst = new KerberosSecurity(doc);
            CallbackHandler callbackHandler = new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof PasswordCallback) {
                        PasswordCallback passwordCallback = (PasswordCallback) callbacks[0];
                        if (passwordCallback.getPrompt().contains("alice")) {
                            passwordCallback.setPassword("alice".toCharArray());
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

            byte[] digestBytes = KeyUtils.generateDigest(bst.getToken());
            sign.setCustomTokenId(Base64.getMimeEncoder().encodeToString(digestBytes));

            sign.build(doc, null, secHeader);

            WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof PasswordCallback) {
                        PasswordCallback passwordCallback = (PasswordCallback) callbacks[0];
                        if (passwordCallback.getPrompt().contains("bob")) {
                            passwordCallback.setPassword("bob".toCharArray());
                        }
                    } else if (callbacks[0] instanceof KerberosContextAndServiceNameCallback) {
                        KerberosContextAndServiceNameCallback cb = (KerberosContextAndServiceNameCallback) callbacks[0];
                        cb.setContextName("bob");
                        cb.setServiceName("bob@service.ws.apache.org");
                    }
                }
            });

            final List<KerberosTokenSecurityEvent> kerberosTokenSecurityEvents = new ArrayList<KerberosTokenSecurityEvent>();

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            SecurityEventListener securityEventListener = new SecurityEventListener() {
                @Override
                public void registerSecurityEvent(SecurityEvent securityEvent) throws XMLSecurityException {
                    if (securityEvent instanceof KerberosTokenSecurityEvent) {
                        kerberosTokenSecurityEvents.add((KerberosTokenSecurityEvent) securityEvent);
                    }
                }
            };
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(
                    new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            Document document = StAX2DOM.readDoc(dbf.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_dsig_Signature.getNamespaceURI(), WSSConstants.TAG_dsig_Signature.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            Assert.assertEquals(kerberosTokenSecurityEvents.size(), 1);
        }
    }

    @Test
    public void testKerberosEncryptionOutbound() throws Exception {
        if (!runTests) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        Document document;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<WSSConstants.Action>();
            actions.add(WSSConstants.ENCRYPT_WITH_KERBEROS_TOKEN);
            securityProperties.setActions(actions);
            securityProperties.setEncryptionSymAlgorithm(WSSConstants.NS_XENC_AES128);
            securityProperties.setCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof KerberosContextAndServiceNameCallback) {
                        KerberosContextAndServiceNameCallback kerberosContextAndServiceNameCallback =
                                (KerberosContextAndServiceNameCallback) callbacks[0];
                        kerberosContextAndServiceNameCallback.setContextName("alice");
                        kerberosContextAndServiceNameCallback.setServiceName("bob@service.ws.apache.org");
                    } else if (callbacks[0] instanceof PasswordCallback) {
                        PasswordCallback passwordCallback = (PasswordCallback) callbacks[0];
                        if (passwordCallback.getPrompt().contains("alice")) {
                            passwordCallback.setPassword("alice".toCharArray());
                        }
                    }
                }
            });

            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            OutboundWSSec wsSecOut = WSSec.getOutboundWSSec(securityProperties);
            XMLStreamWriter xmlStreamWriter = wsSecOut.processOutMessage(baos, StandardCharsets.UTF_8.name(), new ArrayList<SecurityEvent>());
            XMLStreamReader xmlStreamReader = xmlInputFactory.createXMLStreamReader(this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml"));
            XmlReaderToWriter.writeAll(xmlStreamReader, xmlStreamWriter);
            xmlStreamWriter.close();

            document = dbf.newDocumentBuilder().parse(new ByteArrayInputStream(baos.toByteArray()));
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_ReferenceList.getNamespaceURI(), WSSConstants.TAG_xenc_ReferenceList.getLocalPart());
            Assert.assertEquals(1, nodeList.getLength());
        }

        {
            // Configure the Validator
            WSSConfig wssConfig = WSSConfig.getNewInstance();
            KerberosTokenValidator validator = new KerberosTokenValidator();
            validator.setContextName("bob");
            validator.setServiceName("bob@service.ws.apache.org");
            wssConfig.setValidator(WSConstants.BINARY_TOKEN, validator);
            WSSecurityEngine secEngine = new WSSecurityEngine();
            secEngine.setWssConfig(wssConfig);

            CallbackHandler callbackHandler = new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof PasswordCallback) {
                        PasswordCallback passwordCallback = (PasswordCallback) callbacks[0];
                        if (passwordCallback.getPrompt().contains("bob")) {
                            passwordCallback.setPassword("bob".toCharArray());
                        }
                    }
                }
            };

            WSHandlerResult results =
                    secEngine.processSecurityHeader(document, null, callbackHandler, null);
            WSSecurityEngineResult actionResult =
                    results.getActionResults().get(WSConstants.BST).get(0);
            BinarySecurity token =
                    (BinarySecurity) actionResult.get(WSSecurityEngineResult.TAG_BINARY_SECURITY_TOKEN);
            Assert.assertTrue(token != null);

            Principal principal = (Principal) actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
            Assert.assertTrue(principal instanceof KerberosPrincipal);
            Assert.assertTrue(principal.getName().contains("alice"));
        }
    }

    @Test
    public void testKerberosEncryptionInbound() throws Exception {
        if (!runTests) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            KerberosSecurity bst = new KerberosSecurity(doc);
            CallbackHandler callbackHandler = new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof PasswordCallback) {
                        PasswordCallback passwordCallback = (PasswordCallback) callbacks[0];
                        if (passwordCallback.getPrompt().contains("alice")) {
                            passwordCallback.setPassword("alice".toCharArray());
                        }
                    }
                }
            };
            bst.retrieveServiceTicket("alice", callbackHandler, "bob@service.ws.apache.org");
            bst.setID("Id-" + bst.hashCode());

            WSSecEncrypt builder = new WSSecEncrypt();
            builder.setSymmetricEncAlgorithm(WSConstants.AES_256);
            SecretKey secretKey = bst.getSecretKey();
            builder.setSymmetricKey(secretKey);
            builder.setEncryptSymmKey(false);
            builder.setCustomReferenceValue(WSConstants.WSS_GSS_KRB_V5_AP_REQ);
            builder.setEncKeyId(bst.getID());
            builder.build(doc, null, secHeader);
            WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));
        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof PasswordCallback) {
                        PasswordCallback passwordCallback = (PasswordCallback) callbacks[0];
                        if (passwordCallback.getPrompt().contains("bob")) {
                            passwordCallback.setPassword("bob".toCharArray());
                        }
                    } else if (callbacks[0] instanceof KerberosContextAndServiceNameCallback) {
                        KerberosContextAndServiceNameCallback cb = (KerberosContextAndServiceNameCallback) callbacks[0];
                        cb.setContextName("bob");
                        cb.setServiceName("bob@service.ws.apache.org");
                    }
                }
            });

            final List<KerberosTokenSecurityEvent> kerberosTokenSecurityEvents = new ArrayList<KerberosTokenSecurityEvent>();

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            SecurityEventListener securityEventListener = new SecurityEventListener() {
                @Override
                public void registerSecurityEvent(SecurityEvent securityEvent) throws XMLSecurityException {
                    if (securityEvent instanceof KerberosTokenSecurityEvent) {
                        kerberosTokenSecurityEvents.add((KerberosTokenSecurityEvent) securityEvent);
                    }
                }
            };
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(
                    new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            Document document = StAX2DOM.readDoc(dbf.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN.getNamespaceURI(), WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);

            Assert.assertEquals(kerberosTokenSecurityEvents.size(), 1);
        }
    }

    @Test
    public void testKerberosEncryptionKIInbound() throws Exception {
        if (!runTests) {
            System.out.println("Skipping test because kerberos server could not be started");
            return;
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        {
            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);

            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            KerberosSecurity bst = new KerberosSecurity(doc);
            CallbackHandler callbackHandler = new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof PasswordCallback) {
                        PasswordCallback passwordCallback = (PasswordCallback) callbacks[0];
                        if (passwordCallback.getPrompt().contains("alice")) {
                            passwordCallback.setPassword("alice".toCharArray());
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

            byte[] digestBytes = KeyUtils.generateDigest(bst.getToken());
            builder.setEncKeyId(Base64.getMimeEncoder().encodeToString(digestBytes));

            builder.build(doc, null, secHeader);

            WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(), bst.getElement());

            javax.xml.transform.Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(doc), new StreamResult(baos));

        }

        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
            securityProperties.setCallbackHandler(new CallbackHandler() {
                @Override
                public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
                    if (callbacks[0] instanceof PasswordCallback) {
                        PasswordCallback passwordCallback = (PasswordCallback) callbacks[0];
                        if (passwordCallback.getPrompt().contains("bob")) {
                            passwordCallback.setPassword("bob".toCharArray());
                        }
                    } else if (callbacks[0] instanceof KerberosContextAndServiceNameCallback) {
                        KerberosContextAndServiceNameCallback cb = (KerberosContextAndServiceNameCallback) callbacks[0];
                        cb.setContextName("bob");
                        cb.setServiceName("bob@service.ws.apache.org");
                    }
                }
            });

            final List<KerberosTokenSecurityEvent> kerberosTokenSecurityEvents = new ArrayList<KerberosTokenSecurityEvent>();

            InboundWSSec wsSecIn = WSSec.getInboundWSSec(securityProperties);
            SecurityEventListener securityEventListener = new SecurityEventListener() {
                @Override
                public void registerSecurityEvent(SecurityEvent securityEvent) throws XMLSecurityException {
                    if (securityEvent instanceof KerberosTokenSecurityEvent) {
                        kerberosTokenSecurityEvents.add((KerberosTokenSecurityEvent) securityEvent);
                    }
                }
            };
            XMLStreamReader xmlStreamReader = wsSecIn.processInMessage(xmlInputFactory.createXMLStreamReader(
                    new ByteArrayInputStream(baos.toByteArray())), null, securityEventListener);

            Document document = StAX2DOM.readDoc(dbf.newDocumentBuilder(), xmlStreamReader);

            //header element must still be there
            NodeList nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN.getNamespaceURI(), WSSConstants.TAG_WSSE_BINARY_SECURITY_TOKEN.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 1);
            Assert.assertEquals(nodeList.item(0).getParentNode().getLocalName(), WSSConstants.TAG_WSSE_SECURITY.getLocalPart());

            //no encrypted content
            nodeList = document.getElementsByTagNameNS(WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(), WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            Assert.assertEquals(nodeList.getLength(), 0);

            Assert.assertEquals(kerberosTokenSecurityEvents.size(), 1);
        }
    }

}
