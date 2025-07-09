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

package org.apache.wss4j.dom.message;

import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.api.dom.WSConstants;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.common.crypto.KeystoreCallbackHandler;
import org.apache.wss4j.api.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.api.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.api.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecSignature;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.handler.HandlerAction;
import org.apache.wss4j.api.dom.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;

import javax.security.auth.x500.X500Principal;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

/**
 * This is a test for WSS-40. Essentially it just tests that a message is signed using a
 * keyEntry from one keystore, and verified at the other end with a keystore with just the
 * CA cert in it.
 *
 * http://issues.apache.org/jira/browse/WSS-40
 *
 * Generate the CA keys/certs + export the CA cert to a keystore
 *
 * openssl req -x509 -newkey rsa:2048 -keyout wss40CAKey.pem -out wss40CA.pem
 * -config ca.config -days 3650
 * openssl x509 -outform DER -in wss40CA.pem -out wss40CA.crt
 * keytool -import -file wss40CA.crt -alias wss40CA -keystore wss40CA.jks
 *
 * Generate the client keypair, make a csr, sign it with the CA key
 *
 * keytool -genkey -validity 3650 -alias wss40 -keyalg RSA -keystore wss40.jks
 * -dname "CN=Colm,OU=WSS4J,O=Apache,L=Dublin,ST=Leinster,C=IE"
 * keytool -certreq -alias wss40 -keystore wss40.jks -file wss40.cer
 * openssl ca -config ca.config -policy policy_anything -days 3650 -out wss40.pem -infiles wss40.cer
 * openssl x509 -outform DER -in wss40.pem -out wss40.crt
 *
 * Import the CA cert into wss40.jks and import the new signed certificate
 *
 * keytool -import -file wss40CA.crt -alias wss40CA -keystore wss40.jks
 * keytool -import -file wss40.crt -alias wss40 -keystore wss40.jks
 *
 */
public class SignatureCertTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SignatureCertTest.class);
    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto;
    private Crypto cryptoCA;
    private boolean isJDK16up;

    public SignatureCertTest() throws Exception {
        WSSConfig.init();
        crypto = CryptoFactory.getInstance("wss40.properties");
        cryptoCA = CryptoFactory.getInstance("wss40CA.properties");
        try {
            int javaVersion = Integer.getInteger("java.specification.version", 0);
            isJDK16up = javaVersion >= 16;
        } catch (NumberFormatException ex) {
            LOG.warn("Error in retrieving the java version: [{}]", ex.getMessage());
        }
    }

    /**
     * Test signing a SOAP message using a BST.
     */
    @Test
    public void testSignatureDirectReference() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature sign = new WSSecSignature(secHeader);
        sign.setUserInfo("wss40", "security");
        sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document signedDoc = sign.build(crypto);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        //
        // Verify the signature
        //
        WSHandlerResult results = verify(signedDoc, cryptoCA);
        WSSecurityEngineResult result =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        X509Certificate cert =
            (X509Certificate)result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertNotNull(cert);
    }

    /**
     * Test signing a SOAP message using a BST, sending the CA cert as well in the
     * message.
     */
    @Test
    public void testSignatureDirectReferenceCACert() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature sign = new WSSecSignature(secHeader);
        sign.setUserInfo("wss40", "security");
        sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        sign.setUseSingleCertificate(false);

        Document signedDoc = sign.build(crypto);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug("BST CA Cert");
            LOG.debug(outputString);
        }
        //
        // Verify the signature
        //
        WSHandlerResult results = verify(signedDoc, cryptoCA);
        WSSecurityEngineResult result =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        X509Certificate cert =
            (X509Certificate)result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertNotNull(cert);
        X509Certificate[] certs =
            (X509Certificate[])result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATES);
        assertTrue(certs != null && certs.length == 2);
    }


    /**
     * Test signing a SOAP message using Issuer Serial. Note that this should fail, as the
     * trust-store does not contain the cert corresponding to wss40, only the CA cert
     * wss40CA.
     */
    @Test
    public void testSignatureIssuerSerial() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature sign = new WSSecSignature(secHeader);
        sign.setUserInfo("wss40", "security");
        sign.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);

        Document signedDoc = sign.build(crypto);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }

        try {
            verify(signedDoc, cryptoCA);
            fail("Failure expected on issuer serial");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
        }
    }


    /**
     * Test signing a SOAP message using a BST. The signature verification passes, but the trust
     * verification will fail as the CA cert is out of date.
     */
    @Test
    public void testSignatureBadCACert() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature sign = new WSSecSignature(secHeader);
        sign.setUserInfo("wss40expca", "security");
        sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document signedDoc =
            sign.build(CryptoFactory.getInstance("wss40badca.properties"));

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        //
        // Verify the signature
        //
        try {
            verify(signedDoc, CryptoFactory.getInstance("wss40badcatrust.properties"));
            fail("Failure expected on bad CA cert!");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILURE);
        }
    }

    /**
     * A test for "SignatureAction does not set DigestAlgorithm on WSSecSignature instance"
     */
    @Test
    public void testMultipleCertsWSHandler() throws Exception {
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setUsername("wss40");
        java.util.Map<String, Object> config = new java.util.TreeMap<>();
        config.put(WSHandlerConstants.SIG_PROP_FILE, "wss40.properties");
        config.put(WSHandlerConstants.PW_CALLBACK_CLASS, KeystoreCallbackHandler.class.getName());
        config.put(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
        config.put(WSHandlerConstants.USE_SINGLE_CERTIFICATE, "false");
        reqData.setMsgContext(config);

        final Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        CustomHandler handler = new CustomHandler();
        HandlerAction action = new HandlerAction(WSConstants.SIGN);
        handler.send(
            doc,
            reqData,
            Collections.singletonList(action),
            true
        );

        //
        // Verify the signature
        //
        WSHandlerResult results = verify(doc, cryptoCA);
        WSSecurityEngineResult result =
            results.getActionResults().get(WSConstants.SIGN).get(0);
        X509Certificate cert =
            (X509Certificate)result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertNotNull(cert);
        X509Certificate[] certs =
            (X509Certificate[])result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATES);
        assertTrue(certs != null && certs.length == 2);
    }

    @Test
    public void testExpiredCert() throws Exception {
        Properties clientProperties = new Properties();
        clientProperties.put("org.apache.wss4j.crypto.provider",
                "org.apache.wss4j.common.crypto.Merlin");
        clientProperties.put("org.apache.wss4j.crypto.merlin.keystore.type", "jks");
        clientProperties.put("org.apache.wss4j.crypto.merlin.keystore.password", "security");
        clientProperties.put("org.apache.wss4j.crypto.merlin.keystore.alias", "wss40exp");
        clientProperties.put("org.apache.wss4j.crypto.merlin.keystore.file", "keys/wss40exp.jks");

        Crypto clientCrypto = new Merlin(clientProperties, this.getClass().getClassLoader(), null);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature sign = new WSSecSignature(secHeader);
        sign.setUserInfo("wss40exp", "security");
        sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document signedDoc = sign.build(clientCrypto);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        //
        // Verify the signature
        //
        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, null, cryptoCA);
            fail("Failure expected on an expired cert");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILURE);
        }
    }

    @Test
    public void testExpiredCertInKeystore() throws Exception {
        Properties clientProperties = new Properties();
        clientProperties.put("org.apache.wss4j.crypto.provider",
                "org.apache.wss4j.common.crypto.Merlin");
        clientProperties.put("org.apache.wss4j.crypto.merlin.keystore.type", "jks");
        clientProperties.put("org.apache.wss4j.crypto.merlin.keystore.password", "security");
        clientProperties.put("org.apache.wss4j.crypto.merlin.keystore.alias", "wss40exp");
        clientProperties.put("org.apache.wss4j.crypto.merlin.keystore.file", "keys/wss40exp.jks");

        Crypto clientCrypto = new Merlin(clientProperties, this.getClass().getClassLoader(), null);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature sign = new WSSecSignature(secHeader);
        sign.setUserInfo("wss40exp", "security");
        sign.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);

        Document signedDoc = sign.build(clientCrypto);

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        //
        // Verify the signature
        //
        WSSecurityEngine newEngine = new WSSecurityEngine();
        try {
            newEngine.processSecurityHeader(doc, null, null, clientCrypto);
            fail("Failure expected on an expired cert");
        } catch (WSSecurityException ex) {
            assertTrue(ex.getErrorCode() == WSSecurityException.ErrorCode.FAILED_CHECK);
        }
    }

    /**
     * The EdDSA KeyValue test.
     */
    @ParameterizedTest
    @CsvSource({
            "ed25519, 'Algorithm=\"http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519\"', 'CN=ed25519, OU=eDeliveryAS4-2.0, OU=wss4j, O=apache, C=EU'",
            "ed448, 'Algorithm=\"http://www.w3.org/2021/04/xmldsig-more#eddsa-ed448\"', 'CN=ed448, OU=eDeliveryAS4-2.0, OU=wss4j, O=apache, C=EU'",
        })
    public void testEdDSASignatureDirectReference(String alias, String algorithm, X500Principal certSubjectDN) throws Exception {
        try {
            // not needed after JDK 16
            if (!isJDK16up) {
                Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            }

            Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
            WSSecHeader secHeader = new WSSecHeader(doc);
            secHeader.insertSecurityHeader();

            Crypto ed_crypto = CryptoFactory.getInstance("wss-eddsa.properties");

            WSSecSignature builder = new WSSecSignature(secHeader);
            builder.setUserInfo(alias, "security");
            builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
            Document signedDoc = builder.build(ed_crypto);
            // test the algorithm attribute
            String outputString =
                    XMLUtils.prettyDocumentToString(signedDoc);
            if (LOG.isDebugEnabled()) {
                LOG.debug(outputString);
            }

            assertTrue(outputString.contains(algorithm));

            final WSHandlerResult results = verify(signedDoc, ed_crypto);

            WSSecurityEngineResult actionResult =
                    results.getActionResults().get(WSConstants.SIGN).get(0);
            assertNotNull(actionResult);

            java.security.Principal principal =
                    (java.security.Principal) actionResult.get(WSSecurityEngineResult.TAG_PRINCIPAL);
            assertTrue(principal instanceof X500Principal);
            X500Principal x500Principal = (X500Principal) principal;
            assertEquals(certSubjectDN, x500Principal);

        } finally {
            if (!isJDK16up) {
                Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
            }
        }
    }

    /**
     * Verifies the soap envelope
     * <p/>
     *
     * @param doc
     * @throws Exception Thrown when there is a problem in verification
     */
    private WSHandlerResult verify(Document doc, Crypto crypto) throws Exception {
        WSHandlerResult results = secEngine.processSecurityHeader(
            doc, null, null, crypto
        );
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verfied and decrypted message:");
            String outputString =
                XMLUtils.prettyDocumentToString(doc);
            LOG.debug(outputString);
        }
        return results;
    }


}
