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

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSDataRef;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.xml.security.utils.EncryptionConstants;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Tests for ML-KEM (FIPS 203) key transport in WS-Security EncryptedKey, using the W3C
 * "XML Security: Generic Hybrid Cipher" key transport structure
 * (https://www.w3.org/TR/xmlsec-generic-hybrid/, see SANTUARIO-633): the recipient's ML-KEM
 * public key encapsulates a shared secret, an AES key-wrap key is derived from it with HKDF,
 * and the (independently generated) content-encryption key is AES-KeyWrap'd with that derived
 * key - not the raw KEM shared secret used directly as the CEK.
 *
 * <p>Requires BouncyCastle 1.81+, JDK 21+ (javax.crypto.KEM, used internally by Santuario's
 * {@code KeyUtils.kemEncapsulate}/{@code kemDecapsulate}).
 */
public class PQCEncryptionTest {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(PQCEncryptionTest.class);

    private static final String ML_KEM_ALIAS = "mlkem768-test";
    private static final char[] KS_PASSWORD = "pqctest".toCharArray();

    private static KeyPair mlKemKeyPair;
    private static X509Certificate mlKemCert;
    private static Crypto mlKemCrypto;
    private static boolean bcAvailable;

    @BeforeAll
    public static void setUp() throws Exception {
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ML-KEM-768", "BC");
            mlKemKeyPair = kpg.generateKeyPair();
            mlKemCert = buildSelfSignedCert(mlKemKeyPair);
            mlKemCrypto = buildMerlin(mlKemKeyPair, mlKemCert);
            bcAvailable = true;
        } catch (Exception e) {
            LOG.info("ML-KEM not available (BC < 1.81 or provider missing): {}", e.getMessage());
            bcAvailable = false;
        }
        WSSConfig.init();
    }

    @AfterAll
    public static void tearDown() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    private static SecretKey generateCek() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        return keyGen.generateKey();
    }

    /**
     * Round-trip test: real CEK -&gt; ML-KEM-768 Generic Hybrid Cipher key transport -&gt;
     * EncryptedKey XML -&gt; decapsulation/unwrap. Verifies that the CEK is recovered
     * correctly without losing bytes.
     */
    @Test
    public void testMLKEM768EncapsulationRoundTrip() throws Exception {
        assumeTrue(bcAvailable, "ML-KEM-768 requires BouncyCastle 1.81+");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncryptedKey encKeyBuilder = new WSSecEncryptedKey(secHeader);
        encKeyBuilder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        encKeyBuilder.setKeyEncAlgo(WSS4JConstants.KEYTRANSPORT_ML_KEM_768);
        encKeyBuilder.setUserInfo(ML_KEM_ALIAS);

        SecretKey cek = generateCek();
        encKeyBuilder.prepare(mlKemCrypto, cek);

        // Append EncryptedKey to the security header so it's part of the document.
        WSSecurityUtil.prependChildElement(
            secHeader.getSecurityHeaderElement(), encKeyBuilder.getEncryptedKeyElement());

        String xml = XMLUtils.prettyDocumentToString(doc);
        LOG.debug("EncryptedKey document:\n{}", xml);
        assertTrue(xml.contains(EncryptionConstants.ALGO_ID_KEYTRANSPORT_GENERIC_HYBRID),
            "EncryptedKey must carry the Generic Hybrid Cipher Algorithm attribute");
        assertTrue(xml.contains("GenericHybridCipherMethod"), "Missing GenericHybridCipherMethod element");
        assertTrue(xml.contains("KeyEncapsulationMethod"), "Missing KeyEncapsulationMethod element");
        assertTrue(xml.contains(WSS4JConstants.KEYTRANSPORT_ML_KEM_768),
            "KeyEncapsulationMethod must carry the ML-KEM-768 Algorithm attribute");
        assertTrue(xml.contains("DataEncapsulationMethod"), "Missing DataEncapsulationMethod element");

        // Decrypt via WSSecurityEngine
        RequestData data = new RequestData();
        data.setDecCrypto(mlKemCrypto);
        data.setCallbackHandler(mlKemCallbackHandler());
        data.setWssConfig(WSSConfig.getNewInstance());

        WSSecurityEngine engine = new WSSecurityEngine();
        WSHandlerResult results = engine.processSecurityHeader(doc, data);

        WSSecurityEngineResult encResult = results.getActionResults()
            .getOrDefault(WSConstants.ENCR, List.of()).stream().findFirst()
            .orElse(null);
        assertNotNull(encResult, "Engine must produce an ENCR result");

        byte[] recoveredKey = (byte[]) encResult.get(WSSecurityEngineResult.TAG_SECRET);
        assertNotNull(recoveredKey, "Recovered key bytes must not be null");
        org.junit.jupiter.api.Assertions.assertArrayEquals(cek.getEncoded(), recoveredKey,
            "Unwrapped key must match the original CEK");
    }

    /**
     * Full SOAP message test: encrypt body with ML-KEM-768 key transport +
     * AES-256-GCM content encryption, then decrypt and verify body.
     */
    @Test
    public void testMLKEM768FullMessageEncryptDecrypt() throws Exception {
        assumeTrue(bcAvailable, "ML-KEM-768 requires BouncyCastle 1.81+");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        // Step 1: real CEK, ML-KEM key transport
        WSSecEncryptedKey encKeyBuilder = new WSSecEncryptedKey(secHeader);
        encKeyBuilder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        encKeyBuilder.setKeyEncAlgo(WSS4JConstants.KEYTRANSPORT_ML_KEM_768);
        encKeyBuilder.setUserInfo(ML_KEM_ALIAS);
        SecretKey cek = generateCek();
        encKeyBuilder.prepare(mlKemCrypto, cek);

        // Step 2: encrypt SOAP body with the same CEK using AES-256-GCM
        WSSecEncrypt encBuilder = new WSSecEncrypt(secHeader);
        encBuilder.setSymmetricEncAlgorithm(WSConstants.AES_256_GCM);
        encBuilder.setEncryptSymmKey(false);
        encBuilder.setCustomReferenceValue(encKeyBuilder.getId());
        Document encryptedDoc = encBuilder.build(mlKemCrypto, cek);

        // Prepend EncryptedKey before EncryptedData in the security header.
        Element encKeyElement = encKeyBuilder.getEncryptedKeyElement();
        WSSecurityUtil.prependChildElement(secHeader.getSecurityHeaderElement(), encKeyElement);

        String xml = XMLUtils.prettyDocumentToString(encryptedDoc);
        LOG.debug("Full encrypted message:\n{}", xml);
        assertTrue(xml.contains(EncryptionConstants.ALGO_ID_KEYTRANSPORT_GENERIC_HYBRID));
        assertTrue(xml.contains(WSS4JConstants.KEYTRANSPORT_ML_KEM_768));
        assertTrue(xml.contains(WSConstants.AES_256_GCM));
        assertTrue(!xml.contains("counter_port_type"), "Body must be encrypted");

        // Step 3: decrypt
        RequestData data = new RequestData();
        data.setDecCrypto(mlKemCrypto);
        data.setCallbackHandler(mlKemCallbackHandler());
        data.setWssConfig(WSSConfig.getNewInstance());

        WSSecurityEngine engine = new WSSecurityEngine();
        WSHandlerResult results = engine.processSecurityHeader(encryptedDoc, data);

        // EncryptedKey produces one ENCR result; EncryptedData produces another.
        // Walk all results to find the one that carries the Body DataRef.
        boolean foundBodyRef = false;
        for (WSSecurityEngineResult result : results.getResults()) {
            Integer action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            if (action != null && (action & WSConstants.ENCR) != 0) {
                @SuppressWarnings("unchecked")
                List<WSDataRef> refs = (List<WSDataRef>) result.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
                if (refs != null) {
                    for (WSDataRef ref : refs) {
                        if (ref.getName() != null && "Body".equals(ref.getName().getLocalPart())) {
                            foundBodyRef = true;
                        }
                    }
                }
            }
        }
        assertTrue(foundBodyRef, "Decrypted data refs must include the SOAP Body");
    }

    /**
     * Tests that {@link WSSecEncrypt#build} with ML-KEM key transport (single-call API)
     * correctly encrypts and decrypts the SOAP body, using the caller-supplied CEK for both
     * content encryption and key transport (there is no more KEM-derived-key substitution -
     * the KEM shared secret only ever derives the AES key-wrap key, never the CEK itself).
     */
    @Test
    public void testMLKEM768SingleCallBuildEncryptDecrypt() throws Exception {
        assumeTrue(bcAvailable, "ML-KEM-768 requires BouncyCastle 1.81+");

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        // Use WSSecEncrypt in single-call mode with ML-KEM key transport.
        WSSecEncrypt wsEncrypt = new WSSecEncrypt(secHeader);
        wsEncrypt.setSymmetricEncAlgorithm(WSConstants.AES_256_GCM);
        wsEncrypt.setKeyEncAlgo(WSS4JConstants.KEYTRANSPORT_ML_KEM_768);
        wsEncrypt.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        wsEncrypt.setUserInfo(ML_KEM_ALIAS);

        SecretKey cek = generateCek();

        Document encryptedDoc = wsEncrypt.build(mlKemCrypto, cek);

        String xml = XMLUtils.prettyDocumentToString(encryptedDoc);
        assertTrue(xml.contains(WSS4JConstants.KEYTRANSPORT_ML_KEM_768),
            "Encrypted document must contain the ML-KEM-768 key transport URI");
        assertTrue(xml.contains(WSConstants.AES_256_GCM),
            "Encrypted document must contain AES-256-GCM content encryption");
        assertTrue(!xml.contains("counter_port_type"), "Body must be encrypted");

        // Decrypt the document — this must succeed only if the correct CEK was used.
        RequestData data = new RequestData();
        data.setDecCrypto(mlKemCrypto);
        data.setCallbackHandler(mlKemCallbackHandler());
        data.setWssConfig(WSSConfig.getNewInstance());

        WSSecurityEngine engine = new WSSecurityEngine();
        WSHandlerResult results = engine.processSecurityHeader(encryptedDoc, data);

        boolean foundBodyRef = false;
        for (WSSecurityEngineResult result : results.getResults()) {
            Integer action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            if (action != null && (action & WSConstants.ENCR) != 0) {
                @SuppressWarnings("unchecked")
                List<WSDataRef> refs = (List<WSDataRef>) result.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
                if (refs != null) {
                    for (WSDataRef ref : refs) {
                        if (ref.getName() != null && "Body".equals(ref.getName().getLocalPart())) {
                            foundBodyRef = true;
                        }
                    }
                }
            }
        }
        assertTrue(foundBodyRef, "Decrypted data refs must include the SOAP Body");
    }

    /**
     * Verify that the BSP whitelist accepts the Generic Hybrid Cipher (ML-KEM) top-level
     * algorithm without throwing.
     */
    @Test
    public void testMLKEM512BSPWhitelist() throws Exception {
        assumeTrue(bcAvailable, "ML-KEM-512 requires BouncyCastle 1.81+");

        KeyPairGenerator kpg512 = KeyPairGenerator.getInstance("ML-KEM-512", "BC");
        KeyPair kp512 = kpg512.generateKeyPair();
        X509Certificate cert512 = buildSelfSignedCert(kp512);
        Crypto crypto512 = buildMerlin(kp512, cert512);

        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncryptedKey builder = new WSSecEncryptedKey(secHeader);
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setKeyEncAlgo(WSS4JConstants.KEYTRANSPORT_ML_KEM_512);
        builder.setUserInfo(ML_KEM_ALIAS);
        builder.prepare(crypto512, generateCek());

        // Append EncryptedKey to the security header.
        WSSecurityUtil.prependChildElement(
            secHeader.getSecurityHeaderElement(), builder.getEncryptedKeyElement());

        // Decrypt — must not throw BSP R5621
        RequestData data = new RequestData();
        data.setDecCrypto(crypto512);
        data.setCallbackHandler(mlKemCallbackHandler());
        data.setWssConfig(WSSConfig.getNewInstance());

        WSSecurityEngine engine = new WSSecurityEngine();
        WSHandlerResult results = engine.processSecurityHeader(doc, data);
        assertNotNull(results.getActionResults().get(WSConstants.ENCR));
    }

    // ---- helpers -------------------------------------------------------

    private static X509Certificate buildSelfSignedCert(KeyPair kemKeyPair) throws Exception {
        // ML-KEM keys cannot sign; use an ephemeral EC key to sign the certificate.
        KeyPairGenerator ecKpg = KeyPairGenerator.getInstance("EC", "BC");
        ecKpg.initialize(256);
        KeyPair signingKP = ecKpg.generateKeyPair();

        X500Name subject = new X500Name("CN=ML-KEM Test, O=WSS4J PQC Test");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 86_400_000L);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            subject, BigInteger.ONE, notBefore, notAfter, subject,
            kemKeyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider("BC").build(signingKP.getPrivate());

        return new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(certBuilder.build(signer));
    }

    private static Crypto buildMerlin(KeyPair kemKP, X509Certificate cert) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, KS_PASSWORD);
        ks.setKeyEntry(ML_KEM_ALIAS, kemKP.getPrivate(), KS_PASSWORD,
            new java.security.cert.Certificate[]{cert});

        Merlin merlin = new Merlin();
        merlin.setKeyStore(ks);
        return merlin;
    }

    private static CallbackHandler mlKemCallbackHandler() {
        return callbacks -> {
            for (javax.security.auth.callback.Callback cb : callbacks) {
                if (cb instanceof WSPasswordCallback pc) {
                    if (ML_KEM_ALIAS.equals(pc.getIdentifier())) {
                        pc.setPassword(new String(KS_PASSWORD));
                    }
                }
            }
        };
    }
}
