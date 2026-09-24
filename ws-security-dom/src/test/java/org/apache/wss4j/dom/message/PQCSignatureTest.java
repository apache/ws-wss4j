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

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

/**
 * Tests for ML-DSA (FIPS 204) WS-Security signatures.
 *
 * <p>Requires BouncyCastle 1.81+ and Santuario xmlsec 4.0.5-SNAPSHOT (or later)
 * which adds {@code DOMMLDSASignatureMethod} support for ML-DSA URIs.
 */
public class PQCSignatureTest {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(PQCSignatureTest.class);

    private static final String ML_DSA_ALIAS = "mldsa-test";
    private static final char[] KS_PASSWORD = "pqctest".toCharArray();

    private static boolean bcAvailable;

    @BeforeAll
    public static void setUp() {
        try {
            Security.addProvider(new BouncyCastleProvider());
            KeyPairGenerator.getInstance("ML-DSA-65", "BC").generateKeyPair();
            bcAvailable = true;
        } catch (Exception e) {
            LOG.info("ML-DSA not available (BC < 1.81 or provider missing): {}", e.getMessage());
            bcAvailable = false;
        }
        WSSConfig.init();
    }

    @AfterAll
    public static void tearDown() {
        Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
    }

    /**
     * Full WS-Security sign + verify round-trip with ML-DSA.
     * Signs a SOAP envelope using {@link WSSecSignature} then verifies it
     * with {@link WSSecurityEngine}. Exercises the complete path through
     * Santuario's {@code DOMXMLSignatureFactory} with the ML-DSA URI.
     */
    @ParameterizedTest
    @CsvSource({
        "ML-DSA-44," + WSS4JConstants.ML_DSA_44,
        "ML-DSA-65," + WSS4JConstants.ML_DSA_65,
        "ML-DSA-87," + WSS4JConstants.ML_DSA_87
    })
    public void testMLDSAWSSSignAndVerify(String jcaName, String sigAlgoUri) throws Exception {
        assumeTrue(bcAvailable, "ML-DSA requires BouncyCastle 1.81+");

        KeyPair kp = KeyPairGenerator.getInstance(jcaName, "BC").generateKeyPair();
        X509Certificate cert = buildSelfSignedCert(kp, jcaName);
        Crypto crypto = buildMerlin(kp, cert);

        // --- Sign ---
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecSignature builder = new WSSecSignature(secHeader);
        builder.setUserInfo(ML_DSA_ALIAS, new String(KS_PASSWORD));
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        builder.setSignatureAlgorithm(sigAlgoUri);
        Document signedDoc = builder.build(crypto);

        String xml = XMLUtils.prettyDocumentToString(signedDoc);
        LOG.debug("Signed ML-DSA ({}) document:\n{}", jcaName, xml);
        assertTrue(xml.contains(sigAlgoUri),
            "Signed document must contain the ML-DSA algorithm URI");

        // --- Verify ---
        RequestData reqData = new RequestData();
        reqData.setSigVerCrypto(crypto);
        reqData.setCallbackHandler(mlDsaCallbackHandler());
        reqData.setWssConfig(WSSConfig.getNewInstance());

        WSSecurityEngine engine = new WSSecurityEngine();
        WSHandlerResult results = engine.processSecurityHeader(signedDoc, reqData);

        WSSecurityEngineResult sigResult = results.getActionResults()
            .getOrDefault(WSConstants.SIGN, List.of())
            .stream().findFirst().orElse(null);
        assertNotNull(sigResult, "Engine must produce a SIGN result");

        X509Certificate verifiedCert =
            (X509Certificate) sigResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
        assertNotNull(verifiedCert, "Verified certificate must be present in SIGN result");
        LOG.debug("{} signature verified; subject: {}", jcaName,
            verifiedCert.getSubjectX500Principal().getName());
    }

    // ---- helpers -------------------------------------------------------

    private static X509Certificate buildSelfSignedCert(KeyPair kp, String jcaName)
            throws Exception {
        X500Name subject = new X500Name("CN=" + jcaName + " Test, O=WSS4J PQC Test");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 365L * 86_400_000L);
        ContentSigner signer = new JcaContentSignerBuilder(jcaName)
            .setProvider("BC").build(kp.getPrivate());
        return new JcaX509CertificateConverter()
            .setProvider("BC")
            .getCertificate(new JcaX509v3CertificateBuilder(
                subject, BigInteger.ONE, notBefore, notAfter, subject, kp.getPublic())
                .build(signer));
    }

    private static Crypto buildMerlin(KeyPair kp, X509Certificate cert) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12", "BC");
        ks.load(null, KS_PASSWORD);
        ks.setKeyEntry(ML_DSA_ALIAS, kp.getPrivate(), KS_PASSWORD,
            new java.security.cert.Certificate[]{cert});
        Merlin merlin = new Merlin();
        merlin.setKeyStore(ks);
        return merlin;
    }

    private static CallbackHandler mlDsaCallbackHandler() {
        return callbacks -> {
            for (javax.security.auth.callback.Callback cb : callbacks) {
                if (cb instanceof WSPasswordCallback pc
                        && ML_DSA_ALIAS.equals(pc.getIdentifier())) {
                    pc.setPassword(new String(KS_PASSWORD));
                }
            }
        };
    }
}
