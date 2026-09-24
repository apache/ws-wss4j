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
package org.apache.wss4j.stax.test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.ext.WSSSecurityProperties;
import org.apache.wss4j.stax.setup.InboundWSSec;
import org.apache.wss4j.stax.setup.OutboundWSSec;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.wss4j.stax.test.utils.StAX2DOM;
import org.apache.wss4j.stax.test.utils.XmlReaderToWriter;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamReader;
import javax.xml.stream.XMLStreamWriter;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * StAX-path tests for ML-KEM (FIPS 203) key transport in WS-Security SOAP messages, using the
 * W3C "XML Security: Generic Hybrid Cipher" key transport structure
 * (https://www.w3.org/TR/xmlsec-generic-hybrid/, see SANTUARIO-633) - the same wire format now
 * produced by the DOM path ({@link PQCEncryptionTest}), so StAX and DOM ML-KEM output are
 * interoperable.
 */
public class PQCEncryptionStaxTest extends AbstractTestBase {

    private static boolean mlKemAvailable;
    private static boolean bcAddedByTest;
    private static final Map<String, KeyPair> keyPairs = new HashMap<>();

    @BeforeAll
    static void setUpBC() {
        if (Security.getProvider("BC") == null) {
            try {
                Class<?> cls = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
                Provider bc = (Provider) cls.getConstructor().newInstance();
                Security.insertProviderAt(bc, 2);
                bcAddedByTest = true;
            } catch (ReflectiveOperationException e) {
                mlKemAvailable = false;
                return;
            }
        }
        try {
            for (String alg : new String[]{"ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"}) {
                KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg, "BC");
                keyPairs.put(alg, kpg.generateKeyPair());
            }
            mlKemAvailable = true;
        } catch (Exception e) {
            mlKemAvailable = false;
        }
    }

    @AfterAll
    static void removeBCIfAdded() {
        if (bcAddedByTest) {
            Security.removeProvider("BC");
        }
    }

    @ParameterizedTest
    @CsvSource({
        WSS4JConstants.KEYTRANSPORT_ML_KEM_512  + ",ML-KEM-512",
        WSS4JConstants.KEYTRANSPORT_ML_KEM_768  + ",ML-KEM-768",
        WSS4JConstants.KEYTRANSPORT_ML_KEM_1024 + ",ML-KEM-1024"
    })
    public void testMLKEMStaxEncryptStaxDecrypt(String keyTransportUri, String jcaAlgorithm) throws Exception {
        Assumptions.assumeTrue(mlKemAvailable, "ML-KEM requires BouncyCastle 1.84+ and Java 21+ (javax.crypto.KEM)");

        KeyPair kp = keyPairs.get(jcaAlgorithm);

        // Outbound: StAX encrypt
        ByteArrayOutputStream baos;
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            List<WSSConstants.Action> actions = new ArrayList<>();
            actions.add(WSSConstants.ENCRYPTION);
            securityProperties.setActions(actions);
            securityProperties.setEncryptionKeyTransportAlgorithm(keyTransportUri);
            securityProperties.setEncryptionTransportKey(kp.getPublic());
            securityProperties.setEncryptionSymAlgorithm(WSS4JConstants.AES_256_GCM);

            InputStream sourceDocument =
                this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
            baos = doOutboundSecurity(securityProperties, sourceDocument);
        }

        // Verify the serialised XML carries the spec's element names, per
        // https://www.w3.org/TR/xmlsec-generic-hybrid/ section 6.1 "Key Transport Example"
        String serialized = new String(baos.toByteArray(), java.nio.charset.StandardCharsets.UTF_8);
        org.junit.jupiter.api.Assertions.assertTrue(
            serialized.contains("GenericHybridCipherMethod"), "Missing GenericHybridCipherMethod element");
        org.junit.jupiter.api.Assertions.assertTrue(
            serialized.contains("KeyEncapsulationMethod"), "Missing KeyEncapsulationMethod element");
        org.junit.jupiter.api.Assertions.assertTrue(
            serialized.contains("DataEncapsulationMethod"), "Missing DataEncapsulationMethod element");
        org.junit.jupiter.api.Assertions.assertTrue(
            serialized.contains("http://www.w3.org/2010/xmlsec-ghc#generic-hybrid"),
            "Missing Generic Hybrid Cipher EncryptionMethod algorithm");

        // Verify encrypted output has EncryptedKey + EncryptedData
        Document encryptedDoc = documentBuilderFactory.newDocumentBuilder()
            .parse(new ByteArrayInputStream(baos.toByteArray()));
        NodeList encKeys = encryptedDoc.getElementsByTagNameNS(
            WSSConstants.TAG_xenc_EncryptedKey.getNamespaceURI(),
            WSSConstants.TAG_xenc_EncryptedKey.getLocalPart());
        assertEquals(1, encKeys.getLength());
        NodeList encData = encryptedDoc.getElementsByTagNameNS(
            WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
            WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
        assertEquals(1, encData.getLength());

        // Inbound: StAX decrypt
        {
            WSSSecurityProperties securityProperties = new WSSSecurityProperties();
            securityProperties.setDecryptionKey(kp.getPrivate());

            XMLInputFactory xmlInputFactory = XMLInputFactory.newInstance();
            xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, false);
            xmlInputFactory.setProperty(XMLInputFactory.SUPPORT_DTD, false);

            Document plainDoc = doInboundSecurity(securityProperties,
                xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray())));

            // After decryption the EncryptedData element must be gone
            NodeList encDataAfter = plainDoc.getElementsByTagNameNS(
                WSSConstants.TAG_xenc_EncryptedData.getNamespaceURI(),
                WSSConstants.TAG_xenc_EncryptedData.getLocalPart());
            assertEquals(0, encDataAfter.getLength());
        }
    }
}
