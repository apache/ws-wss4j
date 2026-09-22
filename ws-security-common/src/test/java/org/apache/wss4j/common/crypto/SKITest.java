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

package org.apache.wss4j.common.crypto;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.Loader;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * This is a test for WSS-300 - "SubjectKeyIdentifier (SKI) incorrectly calculated for 2048-bit RSA key".
 * The SKI value WSS4J generates for various key sizes is tested against the output from openssl, e.g.:
 *
 * openssl x509 -inform der -ocspid -in wss40_server.crt | grep 'Public key OCSP hash'
 * | perl -ne 'split; print pack("H*",$_[4])' | base64
 */
public class SKITest {

    @Test
    public void testRSA1024() throws Exception {
        // Load the keystore
        Crypto crypto = new Merlin();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(SKITest.class);
        InputStream input = Merlin.loadInputStream(loader, "keys/rsa1024.jks");
        keyStore.load(input, "security".toCharArray());
        input.close();
        ((Merlin)crypto).setKeyStore(keyStore);

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        assertTrue(certs != null && certs.length > 0);

        byte[] skiBytes = crypto.getSKIBytesFromCert(certs[0]);
        String knownBase64Encoding = "H7dt0lv9M8uYOy4SedV0kPOs22A=";
        assertTrue(knownBase64Encoding.equals(org.apache.xml.security.utils.XMLUtils.encodeToString(skiBytes)));
    }

    @Test
    public void testRSA2048() throws Exception {
        // Load the keystore
        Crypto crypto = new Merlin();
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(SKITest.class);
        InputStream input = Merlin.loadInputStream(loader, "keys/wss40_server.jks");
        keyStore.load(input, "security".toCharArray());
        input.close();
        ((Merlin)crypto).setKeyStore(keyStore);

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
        cryptoType.setAlias("wss40_server");
        X509Certificate[] certs = crypto.getX509Certificates(cryptoType);
        assertTrue(certs != null && certs.length > 0);

        byte[] skiBytes = crypto.getSKIBytesFromCert(certs[0]);
        String knownBase64Encoding = "5LsTsLDSb7XxlaCffjNBHM5n+1A=";
        assertTrue(knownBase64Encoding.equals(org.apache.xml.security.utils.XMLUtils.encodeToString(skiBytes)));
    }

    /**
     * A self-signed certificate whose SubjectKeyIdentifier extension declares a key identifier of
     * Integer.MAX_VALUE bytes. The certificate itself is 442 bytes. Its extnValue is
     * 04 09 04 84 7F FF FF FF 01 02 03: an OCTET STRING wrapping an OCTET STRING whose long-form
     * length is 0x7FFFFFFF. Certificates reach this code path from an inbound
     * wsse:BinarySecurityToken, so the declared length is attacker-controlled.
     */
    private static final String HOSTILE_SKI_CERT =
          "MIIBtjCCAR+gAwIBAgIBATANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDDAtob3N0aWxlLXNraTAe"
        + "Fw0yNTAxMDEwMDAwMDBaFw0zNTAxMDEwMDAwMDBaMBYxFDASBgNVBAMMC2hvc3RpbGUtc2tpMIGf"
        + "MA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCrq6urq6urq6urq6urq6urq6urq6urq6urq6urq6ur"
        + "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6ur"
        + "q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urqwIDAQABoxQwEjAQBgNVHQ4E"
        + "CQSEf////wECAzANBgkqhkiG9w0BAQsFAAOBgQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";

    /**
     * An over-long declared length in the SubjectKeyIdentifier must produce a WSSecurityException,
     * not a multi-gigabyte allocation and not an unchecked exception.
     */
    @Test
    public void testSKIWithOverlongDeclaredLength() throws Exception {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert;
        try (InputStream input = new ByteArrayInputStream(Base64.getDecoder().decode(HOSTILE_SKI_CERT))) {
            cert = (X509Certificate)certificateFactory.generateCertificate(input);
        }

        byte[] extensionValue = cert.getExtensionValue(CryptoBase.SKI_OID);
        // A JDK that rejects the malformed extension outright leaves nothing for us to decode
        Assumptions.assumeTrue(extensionValue != null);
        assertArrayEquals(
            new byte[] {4, 9, 4, (byte)0x84, 0x7F, (byte)0xFF, (byte)0xFF, (byte)0xFF, 1, 2, 3},
            extensionValue
        );

        Crypto crypto = new Merlin();
        assertThrows(WSSecurityException.class, () -> crypto.getSKIBytesFromCert(cert));
    }

    @Test
    public void testBouncyCastlePKCS12() throws Exception {
        try {
            Security.addProvider(new BouncyCastleProvider());

            // Load the keystore
            Crypto crypto = CryptoFactory.getInstance("alice_bouncycastle.properties");
            assertNotNull(crypto);
        } finally {
            Security.removeProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
    }
}