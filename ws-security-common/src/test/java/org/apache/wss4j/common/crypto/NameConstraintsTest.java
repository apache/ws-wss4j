/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.wss4j.common.crypto;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsEqual.equalTo;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Properties;
import java.util.regex.Pattern;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.Loader;
import org.junit.Before;
import org.junit.Test;

/**
 * Tests the handling of {@code NameConstraint}s with {@code TrustAnchor}s in the
 * {@link Merlin}, {@link MerlinAKI}, and {@link CertificateStore} crypto implementations.
 * Specifically tests the following:
 * <ul>
 * <li>That when Name Constraints are extracted from a certificate they are correctly
 * decoded into a SEQUENCE</li>
 * <li>That when the new property {@code org.apache.wss4j.crypto.merlin.cert.provider.nameconstraints}
 * is set to true on the Merlin and MerlinAKI implementations the Trust Anchors constructed
 * for path validation have the Name Constraints added</li>
 * <li>That when the above property is <em>not</em> set, the Trust Anchors have
 * null Name Constraints added</li>
 * </ul>
 */
public class NameConstraintsTest extends org.junit.Assert {
    private static final String KEY_ROOT = "keys/nameconstraints/";

    private static final String SELF_SIGNED = KEY_ROOT + "self_signed.p12";

    private static final String ROOT_SIGNED = KEY_ROOT + "root_signed.p12";

    private static final String INTERMEDIATE_SIGNED = KEY_ROOT + "intermediate_signed.p12";

    private static final String KEYSTORE = KEY_ROOT + "nameconstraints.jks";

    private static final char[] PASSWORD = "changeit".toCharArray();

    private static final Pattern SUBJ_PATTERN = Pattern.compile(".*OU=wss4j,O=apache");

    @Before
    public void setup() throws Exception {
        WSProviderConfig.init();
    }

    private KeyStore getRootKeyStore() throws Exception {
        ClassLoader loader = Loader.getClassLoader(NameConstraintsTest.class);
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());

        try (InputStream inputStream = Merlin.loadInputStream(loader, KEYSTORE)) {
            keyStore.load(inputStream, PASSWORD);
            return keyStore;
        }
    }

    private KeyStore getSelfKeyStore() throws Exception {
        ClassLoader loader = Loader.getClassLoader(NameConstraintsTest.class);
        KeyStore keyStore = KeyStore.getInstance("PKCS12");

        try (InputStream inputStream = loader.getResourceAsStream(SELF_SIGNED)) {
            keyStore.load(inputStream, PASSWORD);
            return keyStore;
        }
    }

    private X509Certificate[] getTestCertificateChain(String keychainPath) throws Exception {
        ClassLoader loader = Loader.getClassLoader(NameConstraintsTest.class);
        KeyStore keystore = KeyStore.getInstance("PKCS12");

        try (InputStream inputStream = loader.getResourceAsStream(keychainPath)) {
            keystore.load(inputStream, PASSWORD);

            // We're loading a single cert chain; there will be one alias
            Enumeration<String> aliases = keystore.aliases();
            Certificate[] certificates = keystore.getCertificateChain(aliases.nextElement());
            assertTrue(certificates != null);

            X509Certificate[] x509Certificates = new X509Certificate[certificates.length];
            System.arraycopy(certificates, 0, x509Certificates, 0, certificates.length);

            return x509Certificates;
        }
    }

    @Test
    public void testNameConstraints() throws Exception {
        Merlin merlin = new Merlin();
        X509Certificate[] certificates = getTestCertificateChain(INTERMEDIATE_SIGNED);

        assertNull(merlin.getNameConstraints(certificates[0]));
        assertNull(merlin.getNameConstraints(certificates[1]));

        byte[] nameConstraints = merlin.getNameConstraints(certificates[2]);
        assertNotNull(nameConstraints);
        assertThat("Tag byte is wrong", nameConstraints[0], is(DERDecoder.TYPE_SEQUENCE));

        TrustAnchor trustAnchor = new TrustAnchor(certificates[2], nameConstraints);
        assertThat("TrustAnchor constraints wrong",
                trustAnchor.getNameConstraints(),
                equalTo(nameConstraints));
    }

    @Test
    public void testNameConstraintsWithKeyStoreUsingMerlin() throws Exception {
        withKeyStoreUsingMerlin(getSelfKeyStore(),
                getTestCertificateChain(SELF_SIGNED),
                new Merlin());
        withKeyStoreUsingMerlin(getRootKeyStore(),
                getTestCertificateChain(ROOT_SIGNED),
                new Merlin());
        withKeyStoreUsingMerlin(getRootKeyStore(),
                getTestCertificateChain(INTERMEDIATE_SIGNED),
                new Merlin());
    }

    @Test
    public void testNameConstraintsWithTrustStoreUsingMerlin() throws Exception {
        withTrustStoreUsingMerlin(getSelfKeyStore(),
                getTestCertificateChain(SELF_SIGNED),
                new Merlin());
        withTrustStoreUsingMerlin(getRootKeyStore(),
                getTestCertificateChain(ROOT_SIGNED),
                new Merlin());
        withTrustStoreUsingMerlin(getRootKeyStore(),
                getTestCertificateChain(INTERMEDIATE_SIGNED),
                new Merlin());
    }

    @Test
    public void testNameConstraintsWithKeyStoreUsingMerlinAki() throws Exception {
        withKeyStoreUsingMerlinAKI(getSelfKeyStore(),
                getTestCertificateChain(SELF_SIGNED),
                new MerlinAKI());
        withKeyStoreUsingMerlinAKI(getRootKeyStore(),
                getTestCertificateChain(ROOT_SIGNED),
                new MerlinAKI());
        withKeyStoreUsingMerlinAKI(getRootKeyStore(),
                getTestCertificateChain(INTERMEDIATE_SIGNED),
                new MerlinAKI());
    }

    @Test
    public void testNameConstraintsWithTrustStoreUsingMerlinAki() throws Exception {
        withTrustStoreUsingMerlinAKI(getSelfKeyStore(),
                getTestCertificateChain(SELF_SIGNED),
                new MerlinAKI());
        withTrustStoreUsingMerlinAKI(getRootKeyStore(),
                getTestCertificateChain(ROOT_SIGNED),
                new MerlinAKI());
        withTrustStoreUsingMerlinAKI(getRootKeyStore(),
                getTestCertificateChain(INTERMEDIATE_SIGNED),
                new MerlinAKI());
    }

    @Test
    public void testNameConstraintsWithKeyStoreUsingMerlinBc() throws Exception {
        withKeyStoreUsingMerlin(getSelfKeyStore(),
                getTestCertificateChain(SELF_SIGNED),
                getMerlinBc());
        withKeyStoreUsingMerlin(getRootKeyStore(),
                getTestCertificateChain(ROOT_SIGNED),
                getMerlinBc());
        withKeyStoreUsingMerlin(getRootKeyStore(),
                getTestCertificateChain(INTERMEDIATE_SIGNED),
                getMerlinBc());
    }

    @Test
    public void testNameConstraintsWithTrustStoreUsingMerlinBc() throws Exception {
        withTrustStoreUsingMerlin(getSelfKeyStore(),
                getTestCertificateChain(SELF_SIGNED),
                getMerlinBc());
        withTrustStoreUsingMerlin(getRootKeyStore(),
                getTestCertificateChain(ROOT_SIGNED),
                getMerlinBc());
        withTrustStoreUsingMerlin(getRootKeyStore(),
                getTestCertificateChain(INTERMEDIATE_SIGNED),
                getMerlinBc());
    }

    @Test
    public void testNameConstraintsWithKeyStoreUsingMerlinAkiBc() throws Exception {
        withKeyStoreUsingMerlinAKI(getSelfKeyStore(),
                getTestCertificateChain(SELF_SIGNED),
                getMerlinAkiBc());
        withKeyStoreUsingMerlinAKI(getRootKeyStore(),
                getTestCertificateChain(ROOT_SIGNED),
                getMerlinAkiBc());
        withKeyStoreUsingMerlinAKI(getRootKeyStore(),
                getTestCertificateChain(INTERMEDIATE_SIGNED),
                getMerlinAkiBc());
    }

    @Test
    public void testNameConstraintsWithTrustStoreUsingMerlinAkiBc() throws Exception {
        withTrustStoreUsingMerlinAKI(getSelfKeyStore(),
                getTestCertificateChain(SELF_SIGNED),
                getMerlinAkiBc());
        withTrustStoreUsingMerlinAKI(getRootKeyStore(),
                getTestCertificateChain(ROOT_SIGNED),
                getMerlinAkiBc());
        withTrustStoreUsingMerlinAKI(getRootKeyStore(),
                getTestCertificateChain(INTERMEDIATE_SIGNED),
                getMerlinAkiBc());
    }

    @Test(expected = Exception.class)
    public void testNameConstraintsWithKeyStoreUsingMerlinBreaking() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("org.apache.wss4j.crypto.merlin.cert.provider.nameconstraints",
                "true");

        Merlin merlin = new Merlin(properties,
                this.getClass()
                        .getClassLoader(),
                null);

        withKeyStoreUsingMerlin(getRootKeyStore(), getTestCertificateChain(ROOT_SIGNED), merlin);
    }

    @Test(expected = Exception.class)
    public void testNameConstraintsWithKeyStoreUsingMerlinAkiBreaking() throws Exception {
        Properties properties = new Properties();
        properties.setProperty("org.apache.wss4j.crypto.merlin.cert.provider.nameconstraints",
                "true");

        MerlinAKI merlin = new MerlinAKI(properties,
                this.getClass()
                        .getClassLoader(),
                null);

        withKeyStoreUsingMerlin(getRootKeyStore(), getTestCertificateChain(ROOT_SIGNED), merlin);
    }

    @Test
    public void testNameConstraintsUsingCertificateStore() throws Exception {
        usingCertificateStore(getSelfKeyStore(), getTestCertificateChain(SELF_SIGNED));
        usingCertificateStore(getRootKeyStore(), getTestCertificateChain(ROOT_SIGNED));
        usingCertificateStore(getRootKeyStore(), getTestCertificateChain(INTERMEDIATE_SIGNED));
    }

    private void withKeyStoreUsingMerlin(KeyStore keyStore, X509Certificate[] certificates,
            Merlin crypto) throws Exception {
        // Load the keystore
        crypto.setKeyStore(keyStore);

        crypto.verifyTrust(certificates, false, Collections.singletonList(SUBJ_PATTERN));
        // No WSSecurityException thrown
    }

    private void withTrustStoreUsingMerlin(KeyStore keyStore, X509Certificate[] certificates,
            Merlin crypto) throws Exception {
        // Load the keystore
        crypto.setTrustStore(keyStore);

        crypto.verifyTrust(certificates, false, Collections.singletonList(SUBJ_PATTERN));
        // No WSSecurityException thrown
    }

    private void withKeyStoreUsingMerlinAKI(KeyStore keyStore, X509Certificate[] certificates,
            MerlinAKI crypto) throws Exception {
        // Load the keystore
        crypto.setKeyStore(keyStore);

        crypto.verifyTrust(certificates, false, Collections.singletonList(SUBJ_PATTERN));
        // No WSSecurityException thrown
    }

    private void withTrustStoreUsingMerlinAKI(KeyStore keyStore, X509Certificate[] certificates,
            MerlinAKI crypto) throws Exception {
        // Load the keystore
        crypto.setTrustStore(keyStore);

        crypto.verifyTrust(certificates, false, Collections.singletonList(SUBJ_PATTERN));
        // No WSSecurityException thrown
    }

    private void usingCertificateStore(KeyStore keyStore, X509Certificate[] certificates)
            throws Exception {
        // Load the keystore
        Enumeration<String> aliases = keyStore.aliases();
        List<X509Certificate> certList = new ArrayList<>();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            certList.add((X509Certificate) keyStore.getCertificate(alias));
        }

        CertificateStore crypto = new CertificateStore(certList.toArray(new X509Certificate[] {}));

        crypto.verifyTrust(certificates, false, Collections.singletonList(SUBJ_PATTERN));
        // No WSSecurityException thrown
    }

    private Merlin getMerlinBc() throws WSSecurityException, IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Properties properties = new Properties();
        properties.setProperty("org.apache.wss4j.crypto.merlin.cert.provider", "BC");
        properties.setProperty("org.apache.wss4j.crypto.merlin.cert.provider.nameconstraints",
                "true");

        return new Merlin(properties,
                this.getClass()
                        .getClassLoader(),
                null);
    }

    private MerlinAKI getMerlinAkiBc() throws WSSecurityException, IOException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Properties properties = new Properties();
        properties.setProperty("org.apache.wss4j.crypto.merlin.cert.provider", "BC");
        properties.setProperty("org.apache.wss4j.crypto.merlin.cert.provider.nameconstraints",
                "true");

        return new MerlinAKI(properties,
                this.getClass()
                        .getClassLoader(),
                null);
    }
}
