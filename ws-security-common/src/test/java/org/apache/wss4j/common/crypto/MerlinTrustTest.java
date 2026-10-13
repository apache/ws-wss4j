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

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.Loader;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for the order in which Merlin searches the truststore and keystore when verifying
 * trust in a certificate (WSS-721).
 */
public class MerlinTrustTest {

    private static X509Certificate wss40Cert;

    @BeforeAll
    public static void setup() throws Exception {
        WSProviderConfig.init();
        wss40Cert = (X509Certificate)loadKeyStore("keys/wss40.jks").getCertificate("wss40");
    }

    /**
     * A certificate that is in the truststore is directly trusted without searching the keystore.
     */
    @Test
    public void testDirectTrustSearchesTruststoreFirst() throws Exception {
        verifyDirectTrustSearchesTruststoreFirst(new Merlin());
    }

    @Test
    public void testDirectTrustSearchesTruststoreFirstAKI() throws Exception {
        verifyDirectTrustSearchesTruststoreFirst(new MerlinAKI());
    }

    private void verifyDirectTrustSearchesTruststoreFirst(Merlin crypto) throws Exception {
        KeyStore truststore = createEmptyKeyStore();
        truststore.setCertificateEntry("wss40", wss40Cert);

        AtomicInteger keystoreSearches = new AtomicInteger();
        crypto.setKeyStore(countingKeyStore(loadKeyStore("keys/wss40_server.jks"), keystoreSearches));
        crypto.setTrustStore(truststore);

        crypto.verifyTrust(new X509Certificate[] {wss40Cert}, false, null, null);
        assertEquals(0, keystoreSearches.get());
    }

    /**
     * The issuer of a certificate is looked up in the truststore before the keystore. The keystore
     * is only searched once, for the certificate itself, and not again for its issuer.
     */
    @Test
    public void testIssuerSearchesTruststoreFirst() throws Exception {
        AtomicInteger keystoreSearches = new AtomicInteger();
        Merlin crypto = new Merlin();
        crypto.setKeyStore(countingKeyStore(loadKeyStore("keys/wss40_server.jks"), keystoreSearches));
        crypto.setTrustStore(loadKeyStore("keys/wss40CA.jks"));

        crypto.verifyTrust(new X509Certificate[] {wss40Cert}, false, null, null);
        assertEquals(1, keystoreSearches.get());
    }

    /**
     * A certificate that is only in the keystore is still directly trusted.
     */
    @Test
    public void testDirectTrustInKeystore() throws Exception {
        Merlin crypto = new Merlin();
        crypto.setKeyStore(loadKeyStore("keys/wss40.jks"));
        crypto.setTrustStore(createEmptyKeyStore());

        crypto.verifyTrust(new X509Certificate[] {wss40Cert}, false, null, null);
    }

    /**
     * A certificate in neither the truststore nor the keystore, whose issuer is only in the keystore,
     * is not trusted when a truststore is configured.
     */
    @Test
    public void testNotTrusted() throws Exception {
        Merlin crypto = new Merlin();
        crypto.setKeyStore(loadKeyStore("keys/wss40_server.jks"));
        crypto.setTrustStore(createEmptyKeyStore());

        assertThrows(WSSecurityException.class,
            () -> crypto.verifyTrust(new X509Certificate[] {wss40Cert}, false, null, null));
    }

    private static KeyStore loadKeyStore(String path) throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        ClassLoader loader = Loader.getClassLoader(MerlinTrustTest.class);
        try (InputStream input = Merlin.loadInputStream(loader, path)) {
            keyStore.load(input, "security".toCharArray());
        }
        return keyStore;
    }

    private static KeyStore createEmptyKeyStore() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load(null, null);
        return keyStore;
    }

    /**
     * Wrap a KeyStore so that each enumeration of its aliases is counted.
     */
    private static KeyStore countingKeyStore(KeyStore delegate, AtomicInteger aliasesCount) throws Exception {
        KeyStore keyStore = new KeyStore(new CountingKeyStoreSpi(delegate, aliasesCount),
                                         delegate.getProvider(), delegate.getType()) { };
        keyStore.load(null, null);
        return keyStore;
    }

    private static final class CountingKeyStoreSpi extends KeyStoreSpi {

        private final KeyStore delegate;
        private final AtomicInteger aliasesCount;

        CountingKeyStoreSpi(KeyStore delegate, AtomicInteger aliasesCount) {
            this.delegate = delegate;
            this.aliasesCount = aliasesCount;
        }

        @Override
        public Enumeration<String> engineAliases() {
            aliasesCount.incrementAndGet();
            try {
                return delegate.aliases();
            } catch (KeyStoreException e) {
                return Collections.emptyEnumeration();
            }
        }

        @Override
        public Key engineGetKey(String alias, char[] password) {
            try {
                return delegate.getKey(alias, password);
            } catch (Exception e) {
                return null;
            }
        }

        @Override
        public Certificate[] engineGetCertificateChain(String alias) {
            try {
                return delegate.getCertificateChain(alias);
            } catch (KeyStoreException e) {
                return null;
            }
        }

        @Override
        public Certificate engineGetCertificate(String alias) {
            try {
                return delegate.getCertificate(alias);
            } catch (KeyStoreException e) {
                return null;
            }
        }

        @Override
        public Date engineGetCreationDate(String alias) {
            try {
                return delegate.getCreationDate(alias);
            } catch (KeyStoreException e) {
                return null;
            }
        }

        @Override
        public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
            throws KeyStoreException {
            delegate.setKeyEntry(alias, key, password, chain);
        }

        @Override
        public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
            delegate.setKeyEntry(alias, key, chain);
        }

        @Override
        public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
            delegate.setCertificateEntry(alias, cert);
        }

        @Override
        public void engineDeleteEntry(String alias) throws KeyStoreException {
            delegate.deleteEntry(alias);
        }

        @Override
        public boolean engineContainsAlias(String alias) {
            try {
                return delegate.containsAlias(alias);
            } catch (KeyStoreException e) {
                return false;
            }
        }

        @Override
        public int engineSize() {
            try {
                return delegate.size();
            } catch (KeyStoreException e) {
                return 0;
            }
        }

        @Override
        public boolean engineIsKeyEntry(String alias) {
            try {
                return delegate.isKeyEntry(alias);
            } catch (KeyStoreException e) {
                return false;
            }
        }

        @Override
        public boolean engineIsCertificateEntry(String alias) {
            try {
                return delegate.isCertificateEntry(alias);
            } catch (KeyStoreException e) {
                return false;
            }
        }

        @Override
        public String engineGetCertificateAlias(Certificate cert) {
            try {
                return delegate.getCertificateAlias(cert);
            } catch (KeyStoreException e) {
                return null;
            }
        }

        @Override
        public void engineStore(OutputStream stream, char[] password) {
            throw new UnsupportedOperationException();
        }

        @Override
        public void engineLoad(InputStream stream, char[] password) {
            // The delegate is already loaded
        }
    }
}
