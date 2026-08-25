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
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import org.apache.wss4j.common.util.Loader;

/** Invoked through an isolated class loader by {@link KeyIdentifierWithoutBCTest}. */
public final class KeyIdentifierWithoutBCProbe {

    private KeyIdentifierWithoutBCProbe() {
        // complete
    }

    public static boolean verify() throws Exception {
        X509Certificate cert = loadCertificate("keys/wss40.jks", "security", "wss40");
        X509Certificate caCert = loadCertificate("keys/wss40CA.jks", "security", "wss40CA");
        return Arrays.equals(
            BouncyCastleUtils.getAuthorityKeyIdentifierBytes(cert),
            BouncyCastleUtils.getSubjectKeyIdentifierBytes(caCert)
        );
    }

    private static X509Certificate loadCertificate(String path, String password, String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        ClassLoader loader = Loader.getClassLoader(KeyIdentifierWithoutBCProbe.class);
        try (InputStream input = Merlin.loadInputStream(loader, path)) {
            keyStore.load(input, password.toCharArray());
        }
        return (X509Certificate)keyStore.getCertificate(alias);
    }
}
