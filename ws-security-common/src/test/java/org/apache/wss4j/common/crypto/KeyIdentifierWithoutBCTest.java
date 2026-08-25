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

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Verifies X.509 SKI and AKI extraction while Bouncy Castle is hidden. */
public class KeyIdentifierWithoutBCTest {

    private static final String PROBE_CLASS = KeyIdentifierWithoutBCProbe.class.getName();

    @Test
    public void testKeyIdentifierExtractionWithoutBC() throws Exception {
        URL[] urls = {
            new File("target/classes").toURI().toURL(),
            new File("target/test-classes").toURI().toURL()
        };
        try (URLClassLoader classLoader = new URLClassLoader(urls, getClass().getClassLoader()) {
            @Override
            protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
                if (name.startsWith("org.bouncycastle.")) {
                    throw new ClassNotFoundException("Bouncy Castle deliberately hidden from test class loader");
                }

                if (name.equals(BouncyCastleUtils.class.getName())
                    || name.equals(DERDecoder.class.getName())
                    || name.equals(PROBE_CLASS)) {
                    synchronized (getClassLoadingLock(name)) {
                        Class<?> loadedClass = findLoadedClass(name);
                        if (loadedClass == null) {
                            loadedClass = findClass(name);
                        }
                        if (resolve) {
                            resolveClass(loadedClass);
                        }
                        return loadedClass;
                    }
                }

                return super.loadClass(name, resolve);
            }
        }) {
            assertThrows(ClassNotFoundException.class,
                () -> classLoader.loadClass("org.bouncycastle.asn1.ASN1Primitive"));

            Class<?> probeClass = Class.forName(PROBE_CLASS, true, classLoader);
            assertTrue((Boolean)probeClass.getMethod("verify").invoke(null));
        }
    }
}
