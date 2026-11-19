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

package org.apache.wss4j.common.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for the URL scheme allowlist enforced by
 * {@link Loader#loadInputStream(ClassLoader, String)}. Refused schemes fail before any
 * connection is attempted, so no test here touches the network.
 */
class LoaderTest {

    @TempDir
    Path tempDir;

    @BeforeAll
    static void disableJarCache() {
        // see https://bugs.openjdk.org/browse/JDK-8239054 and https://github.com/junit-team/junit-framework/issues/2811
        URLConnection.setDefaultUseCaches("jar", false);
    }

    @AfterEach
    void clearAllowedSchemesProperty() {
        System.clearProperty(Loader.ALLOWED_URL_SCHEMES_PROPERTY);
    }

    @Test
    void fileUrlIsAllowedByDefault() throws Exception {
        Path file = Files.write(tempDir.resolve("resource.txt"),
            "file-content".getBytes(StandardCharsets.UTF_8));
        try (InputStream is =
            Loader.loadInputStream(getClass().getClassLoader(), file.toUri().toURL().toString())) {
            assertEquals("file-content", read(is));
        }
    }

    @Test
    void jarFileUrlIsAllowedByDefault() throws Exception {
        Path jar = createJar("entry.txt", "jar-content");
        String resource = "jar:" + jar.toUri().toURL() + "!/entry.txt";
        try (InputStream is = Loader.loadInputStream(getClass().getClassLoader(), resource)) {
            assertEquals("jar-content", read(is));
        }
    }

    @Test
    void httpUrlIsRefusedByDefault() {
        assertThrows(WSSecurityException.class,
            () -> Loader.loadInputStream(getClass().getClassLoader(),
                "http://localhost:1/keystore.jks"));
    }

    @Test
    void httpUrlIsRefusedRegardlessOfCase() {
        assertThrows(WSSecurityException.class,
            () -> Loader.loadInputStream(getClass().getClassLoader(),
                "HTTP://localhost:1/keystore.jks"));
    }

    @Test
    void jarHttpUrlIsRefusedByDefault() {
        // The nested URL is what a JarURLConnection would fetch - it must be validated too
        assertThrows(WSSecurityException.class,
            () -> Loader.loadInputStream(getClass().getClassLoader(),
                "jar:http://localhost:1/evil.jar!/entry.txt"));
    }

    @Test
    void doublyNestedJarHttpUrlIsRefused() {
        assertThrows(WSSecurityException.class,
            () -> Loader.loadInputStream(getClass().getClassLoader(),
                "jar:jar:http://localhost:1/evil.jar!/inner.jar!/entry.txt"));
    }

    @Test
    void emptyAllowedSchemesPropertyRefusesAllUrls() throws Exception {
        System.setProperty(Loader.ALLOWED_URL_SCHEMES_PROPERTY, "");
        Path file = Files.write(tempDir.resolve("resource.txt"),
            "file-content".getBytes(StandardCharsets.UTF_8));

        // Even a file: URL is refused when the allowlist is empty...
        assertThrows(WSSecurityException.class,
            () -> Loader.loadInputStream(getClass().getClassLoader(),
                file.toUri().toURL().toString()));

        // ...but a plain file system path is unaffected (it is not URL loading)
        try (InputStream is = Loader.loadInputStream(getClass().getClassLoader(), file.toString())) {
            assertEquals("file-content", read(is));
        }
    }

    private Path createJar(String entryName, String content) throws IOException {
        Path jar = tempDir.resolve("resource.jar");
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(jar))) {
            jos.putNextEntry(new JarEntry(entryName));
            jos.write(content.getBytes(StandardCharsets.UTF_8));
            jos.closeEntry();
        }
        return jar;
    }

    private static String read(InputStream is) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buffer = new byte[256];
        int n = is.read(buffer);
        while (n != -1) {
            bos.write(buffer, 0, n);
            n = is.read(buffer);
        }
        return new String(bos.toByteArray(), StandardCharsets.UTF_8);
    }
}
