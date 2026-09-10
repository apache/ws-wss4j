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

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * This is a test for the PasswordEncryptor interface
 */
public class PasswordEncryptorTest {

    @Test
    public void testStrongJasyptPasswordEncryptor() throws Exception {

        PasswordEncryptor passwordEncryptor =
            new JasyptPasswordEncryptor("master-password");
        String encryptedPassword = passwordEncryptor.encrypt("password");
        assertNotEquals(encryptedPassword, "password");
        String decryptedPassword = passwordEncryptor.decrypt(encryptedPassword);
        assertEquals(decryptedPassword, "password");
    }

    @Test
    public void testJasyptDefaultAlgorithm() throws Exception {
        // The strong algorithm is the default on both the FIPS and non-FIPS paths, and
        // round-trips without needing any pre-encrypted fixture
        assertEquals(JasyptPasswordEncryptor.DEFAULT_ALGORITHM, "PBEWithHmacSHA512AndAES_256");

        PasswordEncryptor passwordEncryptor =
            new JasyptPasswordEncryptor("master-password");
        String encryptedPassword = passwordEncryptor.encrypt("password");
        assertNotEquals(encryptedPassword, "password");
        String decryptedPassword = passwordEncryptor.decrypt(encryptedPassword);
        assertEquals(decryptedPassword, "password");
    }

    @Test
    public void testJasyptLegacyDefaultAlgorithmOptIn() throws Exception {
        // A value encrypted under the previous default algorithm...
        PasswordEncryptor legacyEncryptor =
            new JasyptPasswordEncryptor("master-password",
                                        JasyptPasswordEncryptor.LEGACY_DEFAULT_ALGORITHM);
        String legacyEncryptedPassword = legacyEncryptor.encrypt("password");
        assertNotEquals(legacyEncryptedPassword, "password");

        // ...can still be decrypted with the default constructor by opting in via the system
        // property. The class is already loaded at this point, so this also checks that the
        // property is honored at construction time rather than at class-loading time.
        try {
            System.setProperty(JasyptPasswordEncryptor.USE_LEGACY_DEFAULT_ALGORITHM_PROPERTY, "true");
            PasswordEncryptor passwordEncryptor =
                new JasyptPasswordEncryptor("master-password");
            String decryptedPassword = passwordEncryptor.decrypt(legacyEncryptedPassword);
            assertEquals(decryptedPassword, "password");
        } finally {
            System.clearProperty(JasyptPasswordEncryptor.USE_LEGACY_DEFAULT_ALGORITHM_PROPERTY);
        }
    }

}