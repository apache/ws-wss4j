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

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.JDKTestUtils;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;


import static org.junit.jupiter.api.Assertions.*;

class AlgorithmSuiteValidatorTest {
    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(AlgorithmSuiteValidatorTest.class);

    @BeforeAll
    public static void setUp() throws Exception {
        WSProviderConfig.init();
    }

    @AfterEach
    public void cleanTest() {
        JDKTestUtils.unregisterAuxiliaryProvider();
    }

    @ParameterizedTest
    @CsvSource({"X25519, 160, 512, false",
            "X448, 160, 512, false",
            "ED25519, 160, 512, false",
            "ED448, 160, 512, false",
            "ED25519, 300, 512, true",
            "X25519, 300, 512, true",
            "X448, 160, 300, true",
            "ED448, 160, 300, true",
    })
    void checkAsymmetricKeyLength(String keyAlgorithm, int iMinECKelLength, int iMaxECKelLength, boolean fail) throws NoSuchAlgorithmException {
        if (!JDKTestUtils.isAlgorithmSupportedByJDK(keyAlgorithm)) {
            LOG.info("Add AuxiliaryProvider to execute test with algorithm [{}]", keyAlgorithm);
            JDKTestUtils.registerAuxiliaryProvider();
        }
        AlgorithmSuite algorithmSuite = new AlgorithmSuite();
        algorithmSuite.setMinimumEllipticCurveKeyLength(iMinECKelLength);
        algorithmSuite.setMaximumEllipticCurveKeyLength(iMaxECKelLength);

        AlgorithmSuiteValidator validator = new AlgorithmSuiteValidator(algorithmSuite);
        KeyPairGenerator keygen = KeyPairGenerator.getInstance(keyAlgorithm);
        KeyPair keyPair = keygen.generateKeyPair();
        if (fail) {
            WSSecurityException result = Assertions.assertThrows(WSSecurityException.class,
                    () -> validator.checkAsymmetricKeyLength(keyPair.getPublic()));
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, result.getErrorCode());
        }
        else {
            Assertions.assertDoesNotThrow(
                    () -> validator.checkAsymmetricKeyLength(keyPair.getPublic()));
        }
    }

    /**
     * The derived key length checks take a length in bytes - the denomination of the wsc:Length
     * element of a DerivedKeyToken - and compare it against an AlgorithmSuite requirement stated
     * in bits. Pinning the units here matters: the checks used to divide the byte value by 8
     * instead of multiplying, so they never matched any real length, and they only logged a
     * warning instead of failing, which hid it.
     */
    @ParameterizedTest
    @CsvSource({
        // requirement (bits), wsc:Length (bytes), should be rejected
        "192, 24, false",   // Basic256 / Basic192 / TripleDes signature key derivation
        "128, 16, false",   // Basic128 signature key derivation
        "192, 20, true",    // what WSSecDKSign emits by default for HMAC-SHA1 (160 bits)
        "128, 20, true",
        "192, 32, true",    // the DerivedKeyToken default when wsc:Length is absent (256 bits)
        "128, 32, true",
        "192, 1, true",     // a deliberately short key
        "192, 192, true",   // the requirement misread as bytes
    })
    void checkSignatureDerivedKeyLength(int requiredBits, int suppliedBytes, boolean fail) {
        AlgorithmSuite algorithmSuite = new AlgorithmSuite();
        algorithmSuite.setSignatureDerivedKeyLength(requiredBits);
        AlgorithmSuiteValidator validator = new AlgorithmSuiteValidator(algorithmSuite);

        if (fail) {
            WSSecurityException result = Assertions.assertThrows(WSSecurityException.class,
                    () -> validator.checkSignatureDerivedKeyLength(suppliedBytes));
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, result.getErrorCode());
        } else {
            Assertions.assertDoesNotThrow(
                    () -> validator.checkSignatureDerivedKeyLength(suppliedBytes));
        }
    }

    @ParameterizedTest
    @CsvSource({
        // requirement (bits), wsc:Length (bytes), should be rejected
        "256, 32, false",   // Basic256 encryption key derivation
        "192, 24, false",   // Basic192 / TripleDes encryption key derivation
        "128, 16, false",   // Basic128 encryption key derivation
        "256, 16, true",
        "128, 32, true",
        "128, 128, true",   // the requirement misread as bytes
    })
    void checkEncryptionDerivedKeyLength(int requiredBits, int suppliedBytes, boolean fail) {
        AlgorithmSuite algorithmSuite = new AlgorithmSuite();
        algorithmSuite.setEncryptionDerivedKeyLength(requiredBits);
        AlgorithmSuiteValidator validator = new AlgorithmSuiteValidator(algorithmSuite);

        if (fail) {
            WSSecurityException result = Assertions.assertThrows(WSSecurityException.class,
                    () -> validator.checkEncryptionDerivedKeyLength(suppliedBytes));
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, result.getErrorCode());
        } else {
            Assertions.assertDoesNotThrow(
                    () -> validator.checkEncryptionDerivedKeyLength(suppliedBytes));
        }
    }

    /**
     * An AlgorithmSuite that states no derived key length requirement must not impose one. This is
     * the WSHandler path: decodeAlgorithmSuite never populates these two fields, so a handler-driven
     * deployment has no derived key length requirement at all.
     */
    @Test
    void derivedKeyLengthUnsetImposesNoRequirement() {
        AlgorithmSuiteValidator validator = new AlgorithmSuiteValidator(new AlgorithmSuite());

        Assertions.assertDoesNotThrow(() -> validator.checkSignatureDerivedKeyLength(20));
        Assertions.assertDoesNotThrow(() -> validator.checkEncryptionDerivedKeyLength(20));
    }
}
