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
}
