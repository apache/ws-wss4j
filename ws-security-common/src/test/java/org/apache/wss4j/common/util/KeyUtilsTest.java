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

import javax.crypto.SecretKey;

import org.apache.wss4j.common.WSS4JConstants;
import org.apache.wss4j.common.crypto.WSProviderConfig;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.xml.security.signature.XMLSignature;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

class KeyUtilsTest {

    @BeforeAll
    static void setUp() {
        WSProviderConfig.setXmlSecIgnoreLineBreak();
    }

    @Test
    void rejectsOversizedKeyForFixedLengthEncryptionAlgorithm() {
        byte[] rawKey = new byte[32];

        WSSecurityException exception = Assertions.assertThrows(WSSecurityException.class,
            () -> KeyUtils.prepareSecretKey(WSS4JConstants.AES_128, rawKey));

        Assertions.assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, exception.getErrorCode());
    }

    @Test
    void rejectsUndersizedKeyForFixedLengthEncryptionAlgorithm() {
        byte[] rawKey = new byte[8];

        WSSecurityException exception = Assertions.assertThrows(WSSecurityException.class,
            () -> KeyUtils.prepareSecretKey(WSS4JConstants.AES_128, rawKey));

        Assertions.assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, exception.getErrorCode());
    }

    @Test
    void acceptsExactLengthKeyForFixedLengthEncryptionAlgorithm() throws Exception {
        byte[] rawKey = new byte[16];

        SecretKey secretKey = KeyUtils.prepareSecretKey(WSS4JConstants.AES_128, rawKey);

        Assertions.assertArrayEquals(rawKey, secretKey.getEncoded());
    }

    @Test
    void rejectsOversizedKeyForGCMAlgorithm() {
        byte[] rawKey = new byte[32];

        WSSecurityException exception = Assertions.assertThrows(WSSecurityException.class,
            () -> KeyUtils.prepareSecretKey(WSS4JConstants.AES_128_GCM, rawKey));

        Assertions.assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, exception.getErrorCode());
    }

    @Test
    void rejectsUndersizedKeyForGCMAlgorithm() {
        byte[] rawKey = new byte[8];

        WSSecurityException exception = Assertions.assertThrows(WSSecurityException.class,
            () -> KeyUtils.prepareSecretKey(WSS4JConstants.AES_128_GCM, rawKey));

        Assertions.assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, exception.getErrorCode());
    }

    @Test
    void acceptsExactLengthKeyForGCMAlgorithm() throws Exception {
        byte[] rawKey = new byte[16];

        SecretKey secretKey = KeyUtils.prepareSecretKey(WSS4JConstants.AES_128_GCM, rawKey);

        Assertions.assertArrayEquals(rawKey, secretKey.getEncoded());
    }

    @Test
    void allowsVariableLengthKeyForHMAC() throws Exception {
        byte[] rawKey64 = new byte[64];
        byte[] rawKey20 = new byte[20];

        SecretKey secretKey64 = KeyUtils.prepareSecretKey(XMLSignature.ALGO_ID_MAC_HMAC_SHA256, rawKey64);
        SecretKey secretKey20 = KeyUtils.prepareSecretKey(XMLSignature.ALGO_ID_MAC_HMAC_SHA256, rawKey20);

        Assertions.assertArrayEquals(rawKey64, secretKey64.getEncoded());
        Assertions.assertArrayEquals(rawKey20, secretKey20.getEncoded());
    }

    @Test
    void rejectsOversizedKeyForHMAC() {
        byte[] rawKey = new byte[1025];

        WSSecurityException exception = Assertions.assertThrows(WSSecurityException.class,
            () -> KeyUtils.prepareSecretKey(XMLSignature.ALGO_ID_MAC_HMAC_SHA256, rawKey));

        Assertions.assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, exception.getErrorCode());
    }

    @Test
    void rejectsNullRawKey() {
        WSSecurityException exception = Assertions.assertThrows(WSSecurityException.class,
            () -> KeyUtils.prepareSecretKey(WSS4JConstants.AES_128, null));

        Assertions.assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, exception.getErrorCode());
    }
}