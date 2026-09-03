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

package org.apache.wss4j.common.derivedKey;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class DerivedKeyUtilsTest {

    private static final byte[] SECRET = "0123456789abcdef".getBytes(java.nio.charset.StandardCharsets.UTF_8);
    private static final byte[] NONCE = "abcdefghijklmnop".getBytes(java.nio.charset.StandardCharsets.UTF_8);

    @Test
    void rejectsPositiveDerivedKeyLengthsBelowMinimum() {
        WSSecurityException exception = Assertions.assertThrows(WSSecurityException.class,
            () -> DerivedKeyUtils.deriveKey(
                ConversationConstants.DerivationAlgorithm.P_SHA_1,
                null,
                DerivedKeyUtils.MINIMUM_DERIVED_KEY_LENGTH - 1,
                SECRET,
                NONCE,
                0));

        Assertions.assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, exception.getErrorCode());
    }

    @Test
    void acceptsMinimumDerivedKeyLength() throws Exception {
        byte[] key = DerivedKeyUtils.deriveKey(
            ConversationConstants.DerivationAlgorithm.P_SHA_1,
            null,
            DerivedKeyUtils.MINIMUM_DERIVED_KEY_LENGTH,
            SECRET,
            NONCE,
            0);

        Assertions.assertEquals(DerivedKeyUtils.MINIMUM_DERIVED_KEY_LENGTH, key.length);
    }

    @Test
    void preservesDefaultDerivedKeyLength() throws Exception {
        byte[] key = DerivedKeyUtils.deriveKey(
            ConversationConstants.DerivationAlgorithm.P_SHA_1,
            null,
            0,
            SECRET,
            NONCE,
            0);

        Assertions.assertEquals(32, key.length);
    }
}
