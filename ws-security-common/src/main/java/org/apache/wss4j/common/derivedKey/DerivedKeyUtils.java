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

import java.nio.charset.StandardCharsets;

import org.apache.wss4j.common.ext.WSSecurityException;

public final class DerivedKeyUtils {

    /**
     * The minimum length in bytes of a derived key (128 bits). The wsc:Length value is
     * attacker-controlled message content: a shorter derived key (e.g. Length=1) reduces
     * an HMAC signature key to a trivially brute-forceable keyspace. No standard
     * WS-SecurityPolicy algorithm suite derives keys shorter than 128 bits, so this is
     * enforced as a hard engine-level floor, independent of any configured AlgorithmSuite.
     */
    public static final int MINIMUM_DERIVED_KEY_LENGTH = 16;

    private DerivedKeyUtils() {
        // complete
    }

    /**
     * Derive a key from this DerivedKeyToken instance
     *
     * @param length
     * @param secret
     * @throws org.apache.wss4j.stax.wss.ext.WSSecurityException
     *
     */
    public static byte[] deriveKey(String algorithm, String label, int length, byte[] secret, byte[] nonce, int offset)
        throws WSSecurityException {
        DerivationAlgorithm algo = AlgoFactory.getInstance(algorithm);
        byte[] labelBytes;
        if (label == null || label.length() == 0) {
            String defaultLabel = ConversationConstants.DEFAULT_LABEL + ConversationConstants.DEFAULT_LABEL;
            labelBytes = defaultLabel.getBytes(StandardCharsets.UTF_8);
        } else {
            labelBytes = label.getBytes(StandardCharsets.UTF_8);
        }

        byte[] seed = new byte[labelBytes.length + nonce.length];
        System.arraycopy(labelBytes, 0, seed, 0, labelBytes.length);
        System.arraycopy(nonce, 0, seed, labelBytes.length, nonce.length);

        long keyLength = length;
        if (keyLength <= 0) {
            keyLength = 32L;
        }
        if (keyLength < MINIMUM_DERIVED_KEY_LENGTH) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY,
                "unsupportedKeyId",
                new Object[] {"Requested derived key length of " + keyLength
                    + " byte(s) is less than the minimum allowed ("
                    + MINIMUM_DERIVED_KEY_LENGTH + " bytes)"});
        }
        return algo.createKey(secret, seed, offset, keyLength);
    }
}
