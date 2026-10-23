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

import org.apache.wss4j.common.ext.WSSecurityException;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class UsernameTokenUtilTest {

    @Test
    void canonicalNonceIgnoresEncodingDifferences() throws Exception {
        assertEquals("AAECAwQFBgcICQoLDA0ODw==", UsernameTokenUtil.getCanonicalNonce("AAECAwQFBgcICQoLDA0ODw=="));
        assertEquals("AAECAwQFBgcICQoLDA0ODw==", UsernameTokenUtil.getCanonicalNonce("AAEC\nAwQFBgcICQoLDA0ODw=="));
    }

    /**
     * An empty Nonce cannot be cached, so it must be rejected rather than silently escaping replay
     * detection, whether the Nonce element has no text at all or only whitespace.
     */
    @Test
    void rejectsEmptyNonce() {
        for (String nonce : new String[] {null, "", "   ", "\n"}) {
            WSSecurityException ex =
                assertThrows(WSSecurityException.class, () -> UsernameTokenUtil.getCanonicalNonce(nonce));
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, ex.getErrorCode());
            assertTrue(ex.getMessage().contains("The Nonce is empty"), ex.getMessage());
        }
    }
}
