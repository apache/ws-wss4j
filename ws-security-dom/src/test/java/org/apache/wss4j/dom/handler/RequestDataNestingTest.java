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

package org.apache.wss4j.dom.handler;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;

/**
 * A processor that uncovers a token inside the one it is processing hands it to another processor,
 * which may do the same again, so how deep a message may nest tokens is how much of the receiver's
 * stack the sender gets to spend. RequestData carries that bound for the message.
 */
public class RequestDataNestingTest {

    private static final int LIMIT = RequestData.MAXIMUM_PROCESSOR_NESTING_DEPTH;

    @BeforeAll
    public static void setUp() {
        // Without this the message bundle is not loaded and every getMessage() returns the
        // library's "you must initialize" text instead of the message that was raised.
        WSSConfig.init();
    }

    /**
     * The bound has to leave room for the deepest nesting a real message performs. An
     * EncryptedAssertion reaches 2, and re-encrypting an already encrypted assertion reaches 3.
     */
    @Test
    public void testLimitAccommodatesRealMessages() {
        assertEquals(true, LIMIT >= 3,
            "the bound must not reject an encrypted, encrypted assertion: " + LIMIT);
    }

    @Test
    public void testNestingUpToTheLimitIsAllowed() {
        RequestData data = new RequestData();

        assertDoesNotThrow(() -> {
            for (int i = 0; i < LIMIT; i++) {
                data.enterNestedToken();
            }
        });
    }

    @Test
    public void testNestingBeyondTheLimitIsRejected() throws Exception {
        RequestData data = new RequestData();
        for (int i = 0; i < LIMIT; i++) {
            data.enterNestedToken();
        }

        WSSecurityException exception =
            assertThrows(WSSecurityException.class, data::enterNestedToken);
        assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY, exception.getErrorCode());
    }

    /**
     * Unwinding restores the budget. Were a caller to leave the depth raised - by not pairing
     * enterNestedToken with a finally block - a message would grow harder to process the further
     * through it the engine got.
     */
    @Test
    public void testLeavingATokenRestoresTheBudget() throws Exception {
        RequestData data = new RequestData();
        for (int i = 0; i < LIMIT; i++) {
            data.enterNestedToken();
        }
        for (int i = 0; i < LIMIT; i++) {
            data.exitNestedToken();
        }

        assertDoesNotThrow(() -> {
            for (int i = 0; i < LIMIT; i++) {
                data.enterNestedToken();
            }
        });
    }

    /**
     * Tokens that sit side by side are entered and left in turn rather than nested, so any number
     * of them may appear in one message. The bound constrains depth, not count.
     */
    @Test
    public void testSiblingTokensDoNotAccumulate() {
        RequestData data = new RequestData();

        assertDoesNotThrow(() -> {
            for (int sibling = 0; sibling < LIMIT * 10; sibling++) {
                data.enterNestedToken();
                data.exitNestedToken();
            }
        });
    }

    /**
     * The exception has to name the limit: "nested too deeply" without a number tells an operator
     * facing a rejected message nothing about whether it is their message or their configuration.
     */
    @Test
    public void testTheRejectionNamesTheLimit() throws Exception {
        RequestData data = new RequestData();
        for (int i = 0; i < LIMIT; i++) {
            data.enterNestedToken();
        }

        WSSecurityException exception =
            assertThrows(WSSecurityException.class, data::enterNestedToken);
        assertEquals(true, exception.getMessage().contains(String.valueOf(LIMIT)),
            "the rejection should say what the limit is: " + exception.getMessage());
    }
}
