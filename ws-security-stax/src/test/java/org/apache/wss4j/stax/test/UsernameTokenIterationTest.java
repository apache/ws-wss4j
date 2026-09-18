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
package org.apache.wss4j.stax.test;

import java.time.Duration;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.DateUtil;
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.stax.ext.WSInboundSecurityContext;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.wss4j.stax.impl.InboundWSSecurityContextImpl;
import org.apache.wss4j.stax.impl.securityToken.UsernameSecurityTokenImpl;
import org.apache.wss4j.stax.securityToken.WSSecurityTokenConstants;
import org.apache.wss4j.stax.setup.WSSec;
import org.apache.xml.security.stax.impl.util.IDGenerator;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/**
 * Tests that the wsse11:Iteration value of an inbound UsernameToken is bounded before it is used
 * to derive a key. The value is attacker-controlled message content and the derivation performs
 * one SHA-1 round per iteration, so without a bound a ~1 KB request buys an arbitrary amount of
 * CPU time on the receiver. The DOM engine has always rejected out-of-range values while parsing
 * the token; these tests cover the streaming equivalent.
 */
public class UsernameTokenIterationTest {

    private static final byte[] SALT = new byte[16];

    @BeforeAll
    public static void setUp() throws Exception {
        WSSec.init();
    }

    private UsernameSecurityTokenImpl createToken(Long iteration, WSInboundSecurityContext context) {
        String created =
            DateUtil.getDateTimeFormatter(true).format(ZonedDateTime.now(ZoneOffset.UTC));
        return new UsernameSecurityTokenImpl(
            WSSConstants.UsernameTokenPasswordType.PASSWORD_NONE,
            "username", "password", created, null, SALT, iteration,
            context, IDGenerator.generateID(null),
            WSSecurityTokenConstants.KEYIDENTIFIER_SECURITY_TOKEN_DIRECT_REFERENCE);
    }

    @Test
    public void testIterationAboveMaximumIsRejected() {
        UsernameSecurityTokenImpl token =
            createToken((long)UsernameTokenUtil.MAX_ITERATION + 1, null);

        WSSecurityException exception =
            assertThrows(WSSecurityException.class, token::generateDerivedKey);
        assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, exception.getErrorCode());
    }

    /**
     * The amplification case: a single small request asking for ~2^31 SHA-1 rounds. The bound has
     * to reject it rather than perform the work, so the derivation must return promptly. The
     * timeout is generous - the guarded path fails in microseconds, whereas actually running
     * Integer.MAX_VALUE rounds takes minutes - so this only fails if the bound is gone.
     */
    @Test
    public void testHugeIterationIsRejectedWithoutDoingTheWork() {
        UsernameSecurityTokenImpl token = createToken((long)Integer.MAX_VALUE, null);

        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> {
            WSSecurityException exception =
                assertThrows(WSSecurityException.class, token::generateDerivedKey);
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN,
                         exception.getErrorCode());
        });
    }

    /**
     * An Iteration larger than Integer.MAX_VALUE must be rejected outright. It must not narrow to
     * a negative or zero int and thereby be silently accepted as the default iteration count -
     * which is what happens if the bound is applied after the Long has been converted to an int.
     */
    @Test
    public void testIterationAboveIntegerRangeIsRejected() {
        for (long iteration : new long[] {Integer.MAX_VALUE + 1L, 1L << 32, Long.MAX_VALUE}) {
            UsernameSecurityTokenImpl token = createToken(iteration, null);

            WSSecurityException exception =
                assertThrows(WSSecurityException.class, token::generateDerivedKey,
                             "Iteration " + iteration + " should have been rejected");
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN,
                         exception.getErrorCode());
        }
    }

    @Test
    public void testNegativeIterationIsRejected() {
        UsernameSecurityTokenImpl token = createToken(-1L, null);

        WSSecurityException exception =
            assertThrows(WSSecurityException.class, token::generateDerivedKey);
        assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, exception.getErrorCode());
    }

    @Test
    public void testMaximumIterationIsAccepted() throws Exception {
        UsernameSecurityTokenImpl token =
            createToken((long)UsernameTokenUtil.MAX_ITERATION, null);

        assertEquals(20, token.generateDerivedKey().length);
    }

    @Test
    public void testDefaultIterationIsAccepted() throws Exception {
        UsernameSecurityTokenImpl token = createToken((long)UsernameTokenUtil.DEFAULT_ITERATION, null);

        assertEquals(20, token.generateDerivedKey().length);
    }

    /**
     * The bound is an engine-level limit, not a BSP rule, so turning BSP enforcement off must not
     * re-open it.
     */
    @Test
    public void testBoundIsEnforcedWithBSPEnforcementDisabled() {
        InboundWSSecurityContextImpl securityContext = new InboundWSSecurityContextImpl();
        securityContext.setDisableBSPEnforcement(true);

        UsernameSecurityTokenImpl token = createToken((long)Integer.MAX_VALUE, securityContext);

        assertTimeoutPreemptively(Duration.ofSeconds(60), () -> {
            WSSecurityException exception =
                assertThrows(WSSecurityException.class, token::generateDerivedKey);
            assertEquals(WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN,
                         exception.getErrorCode());
        });
    }
}
