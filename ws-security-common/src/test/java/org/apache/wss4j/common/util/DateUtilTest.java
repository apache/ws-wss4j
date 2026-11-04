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

import java.time.Instant;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

public class DateUtilTest {

    @Test
    public void testTimestampReplayExpiryNoCreated() {
        Instant expires = Instant.now().plusSeconds(100L);
        assertEquals(expires, DateUtil.getTimestampReplayExpiry(null, expires, 300));
        assertNull(DateUtil.getTimestampReplayExpiry(null, null, 300));
    }

    @Test
    public void testTimestampReplayExpiryNoExpires() {
        Instant created = Instant.now();
        assertEquals(created.plusSeconds(300L), DateUtil.getTimestampReplayExpiry(created, null, 300));
    }

    // A Created value in the future is accepted until Created + TTL, which is after now + TTL
    @Test
    public void testTimestampReplayExpiryFutureCreated() {
        Instant created = Instant.now().plusSeconds(60L);
        assertEquals(created.plusSeconds(300L), DateUtil.getTimestampReplayExpiry(created, null, 300));
    }

    // An Expires value before Created + TTL is not enforced by a non-strict Timestamp check
    @Test
    public void testTimestampReplayExpiryEarlyExpires() {
        Instant created = Instant.now();
        Instant expires = created.plusSeconds(1L);
        assertEquals(created.plusSeconds(300L), DateUtil.getTimestampReplayExpiry(created, expires, 300));
    }

    @Test
    public void testTimestampReplayExpiryLateExpires() {
        Instant created = Instant.now();
        Instant expires = created.plusSeconds(600L);
        assertEquals(expires, DateUtil.getTimestampReplayExpiry(created, expires, 300));
    }
}
