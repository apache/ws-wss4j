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

package org.apache.wss4j.common.cache;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Some unit tests for the EHCacheExpiry implementation
 */
public class EHCacheExpiryTest {

    @Test
    public void testNoExpirySpecified() {
        EHCacheExpiry cacheExpiry = new EHCacheExpiry();

        Duration expiryForCreation =
                cacheExpiry.getExpiryForCreation("xyz",
                        new EHCacheValue("xyz", null));
        assertNotNull(expiryForCreation);

        assertEquals(EHCacheExpiry.DEFAULT_TTL, expiryForCreation.getSeconds());
    }

    @Test
    public void testExpirySpecified() {
        EHCacheExpiry cacheExpiry = new EHCacheExpiry();

        Duration expiryForCreation =
                cacheExpiry.getExpiryForCreation("xyz",
                        new EHCacheValue("xyz", Instant.now().plusSeconds(30L)));
        assertNotNull(expiryForCreation);

        // Some loose boundary checking to allow for slow tests
        assertTrue(expiryForCreation.getSeconds() <= 30L);
        assertTrue(expiryForCreation.getSeconds() > 30L - 5L);
    }

    @Test
    public void testExpirySpecified2() {
        EHCacheExpiry cacheExpiry = new EHCacheExpiry();

        Duration expiryForCreation =
                cacheExpiry.getExpiryForCreation("xyz",
                        new EHCacheValue("xyz", Instant.now().plus(6L, ChronoUnit.HOURS)));
        assertNotNull(expiryForCreation);

        // Some loose boundary checking to allow for slow tests
        assertTrue(expiryForCreation.getSeconds() <= 6 * 60 * 60L);
        assertTrue(expiryForCreation.getSeconds() > 6 * 60 * 60L - 5L);
    }

    @Test
    public void testNegativeExpirySpecified() {
        EHCacheExpiry cacheExpiry = new EHCacheExpiry();

        Duration expiryForCreation =
                cacheExpiry.getExpiryForCreation("xyz",
                        new EHCacheValue("xyz", Instant.now().minusSeconds(30L)));
        assertNotNull(expiryForCreation);

        assertEquals(EHCacheExpiry.DEFAULT_TTL, expiryForCreation.getSeconds());
    }

    @Test
    public void testHugeExpirySpecified() {
        EHCacheExpiry cacheExpiry = new EHCacheExpiry();

        Duration expiryForCreation =
                cacheExpiry.getExpiryForCreation("xyz",
                        new EHCacheValue("xyz", Instant.now().plus(14, ChronoUnit.HOURS)));
        assertNotNull(expiryForCreation);

        assertEquals(EHCacheExpiry.DEFAULT_TTL, expiryForCreation.getSeconds());
    }
}