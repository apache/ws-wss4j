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

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Random;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Some unit tests for the ReplayCache implementations
 */
public class ReplayCacheTest {

    @Test
    public void testMemoryReplayCache() throws InterruptedException, IOException {
        ReplayCache replayCache = new MemoryReplayCache();

        testReplayCacheInstance(replayCache);

        replayCache.close();
    }

    @Test
    public void testEhCacheReplayCache() throws Exception {
        ReplayCache replayCache = new EHCacheReplayCache("xyz", (URL)null, getDiskstorePath("abc"));

        testReplayCacheInstance(replayCache);

        replayCache.close();
    }

    @Test
    public void testEhCacheDifferentCaches() throws Exception {
        ReplayCache replayCache = new EHCacheReplayCache("abc", (URL)null, getDiskstorePath("abc"));

        ReplayCache replayCache2 = new EHCacheReplayCache("cba", (URL)null, getDiskstorePath("cba"));

        String id = UUID.randomUUID().toString();
        replayCache.add(id);
        assertTrue(replayCache.contains(id));
        assertFalse(replayCache2.contains(id));

        replayCache.close();
        replayCache2.close();
    }

    @Test
    public void testEhCacheCloseCacheTwice() throws Exception {
        ReplayCache replayCache = new EHCacheReplayCache("abc", (URL)null, getDiskstorePath("abc"));
        replayCache.close();
        replayCache.close();
    }

    // No expiry specified so it falls back to the default
    @Test
    public void testEhCacheReplayCacheNoExpirySpecified() throws Exception {
        ReplayCache replayCache = new EHCacheReplayCache("xyz", (URL)null, getDiskstorePath("xyz"));

        String id = UUID.randomUUID().toString();
        replayCache.add(id);
        assertTrue(replayCache.contains(id));

        EHCacheValue ehCacheValue = ((EHCacheReplayCache) replayCache).get(id);
        assertNotNull(ehCacheValue);
        assertNull(ehCacheValue.getExpiry());
        assertEquals(id, ehCacheValue.getIdentifier());

        replayCache.close();
    }

    // The negative expiry is rejected and it falls back to the default
    @Test
    public void testEhCacheReplayCacheNegativeExpiry() throws Exception {
        ReplayCache replayCache = new EHCacheReplayCache("xyz", (URL)null, getDiskstorePath("xyz"));

        String id = UUID.randomUUID().toString();
        replayCache.add(id, Instant.now().minusSeconds(100L));
        assertTrue(replayCache.contains(id));

        EHCacheValue ehCacheValue = ((EHCacheReplayCache) replayCache).get(id);
        assertNotNull(ehCacheValue);
        assertNotNull(ehCacheValue.getExpiry());
        assertEquals(id, ehCacheValue.getIdentifier());

        replayCache.close();
    }

    // The huge expiry is rejected and it falls back to the default
    @Test
    public void testEhCacheReplayCacheHugeExpiry() throws Exception {
        ReplayCache replayCache = new EHCacheReplayCache("xyz", (URL)null, getDiskstorePath("xyz"));

        String id = UUID.randomUUID().toString();
        replayCache.add(id, Instant.now().plus(14, ChronoUnit.HOURS));
        assertTrue(replayCache.contains(id));

        EHCacheValue ehCacheValue = ((EHCacheReplayCache) replayCache).get(id);
        assertNotNull(ehCacheValue);
        assertNotNull(ehCacheValue.getExpiry());
        assertEquals(id, ehCacheValue.getIdentifier());

        replayCache.close();
    }

    private void testReplayCacheInstance(ReplayCache replayCache) throws InterruptedException, IOException {

        // Test default TTL caches OK
        String id = UUID.randomUUID().toString();
        replayCache.add(id);
        assertTrue(replayCache.contains(id));

        // Test specifying TTL caches OK
        id = UUID.randomUUID().toString();
        replayCache.add(id, Instant.now().plusSeconds(100L));
        assertTrue(replayCache.contains(id));

        // Test expiration
        id = UUID.randomUUID().toString();
        replayCache.add(id, Instant.now().plusSeconds(1L));
        Thread.sleep(1250L);
        assertFalse(replayCache.contains(id));
    }

    private Path getDiskstorePath(String prefix) {
        String diskKey = prefix + "-" + Math.abs(new Random().nextInt());
        File diskstore = new File(System.getProperty("java.io.tmpdir"), diskKey);
        return diskstore.toPath();
    }
}