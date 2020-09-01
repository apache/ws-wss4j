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

import java.io.IOException;
import java.nio.file.Path;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Some unit tests for the ReplayCache implementations
 */
public class ReplayCacheTest {

    @TempDir
    Path tempDir;

    @Test
    public void testMemoryReplayCache() throws InterruptedException, IOException {
        try (ReplayCache replayCache = new MemoryReplayCache()) {
            testReplayCacheInstance(replayCache);
        }
    }

    @Test
    public void testEhCacheReplayCache() throws Exception {
        try (ReplayCache replayCache = new EHCacheReplayCache("xyz", tempDir)) {
            testReplayCacheInstance(replayCache);
        }
    }

    @Test
    public void testEhCacheReplayCacheNoPath() throws Exception {
        try (ReplayCache replayCache = new EHCacheReplayCache("xyz")) {
            testReplayCacheInstance(replayCache);
        }
    }

    @Test
    public void testEhCacheDifferentCaches() throws Exception {
        ReplayCache replayCache = new EHCacheReplayCache("abc", tempDir.resolve("abc"));

        ReplayCache replayCache2 = new EHCacheReplayCache("cba", tempDir.resolve("cba"));

        String id = UUID.randomUUID().toString();
        replayCache.add(id);
        assertTrue(replayCache.contains(id));
        assertFalse(replayCache2.contains(id));

        replayCache.close();
        replayCache2.close();
    }

    @Test
    public void testOverflowToDisk() throws Exception {
        ReplayCache replayCache = new EHCacheReplayCache("abc", tempDir);
        
        for (int i = 0; i < 10050; i++) {
            String id = Integer.toString(i);
            replayCache.add(id);
            assertTrue(replayCache.contains(id));
        }

        replayCache.close();
    }

    @Test
    public void testEhCacheCloseCacheTwice() throws Exception {
        ReplayCache replayCache = new EHCacheReplayCache("abc", tempDir);
        replayCache.close();
        replayCache.close();
    }

    // No expiry specified so it falls back to the default
    @Test
    public void testEhCacheReplayCacheNoExpirySpecified() throws Exception {
        ReplayCache replayCache = new EHCacheReplayCache("xyz", tempDir);

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
        ReplayCache replayCache = new EHCacheReplayCache("xyz", tempDir);

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
        ReplayCache replayCache = new EHCacheReplayCache("xyz", tempDir);

        String id = UUID.randomUUID().toString();
        replayCache.add(id, Instant.now().plus(14, ChronoUnit.HOURS));
        assertTrue(replayCache.contains(id));

        EHCacheValue ehCacheValue = ((EHCacheReplayCache) replayCache).get(id);
        assertNotNull(ehCacheValue);
        assertNotNull(ehCacheValue.getExpiry());
        assertEquals(id, ehCacheValue.getIdentifier());

        replayCache.close();
    }

    @Test
    public void testNullKey() throws Exception {
        Assertions.assertThrows(NullPointerException.class, () ->
                new EHCacheReplayCache(null, tempDir));
    }

    @Test
    public void testPersistentAndDiskstoreNull() throws Exception {
        Assertions.assertThrows(NullPointerException.class, () ->
                new EHCacheReplayCache("abc", null, 10, 10000, true));
    }

    @Test
    public void testZeroDiskSize() throws Exception {
        Assertions.assertThrows(IllegalArgumentException.class, () ->
                new EHCacheReplayCache("abc", tempDir, 0, 10000, false));
    }

    @Test
    public void testTooLargeDiskSize() throws Exception {
        Assertions.assertThrows(IllegalArgumentException.class, () ->
                new EHCacheReplayCache("abc", tempDir, 10001, 10000, false));
    }

    @Test
    public void testTooSmallHeapEntries() throws Exception {
        Assertions.assertThrows(IllegalArgumentException.class, () ->
                new EHCacheReplayCache("abc", tempDir, 10, 10, false));
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

}