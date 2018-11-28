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
import java.net.URL;
import java.time.Instant;
import java.util.UUID;

import org.junit.Assert;
import org.junit.Test;

/**
 * Some unit tests for the ReplayCache implementations
 */
public class ReplayCacheTest extends Assert {

    @Test
    public void testMemoryReplayCache() throws InterruptedException, IOException {
        ReplayCache replayCache = new MemoryReplayCache();

        testReplayCacheInstance(replayCache);

        replayCache.close();
    }

    @Test
    public void testEhCacheReplayCache() throws InterruptedException, IOException {
        ReplayCache replayCache = new EHCacheReplayCache("xyz", (URL)null);

        testReplayCacheInstance(replayCache);

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
}
