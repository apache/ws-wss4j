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

import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Status;
import net.sf.ehcache.config.CacheConfiguration;
import net.sf.ehcache.config.Configuration;
import net.sf.ehcache.config.ConfigurationFactory;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

/**
 *
 */
public class EHCacheManagerHolderTest {

    @Test
    public void testCreateCacheManager() {
        Configuration conf =
            ConfigurationFactory.parseConfiguration(EHCacheManagerHolder.class.getResource("/test-ehcache.xml"));

        assertNotNull(conf);
        conf.setName("testCache");

        CacheManager manager1 = EHCacheManagerHolder.createCacheManager(conf);
        assertNotNull(manager1);
        CacheManager manager2 = EHCacheManagerHolder.createCacheManager();
        assertNotNull(manager2);

        manager1.shutdown();
        assertEquals(Status.STATUS_SHUTDOWN, manager1.getStatus());

        assertEquals(Status.STATUS_ALIVE, manager2.getStatus());

        manager2.shutdown();
        assertEquals(Status.STATUS_SHUTDOWN, manager2.getStatus());

    }

    @Test
    public void testCacheNames() {
        CacheManager cacheManager =
            EHCacheManagerHolder.getCacheManager("testCache2",
                                                 EHCacheManagerHolder.class.getResource("/test-ehcache2.xml"));

        String key = "org.apache.wss4j.TokenStore";
        CacheConfiguration cacheConfig =
            EHCacheManagerHolder.getCacheConfiguration(key, cacheManager);
        assertEquals(3600, cacheConfig.getTimeToIdleSeconds());

        key = "org.apache.wss4j.TokenStore-{http://ws.apache.org}wss4j";
        CacheConfiguration cacheConfig2 =
            EHCacheManagerHolder.getCacheConfiguration(key, cacheManager);
        assertEquals(360000, cacheConfig2.getTimeToIdleSeconds());

        key = "org.apache.wss4j.TokenStore-{http://ws.apache.org}wss4junknown";
        CacheConfiguration cacheConfig3 =
            EHCacheManagerHolder.getCacheConfiguration(key, cacheManager);
        assertEquals(3600, cacheConfig3.getTimeToIdleSeconds());

    }
}