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
import java.nio.file.Path;
import java.time.Instant;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.Loader;
import org.ehcache.Cache;
import org.ehcache.CacheManager;
import org.ehcache.Status;
import org.ehcache.config.builders.CacheConfigurationBuilder;
import org.ehcache.config.builders.CacheManagerBuilder;
import org.ehcache.xml.XmlConfiguration;

/**
 * An in-memory EHCache implementation of the ReplayCache interface. The default TTL is 60 minutes and the
 * max TTL is 12 hours.
 */
public class EHCacheReplayCache implements ReplayCache {

    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(EHCacheReplayCache.class);
    private static final String CACHE_TEMPLATE_NAME = "wss4jCache";

    private final Cache<String, EHCacheValue> cache;
    private final CacheManager cacheManager;
    private final String key;

    public EHCacheReplayCache(String key, URL configFileURL, Path diskstorePath) throws WSSecurityException {
        this.key = key;
        try {
            XmlConfiguration xmlConfig = new XmlConfiguration(getConfigFileURL(configFileURL));
            CacheConfigurationBuilder<String, EHCacheValue> configurationBuilder =
                    xmlConfig.newCacheConfigurationBuilderFromTemplate(CACHE_TEMPLATE_NAME, String.class, EHCacheValue.class);
            CacheManagerBuilder builder = CacheManagerBuilder.newCacheManagerBuilder().withCache(key, configurationBuilder);
            if (diskstorePath != null) {
                builder = builder.with(CacheManagerBuilder.persistence(diskstorePath.toFile()));
            }
            cacheManager = builder.build();

            cacheManager.init();
            cache = cacheManager.getCache(key, String.class, EHCacheValue.class);
        } catch (Exception ex) {
            LOG.error("Error configuring EHCacheReplayCache", ex.getMessage());
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, ex, "replayCacheError");
        }
    }

    private URL getConfigFileURL(URL suppliedConfigFileURL) {
        if (suppliedConfigFileURL == null) {
            //using the default
            String defaultConfigFile = "/wss4j-ehcache.xml";
            URL configFileURL = null;
            try {
                configFileURL = Loader.getResource(defaultConfigFile);
                if (configFileURL == null) {
                    configFileURL = new URL(defaultConfigFile);
                }
                return configFileURL;
            } catch (IOException e) {
                // Do nothing
                LOG.debug(e.getMessage());
            }
        }
        return suppliedConfigFileURL;
    }

    /**
     * Add the given identifier to the cache. It will be cached for a default amount of time.
     * @param identifier The identifier to be added
     */
    public void add(String identifier) {
        add(identifier, null);
    }

    /**
     * Add the given identifier to the cache to be cached for the given time
     * @param identifier The identifier to be added
     * @param expiry A custom expiry time for the identifier. Can be null in which case, the default expiry is used.
     */
    public void add(String identifier, Instant expiry) {
        if (identifier == null || "".equals(identifier)) {
            return;
        }

        cache.put(identifier, new EHCacheValue(identifier, expiry));
    }

    /**
     * Return true if the given identifier is contained in the cache
     * @param identifier The identifier to check
     */
    public boolean contains(String identifier) {
        if (cache == null) {
            return false;
        }
        EHCacheValue element = cache.get(identifier);
        return element != null;
    }

    // Only exposed for testing
    EHCacheValue get(String identifier) {
        return cache.get(identifier);
    }

    @Override
    public synchronized void close() {
        if (cacheManager.getStatus() == Status.AVAILABLE) {
            cacheManager.removeCache(key);
            cacheManager.close();
        }
    }

    public void initComplete() {
    }
    public void preShutdown() {
        close();
    }
    public void postShutdown() {
        close();
    }

}
