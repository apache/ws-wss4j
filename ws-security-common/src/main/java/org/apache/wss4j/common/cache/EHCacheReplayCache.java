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

import java.net.URL;
import java.util.concurrent.atomic.AtomicInteger;

import net.sf.ehcache.Cache;
import net.sf.ehcache.CacheManager;
import net.sf.ehcache.Ehcache;
import net.sf.ehcache.Element;
import net.sf.ehcache.Status;
import net.sf.ehcache.config.CacheConfiguration;

/**
 * An in-memory EHCache implementation of the ReplayCache interface. The default TTL is 60 minutes and the
 * max TTL is 12 hours.
 */
public class EHCacheReplayCache implements ReplayCache {

    public static final long DEFAULT_TTL = 3600L;
    public static final long MAX_TTL = DEFAULT_TTL * 12L;
    protected Ehcache cache;
    protected CacheManager cacheManager;
    private long ttl = DEFAULT_TTL;

    public EHCacheReplayCache(String key, URL configFileURL) {
        this(key, EHCacheManagerHolder.getCacheManager("", configFileURL));
    }

    public EHCacheReplayCache(String key, CacheManager cacheManager) {
        this.cacheManager = cacheManager;

        CacheConfiguration cc = EHCacheManagerHolder.getCacheConfiguration(key, cacheManager);

        Cache newCache = new RefCountCache(cc);
        cache = cacheManager.addCacheIfAbsent(newCache);
        synchronized (cache) {
            if (cache.getStatus() != Status.STATUS_ALIVE) {
                cache = cacheManager.addCacheIfAbsent(newCache);
            }
            if (cache instanceof RefCountCache) {
                ((RefCountCache)cache).incrementAndGet();
            }
        }

        // Set the TimeToLive value from the CacheConfiguration
        ttl = cc.getTimeToLiveSeconds();
    }

    private static class RefCountCache extends Cache {
        private AtomicInteger count = new AtomicInteger();
        public RefCountCache(CacheConfiguration cc) {
            super(cc);
        }
        public int incrementAndGet() {
            return count.incrementAndGet();
        }
        public int decrementAndGet() {
            return count.decrementAndGet();
        }
    }


    /**
     * Set a new (default) TTL value in seconds
     * @param newTtl a new (default) TTL value in seconds
     */
    public void setTTL(long newTtl) {
        ttl = newTtl;
    }

    /**
     * Get the (default) TTL value in seconds
     * @return the (default) TTL value in seconds
     */
    public long getTTL() {
        return ttl;
    }

    /**
     * Add the given identifier to the cache. It will be cached for a default amount of time.
     * @param identifier The identifier to be added
     */
    public void add(String identifier) {
        add(identifier, ttl);
    }

    /**
     * Add the given identifier to the cache to be cached for the given time
     * @param identifier The identifier to be added
     * @param timeToLive The length of time to cache the Identifier in seconds
     */
    public void add(String identifier, long timeToLive) {
        if (identifier == null || "".equals(identifier)) {
            return;
        }

        int parsedTTL = (int)timeToLive;
        if (timeToLive != (long)parsedTTL || parsedTTL < 0 || parsedTTL > MAX_TTL) {
            // Default to configured value
            parsedTTL = (int)ttl;
            if (ttl != (long)parsedTTL) {
                // Fall back to 60 minutes if the default TTL is set incorrectly
                parsedTTL = 3600;
            }
        }

        Element cacheElement = new Element(identifier, identifier, parsedTTL, parsedTTL);
        cacheElement.resetAccessStatistics();
        cache.put(cacheElement);
    }

    /**
     * Return true if the given identifier is contained in the cache
     * @param identifier The identifier to check
     */
    public boolean contains(String identifier) {
        if (cache == null) {
            return false;
        }
        Element element = cache.get(identifier);
        if (element != null) {
            if (cache.isExpired(element)) {
                cache.remove(identifier);
                return false;
            }
            return true;
        }
        return false;
    }

    @Override
    public synchronized void close() {
        if (cacheManager != null) {
            // this step is especially important for global shared cache manager
            if (cache != null) {
                synchronized (cache) {
                    if (cache instanceof RefCountCache
                        && ((RefCountCache)cache).decrementAndGet() == 0) {
                        cacheManager.removeCache(cache.getName());
                    }
                }
            }

            EHCacheManagerHolder.releaseCacheManger(cacheManager);
            cacheManager = null;
            cache = null;
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
