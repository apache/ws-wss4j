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

package org.apache.ws.security.cache;

import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

/**
 * A simple in-memory HashSet based cache to prevent against replay attacks. The default TTL is 5 minutes
 * and the max TTL is 60 minutes.
 */
public class MemoryReplayCache implements ReplayCache {
    
    public static final long DEFAULT_TTL = 60L * 5L;
    public static final long MAX_TTL = DEFAULT_TTL * 12L;
    private Set<ReplayCacheIdentifier> cache = 
        Collections.synchronizedSet(new HashSet<ReplayCacheIdentifier>());
    
    /**
     * Add the given identifier to the cache. It will be cached for a default amount of time.
     * @param identifier The identifier to be added
     */
    public void add(String identifier) {
        add(identifier, DEFAULT_TTL);
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
        ReplayCacheIdentifier cacheIdentifier = new ReplayCacheIdentifier();
        cacheIdentifier.setIdentifier(identifier);
        
        long ttl = timeToLive;
        if (ttl < 0 || ttl > MAX_TTL) {
            ttl = DEFAULT_TTL;
        }
        
        Date expires = new Date();
        long currentTime = expires.getTime();
        expires.setTime(currentTime + (ttl * 1000L));
        cacheIdentifier.setExpiry(expires);
        
        cache.add(cacheIdentifier);
    }
    
    /**
     * Return true if the given identifier is contained in the cache
     * @param identifier The identifier to check
     */
    public boolean contains(String identifier) {
        processTokenExpiry();
        
        if (identifier != null && !"".equals(identifier)) {
            ReplayCacheIdentifier cacheIdentifier = new ReplayCacheIdentifier();
            cacheIdentifier.setIdentifier(identifier);
            return cache.contains(cacheIdentifier);
        }
        return false;
    }
    
    protected void processTokenExpiry() {
        Date current = new Date();
        synchronized (cache) {
            Iterator<ReplayCacheIdentifier> iterator = cache.iterator();
            while (iterator.hasNext()) {
                if (iterator.next().getExpiry().before(current)) {
                    iterator.remove();
                }
            }
        }
    }
    
    private static class ReplayCacheIdentifier {
        
        private String identifier;
        private Date expires;
        
        /**
         * Set the (String) identifier
         * @param identifier the (String) identifier
         */
        public void setIdentifier(String identifier) {
            this.identifier = identifier;
        }
        
        /**
         * Set when this identifier is to be removed from the cache
         * @param expires when this identifier is to be removed from the cache
         */
        public void setExpiry(Date expires) {
            this.expires = expires;
        }
        
        /**
         * Get when this identifier is to be removed from the cache
         * @return when this identifier is to be removed from the cache
         */
        public Date getExpiry() {
            return expires;
        }
        
        @Override
        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }
            if (!(o instanceof ReplayCacheIdentifier)) {
                return false;
            }
            
            ReplayCacheIdentifier replayCacheIdentifier = (ReplayCacheIdentifier)o;
            
            if (identifier == null && replayCacheIdentifier.identifier != null) {
                return false;
            } else if (identifier != null && !identifier.equals(replayCacheIdentifier.identifier)) {
                return false;
            }
            
            return true;
        }
        
        @Override
        public int hashCode() {
            return identifier != null ? identifier.hashCode() : 0;
        }
    }

}
