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

package org.apache.wss4j.dom.cache;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;

/**
 * A simple in-memory HashSet based cache to prevent against replay attacks. The default TTL is 5 minutes
 * and the max TTL is 60 minutes.
 */
public class MemoryReplayCache implements ReplayCache {
    
    public static final long DEFAULT_TTL = 60L * 5L;
    public static final long MAX_TTL = DEFAULT_TTL * 12L;
    private final SortedMap<Date, List<String>> cache = new TreeMap<Date, List<String>>();
    private final Set<String> ids = Collections.synchronizedSet(new HashSet<String>());
    
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
        
        long ttl = timeToLive;
        if (ttl < 0 || ttl > MAX_TTL) {
            ttl = DEFAULT_TTL;
        }
        
        Date expires = new Date();
        long currentTime = expires.getTime();
        expires.setTime(currentTime + (ttl * 1000L));
        
        synchronized (cache) {
            List<String> list = cache.get(expires);
            if (list == null) {
                list = new ArrayList<String>(1);
                cache.put(expires, list);
            }
            list.add(identifier);
        }
        ids.add(identifier);
    }
    
    /**
     * Return true if the given identifier is contained in the cache
     * @param identifier The identifier to check
     */
    public boolean contains(String identifier) {
        processTokenExpiry();
        
        if (identifier != null && !"".equals(identifier)) {
            return ids.contains(identifier);
        }
        return false;
    }
    
    protected void processTokenExpiry() {
        Date current = new Date();
        synchronized (cache) {
            Iterator<Entry<Date, List<String>>> it = cache.entrySet().iterator();
            while (it.hasNext()) {
                Entry<Date, List<String>> entry = it.next();
                if (entry.getKey().before(current)) {
                    for (String id : entry.getValue()) {
                        ids.remove(id);
                    }
                    it.remove();
                } else {
                    break;
                }
            }
        }
    }
}
