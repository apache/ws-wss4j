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


/**
 * A cache to store (String) identifiers to avoid replay attacks. An example of such an identifier
 * is a UsernameToken nonce.
 */
public interface ReplayCache {
    
    /**
     * Add the given identifier to the cache. It will be cached for a default amount of time.
     * @param identifier The identifier to be added
     */
    void add(String identifier);
    
    /**
     * Add the given identifier to the cache to be cached for the given time
     * @param identifier The identifier to be added
     * @param timeToLive The length of time to cache the Identifier in seconds
     */
    void add(String identifier, long timeToLive);
    
    /**
     * Return true if the given identifier is contained in the cache
     * @param identifier The identifier to check
     */
    boolean contains(String identifier);
    
}
