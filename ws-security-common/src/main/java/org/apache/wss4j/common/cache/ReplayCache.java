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

import java.io.Closeable;
import java.time.Instant;

/**
 * A cache to store (String) identifiers to avoid replay attacks. An example of such an identifier
 * is a UsernameToken nonce.
 */
public interface ReplayCache extends Closeable {

    /**
     * Add the given identifier to the cache. It will be cached for a default amount of time.
     * @param identifier The identifier to be added
     */
    void add(String identifier);

    /**
     * Add the given identifier to the cache to be cached for the given time
     * @param identifier The identifier to be added
     * @param expiry A custom expiry time for the identifier
     */
    void add(String identifier, Instant expiry);

    /**
     * Return true if the given identifier is contained in the cache
     * @param identifier The identifier to check
     */
    boolean contains(String identifier);

    /**
     * Add the given identifier to the cache if, and only if, it is not already contained in it, as a
     * single atomic operation. A replay check must use this method rather than contains() followed by
     * add(): two concurrent requests carrying the same identifier could otherwise both pass contains()
     * before either reaches add(), and both be accepted.
     *
     * The default implementation serializes calls on this cache instance, which is only atomic with
     * respect to other calls to this method. Implementations should override it with an operation that
     * is atomic in the underlying store.
     *
     * @param identifier The identifier to be added
     * @param expiry A custom expiry time for the identifier. Can be null in which case, the default
     *               expiry is used.
     * @return true if the identifier was added, false if it was already contained in the cache or is
     *         null or empty, in which case the cache is left unchanged
     */
    default boolean addIfAbsent(String identifier, Instant expiry) {
        if (identifier == null || identifier.length() == 0) {
            return false;
        }
        synchronized (this) {
            if (contains(identifier)) {
                return false;
            }
            if (expiry != null) {
                add(identifier, expiry);
            } else {
                add(identifier);
            }
            return true;
        }
    }

}
