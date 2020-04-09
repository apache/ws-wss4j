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

import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.function.Supplier;

import org.ehcache.expiry.ExpiryPolicy;

/**
 * A custom Expiry implementation for EhCache. It uses the supplied expiry which is part of the cache value.
 * If it doesn't exist, it falls back to the default value (3600 seconds).
 */
public class EHCacheExpiry implements ExpiryPolicy<String, EHCacheValue> {

    /**
     * The default time to live (60 minutes)
     */
    public static final long DEFAULT_TTL = 3600L;

    /**
     * The max time to live (12 hours)
     */
    public static final long MAX_TTL = DEFAULT_TTL * 12L;


    @Override
    public Duration getExpiryForCreation(String s, EHCacheValue ehCacheValue) {
        long parsedTTL = ehCacheValue.getExpiry();
        if (parsedTTL <= 0 || parsedTTL > MAX_TTL) {
            // Use default value
            parsedTTL = DEFAULT_TTL;
        }

        return Duration.of(parsedTTL, ChronoUnit.SECONDS);
    }

    @Override
    public Duration getExpiryForAccess(String s, Supplier<? extends EHCacheValue> supplier) {
        return null;
    }

    @Override
    public Duration getExpiryForUpdate(String s, Supplier<? extends EHCacheValue> supplier, EHCacheValue ehCacheValue) {
        return null;
    }


}
