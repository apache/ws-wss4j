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

/**
 * Some functionality to detect if EhCache is available or not.
 */
public final class WSS4JCacheUtil {

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(WSS4JCacheUtil.class);
    private static final boolean EH_CACHE_INSTALLED;

    static {
        boolean ehCacheInstalled = false;
        try {
            Class<?> cacheManagerClass = Class.forName("org.ehcache.CacheManager");
            if (cacheManagerClass != null) {
                ehCacheInstalled = true;
            }
        } catch (Exception e) {
            //ignore
            LOG.debug(e.getMessage());
        }
        EH_CACHE_INSTALLED = ehCacheInstalled;
    }

    private WSS4JCacheUtil() {
        // complete
    }

    public static boolean isEhCacheInstalled() {
        return EH_CACHE_INSTALLED;
    }

}
