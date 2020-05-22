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
package org.apache.wss4j.dom.common;

import java.io.File;
import java.util.Random;

import org.apache.wss4j.common.cache.EHCacheReplayCache;
import org.apache.wss4j.common.cache.ReplayCache;
import org.apache.wss4j.common.ext.WSSecurityException;

/**
 * A utility class for security tests
 */
public final class SecurityTestUtil {

    private SecurityTestUtil() {
        // complete
    }

    public static ReplayCache createCache(String key) throws WSSecurityException {
        String diskKey = key + "-" + Math.abs(new Random().nextInt());
        File diskstore = new File(System.getProperty("java.io.tmpdir"), diskKey);
        return new EHCacheReplayCache(key, diskstore.toPath());
    }
}
