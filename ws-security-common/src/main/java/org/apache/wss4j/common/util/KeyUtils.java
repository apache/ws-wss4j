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

package org.apache.wss4j.common.util;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.xml.security.algorithms.JCEMapper;

public final class KeyUtils {
    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(KeyUtils.class);

    /**
     * Returns the length of the key in # of bytes
     * 
     * @param algorithm
     * @return the key length
     */
    public static int getKeyLength(String algorithm) throws WSSecurityException {
        return JCEMapper.getKeyLengthFromURI(algorithm) / 8;
    }
    
    /**
     * Convert the raw key bytes into a SecretKey object of type symEncAlgo.
     */
    public static SecretKey prepareSecretKey(String symEncAlgo, byte[] rawKey) {
        // Do an additional check on the keysize required by the encryption algorithm
        int size = 0;
        try {
            size = getKeyLength(symEncAlgo);
        } catch (Exception e) {
            // ignore - some unknown (to JCEMapper) encryption algorithm
            if (LOG.isDebugEnabled()) {
                LOG.debug(e.getMessage());
            }
        }
        String keyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(symEncAlgo);
        SecretKeySpec keySpec;
        if (size > 0 && !symEncAlgo.endsWith("gcm")) {
            keySpec = 
                new SecretKeySpec(
                    rawKey, 0, rawKey.length > size ? size : rawKey.length, keyAlgorithm
                );
        } else {
            keySpec = new SecretKeySpec(rawKey, keyAlgorithm);
        }
        return keySpec;
    }    
}
