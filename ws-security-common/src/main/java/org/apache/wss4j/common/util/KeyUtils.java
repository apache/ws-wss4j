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

import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.XMLCipher;

public final class KeyUtils {
    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(KeyUtils.class);
    private static final int MAX_SYMMETRIC_KEY_SIZE = 1024;
    
    private KeyUtils() {
        // complete
    }

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
     * Convert the raw key bytes into a SecretKey object of type algorithm.
     */
    public static SecretKey prepareSecretKey(String algorithm, byte[] rawKey) {
        // Do an additional check on the keysize required by the encryption algorithm
        int size = 0;
        try {
            size = getKeyLength(algorithm);
        } catch (Exception e) {
            // ignore - some unknown (to JCEMapper) encryption algorithm
            if (LOG.isDebugEnabled()) {
                LOG.debug(e.getMessage());
            }
        }
        String keyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(algorithm);
        SecretKeySpec keySpec;
        if (size > 0 && !algorithm.endsWith("gcm") && !algorithm.contains("hmac-")) {
            keySpec = 
                new SecretKeySpec(
                    rawKey, 0, rawKey.length > size ? size : rawKey.length, keyAlgorithm
                );
        } else if (rawKey.length > MAX_SYMMETRIC_KEY_SIZE) {
            // Prevent a possible attack where a huge secret key is specified
            keySpec = 
                new SecretKeySpec(
                    rawKey, 0, MAX_SYMMETRIC_KEY_SIZE, keyAlgorithm
                );
        } else {
            keySpec = new SecretKeySpec(rawKey, keyAlgorithm);
        }
        return keySpec;
    }
    
    public static KeyGenerator getKeyGenerator(String algorithm) throws WSSecurityException {
        try {
            //
            // Assume AES as default, so initialize it
            //
            String keyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(algorithm);
            if (keyAlgorithm == null || "".equals(keyAlgorithm)) {
                keyAlgorithm = JCEMapper.translateURItoJCEID(algorithm);
            }
            KeyGenerator keyGen = KeyGenerator.getInstance(keyAlgorithm);
            if (algorithm.equalsIgnoreCase(XMLCipher.AES_128)
                || algorithm.equalsIgnoreCase(XMLCipher.AES_128_GCM)) {
                keyGen.init(128);
            } else if (algorithm.equalsIgnoreCase(XMLCipher.AES_192)
                || algorithm.equalsIgnoreCase(XMLCipher.AES_192_GCM)) {
                keyGen.init(192);
            } else if (algorithm.equalsIgnoreCase(XMLCipher.AES_256)
                || algorithm.equalsIgnoreCase(XMLCipher.AES_256_GCM)) {
                keyGen.init(256);
            }
            return keyGen;
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.UNSUPPORTED_ALGORITHM, e
            );
        }
    }
}
