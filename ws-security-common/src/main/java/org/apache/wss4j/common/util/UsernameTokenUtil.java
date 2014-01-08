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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;

public final class UsernameTokenUtil {
    public static final int DEFAULT_ITERATION = 1000;
    
    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(UsernameTokenUtil.class);
    
    /**
     * This static method generates a derived key as defined in WSS Username
     * Token Profile.
     * 
     * @param password The password to include in the key generation
     * @param salt The Salt value
     * @param iteration The Iteration value. If zero (0) is given the method uses the
     *                  default value
     * @return Returns the derived key a byte array
     * @throws WSSecurityException
     */
    public static byte[] generateDerivedKey(
        byte[] password, 
        byte[] salt, 
        int iteration
    ) throws WSSecurityException {
        if (iteration == 0) {
            iteration = DEFAULT_ITERATION;
        }

        byte[] pwSalt = new byte[salt.length + password.length];
        System.arraycopy(password, 0, pwSalt, 0, password.length);
        System.arraycopy(salt, 0, pwSalt, password.length, salt.length);

        MessageDigest sha = null;
        try {
            sha = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(e.getMessage(), e);
            }
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE, "noSHA1availabe", e
            );
        }
        //
        // Make the first hash round with start value
        //
        byte[] k = sha.digest(pwSalt);
        //
        // Perform the 1st up to iteration-1 hash rounds
        //
        for (int i = 1; i < iteration; i++) {
            k = sha.digest(k);
        }
        return k;
    }
    
    /**
     * This static method generates a derived key as defined in WSS Username
     * Token Profile.
     * 
     * @param password The password to include in the key generation
     * @param salt The Salt value
     * @param iteration The Iteration value. If zero (0) is given the method uses the
     *                  default value
     * @return Returns the derived key a byte array
     * @throws WSSecurityException
     */
    public static byte[] generateDerivedKey(
        String password, 
        byte[] salt, 
        int iteration
    ) throws WSSecurityException {
        try {
            return generateDerivedKey(password.getBytes("UTF-8"), salt, iteration);
        } catch (final java.io.UnsupportedEncodingException e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(e.getMessage(), e);
            }
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                    "empty", e, "Unable to convert password to UTF-8");
        }
    }
    
    /**
     * This static method generates a 128 bit salt value as defined in WSS
     * Username Token Profile.
     * 
     * @param useForMac If <code>true</code> define the Salt for use in a MAC
     * @return Returns the 128 bit salt value as byte array
     */
    public static byte[] generateSalt(boolean useForMac) {
        byte[] saltValue = null;
        try {
            saltValue = generateNonce(16);
        } catch (WSSecurityException ex) {
            LOG.debug(ex.getMessage(), ex);
            return null;
        }
        if (useForMac) {
            saltValue[0] = 0x01;
        } else {
            saltValue[0] = 0x02;
        }
        return saltValue;
    }

    /**
     * Generate a nonce of the given length using the SHA1PRNG algorithm. The SecureRandom
     * instance that backs this method is cached for efficiency.
     * 
     * @return a nonce of the given length
     * @throws WSSecurityException
     */
    private static byte[] generateNonce(int length) throws WSSecurityException {
        try {
            byte[] temp = new byte[length];
            XMLSecurityConstants.secureRandom.nextBytes(temp);
            return temp;
        } catch (Exception ex) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                    "empty", ex,
                    "Error in generating nonce of length " + length
            );
        }
    }
}
