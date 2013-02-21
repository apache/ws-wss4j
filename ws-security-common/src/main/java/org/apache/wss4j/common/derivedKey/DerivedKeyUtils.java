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
package org.apache.wss4j.common.derivedKey;

import org.apache.wss4j.common.ext.WSSecurityException;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class DerivedKeyUtils {

    /**
     * Derive a key from this DerivedKeyToken instance
     *
     * @param length
     * @param secret
     * @throws org.apache.wss4j.stax.wss.ext.WSSecurityException
     *
     */
    public static byte[] deriveKey(String algorithm, String label, int length, byte[] secret, byte[] nonce, int offset) throws WSSecurityException {
        try {
            DerivationAlgorithm algo = AlgoFactory.getInstance(algorithm);
            byte[] labelBytes;
            if (label == null || label.length() == 0) {
                labelBytes = (ConversationConstants.DEFAULT_LABEL 
                        + ConversationConstants.DEFAULT_LABEL).getBytes("UTF-8");
            } else {
                labelBytes = label.getBytes("UTF-8");
            }

            byte[] seed = new byte[labelBytes.length + nonce.length];
            System.arraycopy(labelBytes, 0, seed, 0, labelBytes.length);
            System.arraycopy(nonce, 0, seed, labelBytes.length, nonce.length);

            if (length <= 0) {
                length = 32;
            }
            return algo.createKey(secret, seed, offset, length);

        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
    }
}
