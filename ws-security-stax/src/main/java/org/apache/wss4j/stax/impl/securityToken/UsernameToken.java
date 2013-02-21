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
package org.apache.wss4j.stax.impl.securityToken;

import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.derivedKey.AlgoFactory;
import org.apache.wss4j.common.derivedKey.ConversationConstants;
import org.apache.wss4j.common.derivedKey.ConversationException;
import org.apache.wss4j.common.derivedKey.DerivationAlgorithm;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.stax.ext.WSSecurityContext;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class UsernameToken {

    private static final long DEFAULT_ITERATION = 1000;

    private final String username;
    private final String password;
    private final String created;
    private final byte[] nonce;
    private final byte[] salt;
    private final Long iteration;

    public UsernameToken(String username, String password, String created, byte[] nonce, byte[] salt, Long iteration) {
        this.username = username;
        this.password = password;
        this.created = created;
        this.nonce = nonce;
        this.salt = salt;
        this.iteration = iteration;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getCreated() {
        return created;
    }

    public byte[] getNonce() {
        return nonce;
    }

    public byte[] getSalt() {
        return salt;
    }

    public Long getIteration() {
        return iteration;
    }

    /**
     * This method generates a derived key as defined in WSS Username
     * Token Profile.
     *
     * @return Returns the derived key a byte array
     * @throws org.apache.wss4j.common.ext.WSSecurityException
     *
     */
    public byte[] generateDerivedKey(WSSecurityContext wsSecurityContext) throws WSSecurityException {

        if (wsSecurityContext != null) {
            if (salt == null || salt.length == 0) {
                wsSecurityContext.handleBSPRule(BSPRule.R4217);
            }
            if (iteration == null || iteration < DEFAULT_ITERATION) {
                wsSecurityContext.handleBSPRule(BSPRule.R4218);
            }
        }

        Long iters = iteration;
        if (iters == null || iters == 0) {
            iters = DEFAULT_ITERATION;
        }
        byte[] pwBytes;
        try {
            pwBytes = password.getBytes("UTF-8");
        } catch (final UnsupportedEncodingException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
        }

        byte[] pwSalt = new byte[salt.length + pwBytes.length];
        System.arraycopy(pwBytes, 0, pwSalt, 0, pwBytes.length);
        System.arraycopy(salt, 0, pwSalt, pwBytes.length, salt.length);

        MessageDigest sha;
        try {
            sha = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "noSHA1availabe", e);
        }
        sha.reset();

        // Make the first hash round with start value
        byte[] k = sha.digest(pwSalt);

        // Perform the 1st up to iteration-1 hash rounds
        for (int i = 1; i < iters; i++) {
            k = sha.digest(k);
        }
        return k;
    }

    /**
     * Gets the secret key as per WS-Trust spec.
     *
     * @param keylen      How many bytes to generate for the key
     * @param labelString the label used to generate the seed
     * @return a secret key constructed from information contained in this
     *         username token
     */
    protected byte[] getSecretKey(String rawPassword, int keylen, String labelString) throws WSSecurityException {
        try {
            byte[] password = rawPassword.getBytes("UTF-8");
            byte[] label = labelString.getBytes("UTF-8");
            byte[] nonce = getNonce();
            byte[] created = getCreated().getBytes("UTF-8");
            byte[] seed = new byte[label.length + nonce.length + created.length];

            int offset = 0;
            System.arraycopy(label, 0, seed, offset, label.length);
            offset += label.length;

            System.arraycopy(nonce, 0, seed, offset, nonce.length);
            offset += nonce.length;

            System.arraycopy(created, 0, seed, offset, created.length);

            DerivationAlgorithm algo =
                    AlgoFactory.getInstance(ConversationConstants.DerivationAlgorithm.P_SHA_1);
            return algo.createKey(password, seed, 0, keylen);

        } catch (UnsupportedEncodingException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
        } catch (ConversationException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
        }
    }
}
