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
package org.swssf.impl.securityToken;

import org.apache.commons.codec.binary.Base64;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_secext_1_0.UsernameTokenType;
import org.swssf.config.JCEAlgorithmMapper;
import org.swssf.ext.Constants;
import org.swssf.ext.SecurityContext;
import org.swssf.ext.SecurityToken;
import org.swssf.ext.WSSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Hashtable;
import java.util.Map;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class UsernameSecurityToken extends AbstractAlgorithmSuiteSecurityEventFiringSecurityToken {

    private static final int DEFAULT_ITERATION = 1000;

    private String username;
    private String password;
    private String created;
    private byte[] nonce;
    private byte[] salt;
    private Integer iteration;

    UsernameSecurityToken(UsernameTokenType usernameTokenType, SecurityContext securityContext, String id, Object processor) {
        super(securityContext, id, processor);
        this.username = usernameTokenType.getUsername();
        this.password = usernameTokenType.getPassword();
        this.created = usernameTokenType.getCreated();
        this.nonce = usernameTokenType.getNonce() != null ? Base64.decodeBase64(usernameTokenType.getNonce()) : null;
        this.salt = usernameTokenType.getSalt() != null ? Base64.decodeBase64(usernameTokenType.getSalt()) : null;
        this.iteration = usernameTokenType.getIteration() != null ? Integer.parseInt(usernameTokenType.getIteration()) : null;
    }

    public UsernameSecurityToken(String username, String password, String created, byte[] nonce, byte[] salt, Integer iteration, SecurityContext securityContext, String id, Object processor) {
        super(securityContext, id, processor);
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

    public Integer getIteration() {
        return iteration;
    }

    /**
     * This method generates a derived key as defined in WSS Username
     * Token Profile.
     *
     * @param rawPassword The password to include in the key generation
     * @param salt        The Salt value
     * @param iteration   The Iteration value. If zero (0) is given the method uses the
     *                    default value
     * @return Returns the derived key a byte array
     * @throws org.swssf.ext.WSSecurityException
     *
     */
    public byte[] generateDerivedKey(String rawPassword, byte[] salt, int iteration) throws WSSecurityException {
        if (iteration == 0) {
            iteration = DEFAULT_ITERATION;
        }
        byte[] pwBytes = null;
        try {
            pwBytes = rawPassword.getBytes("UTF-8");
        } catch (final java.io.UnsupportedEncodingException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }

        byte[] pwSalt = new byte[salt.length + pwBytes.length];
        System.arraycopy(pwBytes, 0, pwSalt, 0, pwBytes.length);
        System.arraycopy(salt, 0, pwSalt, pwBytes.length, salt.length);

        MessageDigest sha = null;
        try {
            sha = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noSHA1availabe", e);
        }
        sha.reset();

        // Make the first hash round with start value
        byte[] k = sha.digest(pwSalt);

        // Perform the 1st up to iteration-1 hash rounds
        for (int i = 1; i < iteration; i++) {
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
    private byte[] getSecretKey(String rawPassword, int keylen, String labelString) throws WSSecurityException {
        byte[] key = null;
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
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

            key = P_hash(password, seed, mac, keylen);

        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noHMACSHA1available", e);
        } catch (UnsupportedEncodingException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
        return key;
    }

    /**
     * P_hash as defined in RFC 2246 for TLS.
     *
     * @param secret   is the key for the HMAC
     * @param seed     the seed value to start the generation - A(0)
     * @param mac      the HMAC algorithm
     * @param required number of bytes to generate
     * @return a byte array that contains a secret key
     * @throws Exception
     */
    private byte[] P_hash(byte[] secret, byte[] seed, Mac mac, int required) throws WSSecurityException {
        byte[] out = new byte[required];
        int offset = 0;
        int toCopy;
        byte[] a, tmp;

        try {
            // a(0) is the seed
            a = seed;
            SecretKeySpec key = new SecretKeySpec(secret, "HmacSHA1");
            mac.init(key);
            while (required > 0) {
                mac.update(a);
                a = mac.doFinal();
                mac.update(a);
                mac.update(seed);
                tmp = mac.doFinal();
                toCopy = Math.min(required, tmp.length);
                System.arraycopy(tmp, 0, out, offset, toCopy);
                offset += toCopy;
                required -= toCopy;
            }
        } catch (InvalidKeyException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
        return out;
    }

    public boolean isAsymmetric() {
        return false;
    }

    private Map<String, Key> keyTable = new Hashtable<String, Key>();

    public Key getSecretKey(String algorithmURI, Constants.KeyUsage keyUsage) throws WSSecurityException {
        super.getSecretKey(algorithmURI, keyUsage);
        byte[] secretToken = null;
        if (getSalt() != null && getIteration() != null) {
            int iteration = getIteration();
            byte[] salt = getSalt();
            secretToken = generateDerivedKey(getPassword(), salt, iteration);
        } else {
            secretToken = getSecretKey(getPassword(), Constants.WSE_DERIVED_KEY_LEN, Constants.LABEL_FOR_DERIVED_KEY);
        }

        if (keyTable.containsKey(algorithmURI)) {
            return keyTable.get(algorithmURI);
        } else {
            String algoFamily = JCEAlgorithmMapper.getJCERequiredKeyFromURI(algorithmURI);
            Key key = new SecretKeySpec(secretToken, algoFamily);
            keyTable.put(algorithmURI, key);
            return key;
        }
    }

    public PublicKey getPublicKey(Constants.KeyUsage keyUsage) throws WSSecurityException {
        super.getPublicKey(keyUsage);
        return null;
    }

    public SecurityToken getKeyWrappingToken() {
        return null;
    }

    public String getKeyWrappingTokenAlgorithm() {
        return null;
    }

    public Constants.TokenType getTokenType() {
        return null;
    }
}
