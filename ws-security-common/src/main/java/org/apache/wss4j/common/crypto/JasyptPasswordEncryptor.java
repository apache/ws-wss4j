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

package org.apache.wss4j.common.crypto;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.util.FIPSUtils;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.iv.RandomIvGenerator;
import org.jasypt.salt.RandomSaltGenerator;


/**
 * An implementation of PasswordEncryptor that relies on Jasypt's StandardPBEStringEncryptor to
 * encrypt and decrypt passwords. The default algorithm that is used is
 * "PBEWithHmacSHA512AndAES_256". Values encrypted under the previous non-FIPS default
 * ("PBEWithMD5AndTripleDES") can still be decrypted by setting the
 * "org.apache.wss4j.crypto.jasypt.useLegacyDefaultAlgorithm" system property to "true", or by
 * passing that algorithm to the constructor explicitly - but the legacy algorithm (an MD5-based
 * PKCS#5 v1.5 KDF with 3DES) is weak against offline dictionary attack and values should be
 * re-encrypted under the current default.
 */
public class JasyptPasswordEncryptor implements PasswordEncryptor {

    /**
     * The default algorithm prior to WSS4J adopting "PBEWithHmacSHA512AndAES_256"
     * universally (it was previously only the default when FIPS mode was enabled).
     */
    public static final String LEGACY_DEFAULT_ALGORITHM = "PBEWithMD5AndTripleDES";

    /**
     * System property to restore {@link #LEGACY_DEFAULT_ALGORITHM} as the default
     * algorithm (ignored in FIPS mode), for compatibility with values encrypted under
     * previous releases. The property is read each time an instance is constructed
     * without an explicit algorithm, not once at class-loading time.
     */
    public static final String USE_LEGACY_DEFAULT_ALGORITHM_PROPERTY =
        "org.apache.wss4j.crypto.jasypt.useLegacyDefaultAlgorithm";

    public static final String DEFAULT_ALGORITHM = "PBEWithHmacSHA512AndAES_256";

    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(JasyptPasswordEncryptor.class);

    private final StandardPBEStringEncryptor passwordEncryptor;
    private CallbackHandler callbackHandler;

    public JasyptPasswordEncryptor(String password) {
        this(password, defaultAlgorithm());
    }

    public JasyptPasswordEncryptor(String password, String algorithm) {
        passwordEncryptor = new StandardPBEStringEncryptor();
        passwordEncryptor.setPassword(password);
        passwordEncryptor.setAlgorithm(algorithm);
        configureGenerators(algorithm);
    }

    public JasyptPasswordEncryptor(CallbackHandler callbackHandler) {
        this(callbackHandler, defaultAlgorithm());
    }

    public JasyptPasswordEncryptor(CallbackHandler callbackHandler, String algorithm) {
        passwordEncryptor = new StandardPBEStringEncryptor();
        passwordEncryptor.setAlgorithm(algorithm);
        configureGenerators(algorithm);
        this.callbackHandler = callbackHandler;
    }

    /**
     * Resolve the algorithm to use when none is given explicitly, honoring
     * {@link #USE_LEGACY_DEFAULT_ALGORITHM_PROPERTY} at construction time (outside FIPS mode).
     */
    private static String defaultAlgorithm() {
        if (!FIPSUtils.isFIPSEnabled()
            && Boolean.parseBoolean(System.getProperty(USE_LEGACY_DEFAULT_ALGORITHM_PROPERTY, "false"))) {
            return LEGACY_DEFAULT_ALGORITHM;
        }
        return DEFAULT_ALGORITHM;
    }

    private void configureGenerators(String algorithm) {
        if (FIPSUtils.isFIPSEnabled()) {
            passwordEncryptor.setSaltGenerator(new RandomSaltGenerator("PKCS11"));
            passwordEncryptor.setIvGenerator(new RandomIvGenerator("PKCS11"));
        } else if (requiresIv(algorithm)) {
            // AES-based PBE algorithms need an explicit IV generator with Jasypt
            passwordEncryptor.setIvGenerator(new RandomIvGenerator());
        }
    }

    private static boolean requiresIv(String algorithm) {
        return algorithm != null && algorithm.toUpperCase(java.util.Locale.ROOT).contains("AES");
    }

    /**
     * Encrypt the given password
     * @param password the password to be encrypted
     * @return the encrypted password
     */
    public String encrypt(String password) {
        if (callbackHandler != null) {
            WSPasswordCallback pwCb =
                new WSPasswordCallback("", WSPasswordCallback.PASSWORD_ENCRYPTOR_PASSWORD);
            try {
                callbackHandler.handle(new Callback[]{pwCb});
            } catch (IOException | UnsupportedCallbackException e) {
                LOG.debug("Error in getting password: ", e);
            }
            if (pwCb.getPassword() != null) {
                passwordEncryptor.setPassword(pwCb.getPassword());
            }
        }
        return passwordEncryptor.encrypt(password);
    }

    /**
     * Decrypt the given encrypted password
     * @param encryptedPassword the encrypted password to decrypt
     * @return the decrypted password
     */
    public String decrypt(String encryptedPassword) {
        if (callbackHandler != null) {
            WSPasswordCallback pwCb =
                new WSPasswordCallback("", WSPasswordCallback.PASSWORD_ENCRYPTOR_PASSWORD);
            try {
                callbackHandler.handle(new Callback[]{pwCb});
            } catch (IOException | UnsupportedCallbackException e) {
                LOG.debug("Error in getting password: ", e);
            }
            if (pwCb.getPassword() != null) {
                passwordEncryptor.setPassword(pwCb.getPassword());
            }
        }
        return passwordEncryptor.decrypt(encryptedPassword);
    }

}
