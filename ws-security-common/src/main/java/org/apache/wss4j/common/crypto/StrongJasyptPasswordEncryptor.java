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
import org.jasypt.util.text.StrongTextEncryptor;


/**
 * An implementation of PasswordEncryptor that relies on Jasypt's StrongTextEncryptor to encrypt
 * and decrypt passwords.
 */
public class StrongJasyptPasswordEncryptor implements PasswordEncryptor {
    
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(StrongJasyptPasswordEncryptor.class);
    
    private final StrongTextEncryptor passwordEncryptor;
    
    public StrongJasyptPasswordEncryptor(String masterPassword) {
        passwordEncryptor = new StrongTextEncryptor();
        passwordEncryptor.setPassword(masterPassword);
    }
    
    public StrongJasyptPasswordEncryptor(CallbackHandler callbackHandler) {
        passwordEncryptor = new StrongTextEncryptor();
        
        WSPasswordCallback pwCb = 
            new WSPasswordCallback("", WSPasswordCallback.Usage.PASSWORD_ENCRYPTOR_PASSWORD);
        try {
            callbackHandler.handle(new Callback[]{pwCb});
        } catch (IOException e) {
            LOG.debug("Error in getting master password: ", e);
        } catch (UnsupportedCallbackException e) {
            LOG.debug("Error in getting master password: ", e);
        }
        if (pwCb.getPassword() != null) {
            passwordEncryptor.setPassword(pwCb.getPassword());
        }
    }

    /**
     * Encrypt the given password
     * @param password the password to be encrypted
     * @return the encrypted password
     */
    public String encrypt(String password) {
        return passwordEncryptor.encrypt(password);
    }
    
    /**
     * Decrypt the given encrypted password
     * @param encryptedPassword the encrypted password to decrypt
     * @return the decrypted password
     */
    public String decrypt(String encryptedPassword) {
        return passwordEncryptor.decrypt(encryptedPassword);
    }
    
}
