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


/**
 * This interface describes a way to encrypt and decrypt passwords. It allows a way to store
 * encrypted keystore passwords in Merlin Crypto properties file, that can be decrypted before
 * loading the keystore, etc.
 */
public interface PasswordEncryptor {

    /**
     * Encrypt the given password
     * @param password the password to be encrypted
     * @return the encrypted password
     */
    String encrypt(String password);
    
    /**
     * Decrypt the given encrypted password
     * @param encryptedPassword the encrypted password to decrypt
     * @return the decrypted password
     */
    String decrypt(String encryptedPassword);
    
}
