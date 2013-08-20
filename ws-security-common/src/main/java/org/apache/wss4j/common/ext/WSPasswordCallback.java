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

package org.apache.wss4j.common.ext;

import org.w3c.dom.Element;

import javax.security.auth.callback.Callback;

/**
 * Simple class to provide a password callback mechanism.
 * <p/>
 * It uses the JAAS authentication mechanisms and callback methods.
 * In addition to the identifier (user name) this class also provides
 * information what type of information the callback <code>handle</code>
 * method shall provide.
 * <p/>
 * The <code> WSPasswordCallback</code> class defines the following usage
 * codes:
 * <ul>
 * <li><code>UNKNOWN</code> - an unknown usage. Never used by the WSS4J
 * implementation and shall be treated as an error by the <code>handle
 * </code> method.</li>
 * <li><code>DECRYPT</code> - need a password to get the private key of
 * this identifier (username) from the keystore. WSS4J uses this private
 * key to decrypt the session (symmetric) key. Because the encryption
 * method uses the public key to encrypt the session key it needs no
 * password (a public key is usually not protected by a password).</li>
 * <li><code>USERNAME_TOKEN</code> - need the password to fill in or to
 * verify a <code>UsernameToken</code>.</li>
 * <li><code>SIGNATURE</code> - need the password to get the private key of
 * this identifier (username) from the keystore. WSS4J uses this private
 * key to produce a signature. The signature verification uses the public
 * key to verify the signature.</li>
 * <li><code>SECURITY_CONTEXT_TOKEN</code> - need the key to to be associated
 * with a <code>wsc:SecurityContextToken</code>.</li>
 * <li><code>PASSWORD_ENCRYPTOR_PASSWORD</code> - return the password used with a 
 * PasswordEncryptor implementation to decrypt encrypted passwords stored in
 * Crypto properties files</li>
 * </ul>
 */

public class WSPasswordCallback implements Callback {

    public enum Usage {
        UNKNOWN,
        DECRYPT,
        USERNAME_TOKEN,
        SIGNATURE,
        SECURITY_CONTEXT_TOKEN,
        CUSTOM_TOKEN,
        ENCRYPTED_KEY_TOKEN,
        SECRET_KEY,
        PASSWORD_ENCRYPTOR_PASSWORD
    }

    private String identifier;
    private String password;
    private byte[] key;
    private Usage usage;
    private String type;
    private Element customToken;
    
    /**
     * Constructor.
     *
     * @param id The application called back must supply the password for
     *           this identifier.
     */
    public WSPasswordCallback(String id, Usage usage) {
        this(id, null, null, usage);
    }
    
    /**
     * Constructor.
     *
     * @param id The application called back must supply the password for
     *           this identifier.
     */
    public WSPasswordCallback(String id, String pw, String type, Usage usage) {
        identifier = id;
        password = pw;
        this.type = type;
        this.usage = usage;
    }
    
    /**
     * Get the identifier.
     * <p/>
     *
     * @return The identifier
     */
    public String getIdentifier() {
        return identifier;
    }
    
    /**
     * Set the identifier
     * @param ident The identity.
     */
    public void setIdentifier(String ident) {
        this.identifier = ident;
    }

    /**
     * Set the password.
     * <p/>
     *
     * @param passwd is the password associated to the identifier
     */
    public void setPassword(String passwd) {
        password = passwd;
    }

    /**
     * Get the password.
     * <p/>
     *
     * @return The password
     */
    public String getPassword() {
        return password;
    }

    /**
     * Set the Key.
     * <p/>
     *
     * @param key is the key associated to the identifier
     */
    public void setKey(byte[] key) {
        this.key = key;
    }

    /**
     * Get the key.
     * <p/>
     *
     * @return The key
     */
    public byte[] getKey() {
        return this.key;
    }

    /**
     * Get the usage.
     * <p/>
     *
     * @return The usage for this callback
     */
    public Usage getUsage() {
        return usage;
    }
    
    /**
     * @return Returns the type.
     */
    public String getType() {
        return type;
    }

    /**
     * 
     * @return the custom token
     */
    public Element getCustomToken() {
        return customToken;
    }

    /**
     * Set the custom token
     * @param customToken
     */
    public void setCustomToken(Element customToken) {
        this.customToken = customToken;
    }
    
}