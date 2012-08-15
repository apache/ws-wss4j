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

package org.apache.ws.security;

import org.w3c.dom.Element;

import org.apache.ws.security.handler.RequestData;

import javax.security.auth.callback.Callback;

/**
 * Simple class to provide a password callback mechanism.
 *
 * It uses the JAAS authentication mechanisms and callback methods.
 * In addition to the identifier (user name) this class also provides
 * information what type of information the callback <code>handle</code>
 * method shall provide.
 *
 * @author Werner Dittmann (Werner.Dittmann@siemens.com).
 */
public class WSPasswordCallback implements Callback {

    /**
     * An unknown usage. Never used by the WSS4J implementation and should be treated 
     * as an error.
     */
    public static final int UNKNOWN = 0;
    
    /**
     * DECRYPT usage is used when the calling code needs a password to get the private key of
     * this identifier (alias) from a keystore. This is only used for the inbound case of
     * decrypting a session (symmetric) key, and not for the case of getting a private key to
     * sign the message. The CallbackHandler must set the password via the setPassword(String) 
     * method.
     */
    public static final int DECRYPT = 1;
    
    /**
     * USERNAME_TOKEN usage is used to obtain a password for either creating a Username Token,
     * or for validating it. It is also used for the case of deriving a key from a Username Token.
     * The CallbackHandler must set the password via the setPassword(String) method.
     */
    public static final int USERNAME_TOKEN = 2;
    
    /**
     * SIGNATURE usage is used on the outbound side only, to get a password to get the private
     * key of this identifier (alias) from a keystore. The CallbackHandler must set the password 
     * via the setPassword(String) method.
     */
    public static final int SIGNATURE = 3;
    
    /**
     * This identifier is deprecated and not used any more.
     */
    @Deprecated
    public static final int KEY_NAME = 4;
    
    /**
     * This identifier is deprecated and not used any more.
     */
    @Deprecated
    public static final int USERNAME_TOKEN_UNKNOWN = 5;
    
    /**
     * SECURITY_CONTEXT_TOKEN usage is for the case of when we want the CallbackHandler to 
     * supply the key associated with a SecurityContextToken. The CallbackHandler must set 
     * the key via the setKey(byte[]) method.
     */
    public static final int SECURITY_CONTEXT_TOKEN = 6;
    
    /**
     * CUSTOM_TOKEN usage is used for the case that we want the CallbackHandler to supply a
     * token as a DOM Element. For example, this is used for the case of a reference to a 
     * SAML Assertion or Security Context Token that is not in the message. The CallbackHandler 
     * must set the token via the setCustomToken(Element) method.
     */
    public static final int CUSTOM_TOKEN = 7;
    
    /**
     * This identifier is deprecated and not used any more.
     */
    @Deprecated
    public static final int ENCRYPTED_KEY_TOKEN = 8;
    
    /**
     * SECRET_KEY usage is used for the case that we want to obtain a secret key for encryption
     * or signature on the outbound side, or for decryption or verification on the inbound side.
     * The CallbackHandler must set the key via the setKey(byte[]) method.
     */
    public static final int SECRET_KEY = 9;
    
    private String identifier;
    private String password;
    private byte[] key;
    private int usage;
    private String type;
    private Element customToken;
    private RequestData data;
    
    /**
     * Constructor.
     *
     * @param id The application called back must supply the password for
     *           this identifier.
     */
    public WSPasswordCallback(String id, int usage) {
        this(id, null, null, usage, null);
    }
    /**
     * Constructor.
     *
     * @param id The application called back must supply the password for
     *           this identifier.
     */
    public WSPasswordCallback(String id, String pw, String type, int usage) {
        identifier = id;
        password = pw;
        this.type = type;
        this.usage = usage;
    }
    /**
     * Constructor.
     *
     * @param id The application called back must supply the password for
     *           this identifier.
     */
    public WSPasswordCallback(String id, String pw, String type, int usage, RequestData data) {
        identifier = id;
        password = pw;
        this.type = type;
        this.usage = usage;
        this.data = data;
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
    public int getUsage() {
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
    
    
    /**
     * Returns the RequestData associated with the request
     * @return the RequestData associated with the request
     */
    public RequestData getRequestData() {
        return data;
    }
}


