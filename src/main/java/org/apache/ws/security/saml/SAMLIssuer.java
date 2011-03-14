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

package org.apache.ws.security.saml;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.saml.ext.AssertionWrapper;

/**
 * Builds a WS SAML Assertion and inserts it into the SOAP Envelope.
 * Refer to the WS specification, SAML Token profile
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 */
public interface SAMLIssuer {

    /**
     * Creates a new <code>AssertionWrapper</code>.
     * 
     * A complete <code>AssertionWrapper</code> is constructed.
     *
     * @return AssertionWrapper
     * @throws WSSecurityException
     */
    public AssertionWrapper newAssertion() throws WSSecurityException;
    
    /**
     * Set whether to send the key value or whether to include the entire cert.
     * @param sendKeyValue whether to send the key value.
     */
    public void setSendKeyValue(boolean sendKeyValue);
    
    /**
     * Get whether to send the key value or whether to include the entire cert.
     * @return whether to send the key value
     */
    public boolean isSendKeyValue();
    
    /**
     * Set whether to sign the assertion or not.
     * @param signAssertion whether to sign the assertion or not.
     */
    public void setSignAssertion(boolean signAssertion);
    
    /**
     * Get whether to sign the assertion or not
     * @return whether to sign the assertion or not
     */
    public boolean isSignAssertion();
    
    /**
     * Set the CallbackHandler to use
     * @param callbackHandler the CallbackHandler to use
     */
    public void setCallbackHandler(CallbackHandler callbackHandler);
    
    /**
     * Get the CallbackHandler in use
     * @return the CallbackHandler in use
     */
    public CallbackHandler getCallbackHandler();
    
    /**
     * Set the issuer crypto
     * @param issuerCrypto the issuer crypto
     */
    public void setIssuerCrypto(Crypto issuerCrypto);

    /**
     * @return Returns the issuerCrypto.
     */
    public Crypto getIssuerCrypto();
    
    /**
     * Set the issuer name
     * @param issuer the issuer name
     */
    public void setIssuerName(String issuer);
    
    /**
     * Get the issuer name
     * @return the issuer name
     */
    public String getIssuerName();
    
    /**
     * Set the issuer key name
     * @param issuerKeyName the issuer key name
     */
    public void setIssuerKeyName(String issuerKeyName);

    /**
     * @return Returns the issuerKeyName.
     */
    public String getIssuerKeyName();

    /**
     * Set the issuer key password
     * @param issuerKeyPassword the issuerKeyPassword.
     */
    public void setIssuerKeyPassword(String issuerKeyPassword);
    
    /**
     * @return Returns the issuerKeyPassword.
     */
    public String getIssuerKeyPassword();

}
