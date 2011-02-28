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

package org.apache.ws.security.validate;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.Timestamp;

/**
 * This class validates a processed Timestamp, extracted from the Credential passed to
 * the validate method.
 */
public class TimestampValidator implements Validator {
    
    private WSSConfig wssConfig;
    
    /**
     * Validate the credential argument. It must contain a non-null Timestamp.
     * 
     * @param credential the Credential to be validated
     * @throws WSSecurityException on a failed validation
     */
    public Credential validate(Credential credential) throws WSSecurityException {
        if (credential == null || credential.getTimestamp() == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCredential");
        }
        if (wssConfig == null) {
            throw new WSSecurityException("WSSConfig cannot be null");
        }
        
        boolean timeStampStrict = true;
        int timeStampTTL = 300;
        if (wssConfig != null) {
            timeStampStrict = wssConfig.isTimeStampStrict();
            timeStampTTL = wssConfig.getTimeStampTTL();
        }
        
        Timestamp timeStamp = credential.getTimestamp();
        // Validate whether the security semantics have expired
        if ((timeStampStrict && timeStamp.isExpired()) 
            || !timeStamp.verifyCreated(timeStampTTL)) {
            throw new WSSecurityException(
                WSSecurityException.MESSAGE_EXPIRED,
                "invalidTimestamp",
                new Object[] {"The security semantics of the message have expired"}
            );
        }
        return credential;
    }
    
    /**
     * Set a WSSConfig instance used to extract configured options used to 
     * validate credentials. This is optional for this implementation.
     * @param wssConfig a WSSConfig instance
     */
    public void setWSSConfig(WSSConfig wssConfig) {
        this.wssConfig = wssConfig;
    }
    
    /**
     * Set a Crypto instance used to validate credentials. This method is not currently
     * used for this implementation.
     * @param crypto a Crypto instance used to validate credentials
     */
    public void setCrypto(Crypto crypto) {
        //
    }
    
    /**
     * Set a CallbackHandler instance used to validate credentials. This method is not 
     * currently used for this implementation.
     * @param callbackHandler a CallbackHandler instance used to validate credentials
     */
    public void setCallbackHandler(CallbackHandler callbackHandler) {
        //
    }
   
}
