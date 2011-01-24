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
 * This interface describes a pluggable way of validating credentials that have been extracted
 * by the processors.
 */
public class TimestampValidator implements Validator {
    
    private WSSConfig wssConfig;
    
    public void validate(Credential credential) throws WSSecurityException {
        if (credential == null) {
            throw new WSSecurityException("Credential cannot be null");
        }
        Timestamp timeStamp = credential.getTimestamp();
        if (timeStamp == null) {
            throw new WSSecurityException(WSSecurityException.MESSAGE_EXPIRED, "invalidTimestamp");
        }
        if (wssConfig == null) {
            throw new WSSecurityException("WSSConfig cannot be null");
        }
        
        // Validate whether the security semantics have expired
        if ((wssConfig.isTimeStampStrict() && timeStamp.isExpired()) 
            || !timeStamp.verifyCreated(wssConfig.getTimeStampTTL())) {
            throw new WSSecurityException(
                WSSecurityException.MESSAGE_EXPIRED,
                "invalidTimestamp",
                new Object[] {"The security semantics of the message have expired"}
            );
        }
    }
    
    public void setWSSConfig(WSSConfig wssConfig) {
        this.wssConfig = wssConfig;
    }
    
    public void setCrypto(Crypto crypto) {
        //
    }
    
    public void setCallbackHandler(CallbackHandler callbackHandler) {
        //
    }
   
}
