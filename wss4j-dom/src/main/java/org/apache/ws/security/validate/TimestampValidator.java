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


import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.Timestamp;

/**
 * This class validates a processed Timestamp, extracted from the Credential passed to
 * the validate method.
 */
public class TimestampValidator implements Validator {
    
    /**
     * Validate the credential argument. It must contain a non-null Timestamp.
     * 
     * @param credential the Credential to be validated
     * @param data the RequestData associated with the request
     * @throws WSSecurityException on a failed validation
     */
    public Credential validate(Credential credential, RequestData data) throws WSSecurityException {
        if (credential == null || credential.getTimestamp() == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE, "noCredential");
        }
        if (data.getWssConfig() == null) {
            throw new WSSecurityException("WSSConfig cannot be null");
        }
        WSSConfig wssConfig = data.getWssConfig();
        boolean timeStampStrict = true;
        int timeStampTTL = 300;
        int futureTimeToLive = 60;
        if (wssConfig != null) {
            timeStampStrict = wssConfig.isTimeStampStrict();
            timeStampTTL = wssConfig.getTimeStampTTL();
            futureTimeToLive = wssConfig.getTimeStampFutureTTL();
        }
        
        Timestamp timeStamp = credential.getTimestamp();
        // Validate whether the security semantics have expired
        if ((timeStampStrict && timeStamp.isExpired()) 
            || !timeStamp.verifyCreated(timeStampTTL, futureTimeToLive)) {
            throw new WSSecurityException(
                WSSecurityException.MESSAGE_EXPIRED,
                "invalidTimestamp",
                new Object[] {"The security semantics of the message have expired"}
            );
        }
        return credential;
    }
    

   
}
