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

package org.apache.wss4j.dom.validate;


import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.Timestamp;

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
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noCredential");
        }
        if (data.getWssConfig() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                                          new Object[] {"WSSConfig cannot be null"});
        }
        boolean timeStampStrict = data.isTimeStampStrict();
        int timeStampTTL = data.getTimeStampTTL();
        int futureTimeToLive = data.getTimeStampFutureTTL();

        Timestamp timeStamp = credential.getTimestamp();

        // See if the Timestamp has expired
        if (timeStampStrict && timeStamp.isExpired()) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.MESSAGE_EXPIRED,
                "invalidTimestamp",
                new Object[] {"The message timestamp has expired"});
        }

        // Validate the Created date
        if (!timeStamp.verifyCreated(timeStampTTL, futureTimeToLive)) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.MESSAGE_EXPIRED,
                "invalidTimestamp",
                new Object[] {"The message timestamp is out of range"});
        }

        if (data.isRequireTimestampExpires() && timeStamp.getExpires() == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.SECURITY_ERROR,
                "invalidTimestamp",
                new Object[] {"The received Timestamp does not contain an expires Element"});
        }
        return credential;
    }



}
