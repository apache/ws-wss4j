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
package org.apache.wss4j.stax.validate;

import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeParseException;

import org.apache.wss4j.binding.wsu10.TimestampType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.DateUtil;

public class TimestampValidatorImpl implements TimestampValidator {

    private static final transient org.slf4j.Logger LOG = org.slf4j.LoggerFactory.getLogger(TimestampValidatorImpl.class);

    @Override
    public void validate(TimestampType timestampType, TokenContext tokenContext) throws WSSecurityException {

        if (timestampType.getCreated() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "missingCreated");
        }

        try {
            // Validate whether the security semantics have expired
            //created and expires is optional per spec. But we enforce the created element in the validation
            ZonedDateTime createdDate = null;
            if (timestampType.getCreated() != null) {
                try {
                    createdDate = ZonedDateTime.parse(timestampType.getCreated().getValue());
                } catch (DateTimeParseException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
                }
                LOG.debug("Timestamp created: {}", createdDate.toString());
            }

            ZonedDateTime expiresDate = null;
            if (timestampType.getExpires() != null) {
                try {
                    expiresDate = ZonedDateTime.parse(timestampType.getExpires().getValue());
                } catch (DateTimeParseException e) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
                }
                LOG.debug("Timestamp expires: {}", expiresDate.toString());
            } else if (tokenContext.getWssSecurityProperties().isRequireTimestampExpires()) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "invalidTimestamp",
                                              new Object[] {"The received Timestamp does not contain an expires Element"});
            }

            int ttl = tokenContext.getWssSecurityProperties().getTimestampTTL();
            int futureTTL = tokenContext.getWssSecurityProperties().getTimeStampFutureTTL();

            Instant rightNow = Instant.now();
            if (expiresDate != null && tokenContext.getWssSecurityProperties().isStrictTimestampCheck()
                && expiresDate.toInstant().isBefore(rightNow)) {
                LOG.debug("Time now: {}", rightNow.toString());
                throw new WSSecurityException(WSSecurityException.ErrorCode.MESSAGE_EXPIRED, "invalidTimestamp",
                                              new Object[] {"The security semantics of the message have expired"});
            }

            if (createdDate != null && !DateUtil.verifyCreated(createdDate.toInstant(), ttl, futureTTL)) {
                LOG.debug("Time now: {}", rightNow.toString());
                throw new WSSecurityException(WSSecurityException.ErrorCode.MESSAGE_EXPIRED, "invalidTimestamp",
                                              new Object[] {"The security semantics of the message have expired"});
            }

        } catch (IllegalArgumentException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, e);
        }
    }

}
