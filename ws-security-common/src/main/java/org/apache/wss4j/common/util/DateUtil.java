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

package org.apache.wss4j.common.util;

import java.time.Instant;
import java.time.format.DateTimeFormatter;

public final class DateUtil {

    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(DateUtil.class);

    private static final DateTimeFormatter MILLISECOND_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");

    private static final DateTimeFormatter SECOND_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss'Z'");

    private DateUtil() {
        // complete
    }

    /**
     * Return true if the "Created" value is before the current time minus the timeToLive
     * argument, and if the Created value is not "in the future".
     *
     * @param timeToLive the value in seconds for the validity of the Created time
     * @param futureTimeToLive the value in seconds for the future validity of the Created time
     * @return true if the Date is before (now-timeToLive), false otherwise
     */
    public static boolean verifyCreated(
        Instant created,
        int timeToLive,
        int futureTimeToLive
    ) {
        if (created == null) {
            return true;
        }

        Instant validCreation = Instant.now();
        if (futureTimeToLive > 0) {
            validCreation = validCreation.plusSeconds(futureTimeToLive);
        }
        // Check to see if the created time is in the future
        if (created.isAfter(validCreation)) {
            LOG.warn("Validation of Created: The message was created in the future!");
            return false;
        }

        // Calculate the time that is allowed for the message to travel
        validCreation = Instant.now().minusSeconds(timeToLive);

        // Validate the time it took the message to travel
        if (created.isBefore(validCreation)) {
            LOG.warn("Validation of Created: The message was created too long ago");
            return false;
        }

        LOG.debug("Validation of Created: Everything is ok");
        return true;
    }

    /**
     * Return how long the replay cache entry for a message with the given Timestamp must be kept,
     * which is for as long as the Timestamp may still be accepted: the later of the Expires value
     * and Created + timeToLive. verifyCreated accepts the message until Created + timeToLive,
     * which can be after the Expires value if the Expires value is not enforced (a non-strict
     * Timestamp check), and after the current time + timeToLive, as the Created value may be in
     * the future, within the future time to live.
     *
     * @param created the Created value of the Timestamp, can be null
     * @param expires the Expires value of the Timestamp, can be null
     * @param timeToLive the value in seconds for the validity of the Created time
     * @return the expiry of the replay cache entry, or null if the Timestamp does not bound it
     */
    public static Instant getTimestampReplayExpiry(Instant created, Instant expires, int timeToLive) {
        if (created == null) {
            return expires;
        }
        Instant createdExpiry = created.plusSeconds(timeToLive);
        if (expires != null && expires.isAfter(createdExpiry)) {
            return expires;
        }
        return createdExpiry;
    }

    public static DateTimeFormatter getDateTimeFormatter(boolean milliseconds) {
        if (milliseconds) {
            return MILLISECOND_FORMATTER;
        }
        return SECOND_FORMATTER;
    }
}
