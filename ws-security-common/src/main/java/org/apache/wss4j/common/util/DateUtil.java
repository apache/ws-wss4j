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

import java.util.Date;

public final class DateUtil {
    private static final org.slf4j.Logger LOG =
            org.slf4j.LoggerFactory.getLogger(DateUtil.class);

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
        Date createdDate,
        int timeToLive,
        int futureTimeToLive
    ) {
        if (createdDate == null) {
            return true;
        }

        Date validCreation = new Date();
        long currentTime = validCreation.getTime();
        if (futureTimeToLive > 0) {
            validCreation.setTime(currentTime + (long)futureTimeToLive * 1000L);
        }
        // Check to see if the created time is in the future
        if (createdDate.after(validCreation)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Validation of Created: The message was created in the future!");
            }
            return false;
        }

        // Calculate the time that is allowed for the message to travel
        currentTime -= (long)timeToLive * 1000L;
        validCreation.setTime(currentTime);

        // Validate the time it took the message to travel
        if (createdDate.before(validCreation)) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Validation of Created: The message was created too long ago");
            }
            return false;
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Validation of Created: Everything is ok");
        }
        return true;
    }

}
