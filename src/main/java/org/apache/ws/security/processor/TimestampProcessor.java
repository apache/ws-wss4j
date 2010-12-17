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

package org.apache.ws.security.processor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.token.Timestamp;
import org.w3c.dom.Element;

import java.util.List;
import javax.security.auth.callback.CallbackHandler;

public class TimestampProcessor implements Processor {
    private static Log log = LogFactory.getLog(TimestampProcessor.class.getName());

    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        Crypto crypto, 
        Crypto decCrypto, 
        CallbackHandler cb, 
        WSDocInfo wsDocInfo, 
        WSSConfig wsc
    ) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found Timestamp list element");
        }
        //
        // Decode Timestamp, add the found time (created/expiry) to result
        //
        Timestamp timestamp = new Timestamp(elem);
        handleTimestamp(timestamp, wsc);
        WSSecurityEngineResult result = 
            new WSSecurityEngineResult(WSConstants.TS, timestamp);
        result.put(WSSecurityEngineResult.TAG_ID, timestamp.getID());
        wsDocInfo.addResult(result);
        return java.util.Collections.singletonList(result);
    }

    private void handleTimestamp(
        Timestamp timestamp, 
        WSSConfig wssConfig
    ) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Preparing to verify the timestamp");
        }

        // Validate whether the security semantics have expired
        if ((wssConfig.isTimeStampStrict() && timestamp.isExpired()) 
            || !timestamp.verifyCreated(wssConfig.getTimeStampTTL())) {
            throw new WSSecurityException(
                WSSecurityException.MESSAGE_EXPIRED,
                "invalidTimestamp",
                new Object[] {"The security semantics of the message have expired"}
            );
        }
    }
    
}
