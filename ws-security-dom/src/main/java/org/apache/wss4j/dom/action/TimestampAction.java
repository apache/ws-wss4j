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

package org.apache.wss4j.dom.action;

import org.apache.wss4j.common.SecurityActionToken;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.api.dom.WSConstants;
import org.apache.wss4j.api.dom.RequestData;
import org.apache.wss4j.api.dom.action.Action;
import org.apache.wss4j.dom.message.WSSecTimestamp;

public class TimestampAction implements Action {

    public void execute(SecurityActionToken actionToken, RequestData reqData)
        throws WSSecurityException {
        //
        // add the Timestamp to the SOAP Envelope
        //
        WSSecTimestamp timeStampBuilder = new WSSecTimestamp(reqData.getSecHeader());
        timeStampBuilder.setIdAllocator(reqData.getWssConfig().getIdAllocator());
        timeStampBuilder.setPrecisionInMilliSeconds(reqData.isPrecisionInMilliSeconds());
        timeStampBuilder.setTimeToLive(reqData.getTimeStampTTL());
        timeStampBuilder.setWsTimeSource(reqData.getWssConfig().getCurrentTime());
        timeStampBuilder.setWsDocInfo(reqData.getWsDocInfo());
        timeStampBuilder.setExpandXopInclude(reqData.isExpandXopInclude());
        timeStampBuilder.build();
    }

    @Override
    public Integer[] getSupportedActions() {
        return new Integer[]{WSConstants.TS};
    }
}
