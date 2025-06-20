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

package org.apache.wss4j.dom.processor;

import java.util.List;

import javax.xml.namespace.QName;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.common.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.common.dom.RequestData;
import org.apache.wss4j.common.dom.message.token.Timestamp;
import org.apache.wss4j.common.dom.processor.Processor;
import org.apache.wss4j.common.dom.validate.Credential;
import org.apache.wss4j.common.dom.validate.Validator;
import org.w3c.dom.Element;

public class TimestampProcessor implements Processor {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(TimestampProcessor.class);

    public List<WSSecurityEngineResult> handleToken(
        Element elem,
        RequestData data
    ) throws WSSecurityException {
        LOG.debug("Found Timestamp list element");
        //
        // Decode Timestamp, add the found time (created/expiry) to result
        //
        Timestamp timestamp = new Timestamp(elem, data.getBSPEnforcer());
        Credential credential = new Credential();
        credential.setTimestamp(timestamp);

        WSSecurityEngineResult result = new WSSecurityEngineResult(WSConstants.TS);
        result.addTimestampResult(timestamp, timestamp.getElement());
        String tokenId = timestamp.getID();
        if (tokenId.length() != 0) {
            result.put(WSSecurityEngineResult.TAG_ID, tokenId);
        }

        Validator validator = data.getValidator(WSConstants.TIMESTAMP);
        if (validator != null) {
            validator.validate(credential, data);

            result.put(WSSecurityEngineResult.TAG_VALIDATED_TOKEN, Boolean.TRUE);
        }

        data.getWsDocInfo().addTokenElement(elem);
        data.getWsDocInfo().addResult(result);
        return java.util.Collections.singletonList(result);
    }

    @Override
    public QName[] getSupportedQNames() {
        return new QName[]{WSConstants.TIMESTAMP};
    }
}
