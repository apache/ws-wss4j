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

import org.apache.wss4j.common.dom.WSConstants;
import org.apache.wss4j.common.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.dom.RequestData;
import org.apache.wss4j.common.dom.message.token.SignatureConfirmation;
import org.apache.wss4j.common.dom.processor.Processor;
import org.w3c.dom.Element;

import java.util.List;

import javax.xml.namespace.QName;

public class SignatureConfirmationProcessor implements Processor {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SignatureConfirmationProcessor.class);

    public List<WSSecurityEngineResult> handleToken(
        Element elem,
        RequestData data
    ) throws WSSecurityException {
        LOG.debug("Found SignatureConfirmation list element");
        //
        // Decode SignatureConfirmation, just store in result
        //
        SignatureConfirmation sigConf = new SignatureConfirmation(elem, data.getBSPEnforcer());

        WSSecurityEngineResult result = new WSSecurityEngineResult(WSConstants.SC);
        result.addSignatureConfirmationResult(sigConf, sigConf.getElement());
        String tokenId = sigConf.getID();
        if (tokenId.length() != 0) {
            result.put(WSSecurityEngineResult.TAG_ID, tokenId);
        }
        data.getWsDocInfo().addResult(result);
        data.getWsDocInfo().addTokenElement(elem);
        return java.util.Collections.singletonList(result);
    }

    @Override
    public QName[] getSupportedQNames() {
        return new QName[]{WSConstants.SIGNATURE_CONFIRMATION};
    }

}
