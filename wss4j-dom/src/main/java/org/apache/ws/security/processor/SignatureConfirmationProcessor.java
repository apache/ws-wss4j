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

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.SignatureConfirmation;
import org.w3c.dom.Element;

import java.util.List;

public class SignatureConfirmationProcessor implements Processor {
    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(SignatureConfirmationProcessor.class);
    
    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        RequestData data,
        WSDocInfo wsDocInfo 
    ) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found SignatureConfirmation list element");
        }
        //
        // Decode SignatureConfirmation, just store in result
        //
        SignatureConfirmation sigConf = new SignatureConfirmation(elem);
        String id = sigConf.getID();
        // A wsu:Id is required as per the BSP spec
        if (data.getWssConfig().isWsiBSPCompliant() && (id == null || "".equals(id))) {
            throw new WSSecurityException(
                WSSecurityException.INVALID_SECURITY, 
                "requiredElementNoID", 
                new Object[] {elem.getLocalName()}
            );
        }
        
        WSSecurityEngineResult result = 
            new WSSecurityEngineResult(WSConstants.SC, sigConf);
        result.put(WSSecurityEngineResult.TAG_ID, id);
        wsDocInfo.addResult(result);
        wsDocInfo.addTokenElement(elem);
        return java.util.Collections.singletonList(result);
    }
    
}
