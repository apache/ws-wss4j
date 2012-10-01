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

import java.util.List;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.AlgorithmSuite;
import org.apache.ws.security.components.crypto.AlgorithmSuiteValidator;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.DerivedKeyToken;
import org.apache.ws.security.str.DerivedKeyTokenSTRParser;
import org.apache.ws.security.str.STRParser;
import org.w3c.dom.Element;

/**
 * The processor to process <code>wsc:DerivedKeyToken</code>.
 * 
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class DerivedKeyTokenProcessor implements Processor {
    
    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        RequestData data, 
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        // Deserialize the DKT
        DerivedKeyToken dkt = new DerivedKeyToken(elem, data.getWssConfig().isWsiBSPCompliant());
        
        // Check for compliance against the defined AlgorithmSuite
        AlgorithmSuite algorithmSuite = data.getAlgorithmSuite();
        if (algorithmSuite != null) {
            AlgorithmSuiteValidator algorithmSuiteValidator = new
                AlgorithmSuiteValidator(algorithmSuite);
            algorithmSuiteValidator.checkDerivedKeyAlgorithm(
                dkt.getAlgorithm()
            );
        }
        
        byte[] secret = null;
        Element secRefElement = dkt.getSecurityTokenReferenceElement();
        if (secRefElement != null) {
            STRParser strParser = new DerivedKeyTokenSTRParser();
            strParser.parseSecurityTokenReference(
                secRefElement, data, wsDocInfo, null
            );
            secret = strParser.getSecretKey();
        } else {
            throw new WSSecurityException(WSSecurityException.FAILED_CHECK, "noReference");
        }
        
        String tempNonce = dkt.getNonce();
        if (tempNonce == null) {
            throw new WSSecurityException("Missing wsc:Nonce value");
        }
        int length = dkt.getLength();
        byte[] keyBytes = dkt.deriveKey(length, secret);
        WSSecurityEngineResult result =
            new WSSecurityEngineResult(WSConstants.DKT, null, keyBytes, null);
        wsDocInfo.addTokenElement(elem);
        result.put(WSSecurityEngineResult.TAG_ID, dkt.getID());
        result.put(WSSecurityEngineResult.TAG_DERIVED_KEY_TOKEN, dkt);
        result.put(WSSecurityEngineResult.TAG_SECRET, secret);
        result.put(WSSecurityEngineResult.TAG_TOKEN_ELEMENT, dkt.getElement());
        wsDocInfo.addResult(result);
        return java.util.Collections.singletonList(result);
    }


}
