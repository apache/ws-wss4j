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

import java.util.Collections;
import java.util.List;

import javax.xml.namespace.QName;

import org.w3c.dom.Element;
import org.apache.wss4j.api.dom.WSConstants;
import org.apache.wss4j.api.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.common.crypto.AlgorithmSuite;
import org.apache.wss4j.common.crypto.AlgorithmSuiteValidator;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.api.dom.RequestData;
import org.apache.wss4j.api.dom.message.token.DerivedKeyToken;
import org.apache.wss4j.api.dom.processor.Processor;
import org.apache.wss4j.dom.str.DerivedKeyTokenSTRParser;
import org.apache.wss4j.dom.str.STRParser;
import org.apache.wss4j.dom.str.STRParserParameters;
import org.apache.wss4j.dom.str.STRParserResult;

/**
 * The processor to process <code>wsc:DerivedKeyToken</code>.
 */
public class DerivedKeyTokenProcessor implements Processor {

    public List<WSSecurityEngineResult> handleToken(
        Element elem,
        RequestData data
    ) throws WSSecurityException {
        // Deserialize the DKT
        DerivedKeyToken dkt = new DerivedKeyToken(elem, data.getBSPEnforcer());

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
            STRParserParameters parameters = new STRParserParameters();
            parameters.setData(data);
            parameters.setStrElement(secRefElement);

            STRParser strParser = new DerivedKeyTokenSTRParser();
            STRParserResult parserResult = strParser.parseSecurityTokenReference(parameters);
            secret = parserResult.getSecretKey();
        } else {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_CHECK, "noReference");
        }

        String tempNonce = dkt.getNonce();
        if (tempNonce == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                                          new Object[] {"Missing wsc:Nonce value"});
        }
        int length = dkt.getLength();
        byte[] keyBytes = dkt.deriveKey(length, secret);
        WSSecurityEngineResult result =
            new WSSecurityEngineResult(WSConstants.DKT, null, keyBytes, null);
        data.getWsDocInfo().addTokenElement(elem);
        String tokenId = dkt.getID();
        if (tokenId.length() != 0) {
            result.put(WSSecurityEngineResult.TAG_ID, tokenId);
        }
        result.put(WSSecurityEngineResult.TAG_DERIVED_KEY_TOKEN, dkt);
        result.put(WSSecurityEngineResult.TAG_SECRET, secret);
        result.put(WSSecurityEngineResult.TAG_TOKEN_ELEMENT, dkt.getElement());
        data.getWsDocInfo().addResult(result);
        return Collections.singletonList(result);
    }

    @Override
    public QName[] getSupportedQNames() {
        return new QName[]{WSConstants.DERIVED_KEY_TOKEN_05_02, WSConstants.DERIVED_KEY_TOKEN_05_12};
    }


}
