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

package org.apache.ws.security.dom.str;

import java.util.List;

import org.apache.ws.security.dom.WSDocInfo;
import org.apache.ws.security.dom.WSSecurityEngine;
import org.apache.ws.security.dom.WSSecurityEngineResult;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.common.saml.AssertionWrapper;
import org.apache.ws.security.dom.handler.RequestData;
import org.apache.ws.security.dom.message.token.SecurityTokenReference;
import org.apache.ws.security.dom.processor.Processor;
import org.w3c.dom.Element;

/**
 * Some utilities for the STRParsers.
 */
public final class STRParserUtil {
    
    private STRParserUtil() {
        // complete
    }
    
    /**
     * Get an AssertionWrapper object from parsing a SecurityTokenReference that uses
     * a KeyIdentifier that points to a SAML Assertion.
     * 
     * @param secRef the SecurityTokenReference to the SAML Assertion
     * @param strElement The SecurityTokenReference DOM element
     * @param request The RequestData instance used to obtain configuration
     * @param wsDocInfo The WSDocInfo object that holds previous results
     * @return an AssertionWrapper object
     * @throws WSSecurityException
     */
    public static AssertionWrapper getAssertionFromKeyIdentifier(
        SecurityTokenReference secRef,
        Element strElement,
        RequestData request,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        String keyIdentifierValue = secRef.getKeyIdentifierValue();
        String type = secRef.getKeyIdentifierValueType();
        WSSecurityEngineResult result = wsDocInfo.getResult(keyIdentifierValue);

        AssertionWrapper assertion = null;
        Element token = null;
        if (result != null) {
            assertion = 
                (AssertionWrapper)result.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
            return assertion;
        } else {
            token = 
                secRef.findProcessedTokenElement(
                    strElement.getOwnerDocument(), wsDocInfo,
                    request.getCallbackHandler(),
                    keyIdentifierValue, type
                );
            if (token != null) {
                if (!"Assertion".equals(token.getLocalName())) {
                    throw new WSSecurityException(
                        WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity"
                    );
                }
                return new AssertionWrapper(token);
            }
            token = 
                secRef.findUnprocessedTokenElement(
                    strElement.getOwnerDocument(), wsDocInfo,
                    request.getCallbackHandler(), keyIdentifierValue, type
                );
            
            if (token == null || !"Assertion".equals(token.getLocalName())) {
                throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, "invalidSAMLsecurity"
                );
            }
            Processor proc = request.getWssConfig().getProcessor(WSSecurityEngine.SAML_TOKEN);
            List<WSSecurityEngineResult> samlResult =
                proc.handleToken(token, request, wsDocInfo);
            return 
                (AssertionWrapper)samlResult.get(0).get(
                    WSSecurityEngineResult.TAG_SAML_ASSERTION
                );
        }
    }
    
}
