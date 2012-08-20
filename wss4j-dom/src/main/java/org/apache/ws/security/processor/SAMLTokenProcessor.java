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

import org.apache.ws.security.SAMLTokenPrincipal;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.common.ext.WSSecurityException;
import org.apache.ws.security.common.saml.AssertionWrapper;
import org.apache.ws.security.common.util.DOM2Writer;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.saml.WSSSAMLKeyInfoProcessor;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.Validator;

import org.w3c.dom.Element;

import java.util.List;
import javax.xml.namespace.QName;

public class SAMLTokenProcessor implements Processor {
    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(SAMLTokenProcessor.class);
    
    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        RequestData data, 
        WSDocInfo wsDocInfo 
    ) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found SAML Assertion element");
        }
        
        Validator validator = 
            data.getValidator(new QName(elem.getNamespaceURI(), elem.getLocalName()));
        Credential credential = handleSAMLToken(elem, data, validator, wsDocInfo);
        AssertionWrapper assertion = credential.getAssertion();
        if (log.isDebugEnabled()) {
            log.debug("SAML Assertion issuer " + assertion.getIssuerString());
            log.debug(DOM2Writer.nodeToString(elem));
        }
        
        // See if the token has been previously processed
        String id = assertion.getId();
        Element foundElement = wsDocInfo.getTokenElement(id);
        if (elem.equals(foundElement)) {
            WSSecurityEngineResult result = wsDocInfo.getResult(id);
            return java.util.Collections.singletonList(result);
        } else if (foundElement != null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.INVALID_SECURITY_TOKEN, "duplicateError"
            );
        }

        wsDocInfo.addTokenElement(elem);
        WSSecurityEngineResult result = null;
        if (assertion.isSigned()) {
            result = new WSSecurityEngineResult(WSConstants.ST_SIGNED, assertion);
        } else {
            result = new WSSecurityEngineResult(WSConstants.ST_UNSIGNED, assertion);
        }
        
        result.put(WSSecurityEngineResult.TAG_ID, assertion.getId());

        if (validator != null) {
            result.put(WSSecurityEngineResult.TAG_VALIDATED_TOKEN, Boolean.TRUE);
            if (credential.getTransformedToken() != null) {
                result.put(
                    WSSecurityEngineResult.TAG_TRANSFORMED_TOKEN, credential.getTransformedToken()
                );
                SAMLTokenPrincipal samlPrincipal = 
                    new SAMLTokenPrincipal(credential.getTransformedToken());
                result.put(WSSecurityEngineResult.TAG_PRINCIPAL, samlPrincipal);
            } else if (credential.getPrincipal() != null) {
                result.put(WSSecurityEngineResult.TAG_PRINCIPAL, credential.getPrincipal());
            } else {
                result.put(WSSecurityEngineResult.TAG_PRINCIPAL, new SAMLTokenPrincipal(assertion));
            }
        }
        wsDocInfo.addResult(result);
        return java.util.Collections.singletonList(result);
    }

    public Credential handleSAMLToken(
        Element token, 
        RequestData data,
        Validator validator,
        WSDocInfo docInfo
    ) throws WSSecurityException {
        AssertionWrapper assertion = new AssertionWrapper(token);
        if (assertion.isSigned()) {
            assertion.verifySignature(
                new WSSSAMLKeyInfoProcessor(data, docInfo), data.getSigCrypto(),
                data.getWssConfig().isWsiBSPCompliant()
            );
        }
        // Parse the HOK subject if it exists
        assertion.parseHOKSubject( 
            new WSSSAMLKeyInfoProcessor(data, docInfo), data.getSigCrypto(), 
            data.getCallbackHandler(), data.getWssConfig().isWsiBSPCompliant()
        );
            
        // Now delegate the rest of the verification to the Validator
        Credential credential = new Credential();
        credential.setAssertion(assertion);
        if (validator != null) {
            return validator.validate(credential, data);
        }
        return credential;
    }

}
