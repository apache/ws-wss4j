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
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSUsernameTokenPrincipal;
import org.apache.ws.security.cache.ReplayCache;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.validate.Credential;
import org.apache.ws.security.validate.Validator;
import java.util.Date;
import java.util.List;

import org.w3c.dom.Element;

public class UsernameTokenProcessor implements Processor {
    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(UsernameTokenProcessor.class);
    
    public List<WSSecurityEngineResult> handleToken(
        Element elem, 
        RequestData data,
        WSDocInfo wsDocInfo
    ) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found UsernameToken list element");
        }
        // See if the token has been previously processed
        String id = elem.getAttributeNS(WSConstants.WSU_NS, "Id");
        if (!"".equals(id)) {
            Element foundElement = wsDocInfo.getTokenElement(id);
            if (elem.equals(foundElement)) {
                WSSecurityEngineResult result = wsDocInfo.getResult(id);
                return java.util.Collections.singletonList(result);
            } else if (foundElement != null) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY_TOKEN, "duplicateError"
                );
            }
        }
        
        Validator validator = data.getValidator(WSSecurityEngine.USERNAME_TOKEN);
        Credential credential = handleUsernameToken(elem, validator, data);
        UsernameToken token = credential.getUsernametoken();
        
        int action = WSConstants.UT;
        byte[] secretKey = null;
        if (token.getPassword() == null) { 
            action = WSConstants.UT_NOPASSWORD;
            if (token.isDerivedKey()) {
                token.setRawPassword(data);
                secretKey = token.getDerivedKey();
            } 
        }
        WSSecurityEngineResult result = new WSSecurityEngineResult(action, token);
        result.put(WSSecurityEngineResult.TAG_ID, token.getID());
        result.put(WSSecurityEngineResult.TAG_SECRET, secretKey);
        
        if (validator != null) {
            result.put(WSSecurityEngineResult.TAG_VALIDATED_TOKEN, Boolean.TRUE);
            if (credential.getTransformedToken() != null) {
                result.put(
                    WSSecurityEngineResult.TAG_TRANSFORMED_TOKEN, credential.getTransformedToken()
                );
                if (credential.getPrincipal() != null) {
                    result.put(WSSecurityEngineResult.TAG_PRINCIPAL, credential.getPrincipal());
                } else {
                    SAMLTokenPrincipal samlPrincipal =
                        new SAMLTokenPrincipal(credential.getTransformedToken());
                    result.put(WSSecurityEngineResult.TAG_PRINCIPAL, samlPrincipal);
                }
            } else if (credential.getPrincipal() != null) {
                result.put(WSSecurityEngineResult.TAG_PRINCIPAL, credential.getPrincipal());
            } else {
                WSUsernameTokenPrincipal principal = 
                    new WSUsernameTokenPrincipal(token.getName(), token.isHashed());
                principal.setNonce(token.getNonce());
                principal.setPassword(token.getPassword());
                principal.setCreatedTime(token.getCreated());
                principal.setPasswordType(token.getPasswordType());
                result.put(WSSecurityEngineResult.TAG_PRINCIPAL, principal);
            }
            result.put(WSSecurityEngineResult.TAG_SUBJECT, credential.getSubject());
        }
        
        wsDocInfo.addTokenElement(elem);
        wsDocInfo.addResult(result);
        return java.util.Collections.singletonList(result);
    }

    /**
     * Check the UsernameToken element and validate it.
     *
     * @param token the DOM element that contains the UsernameToken
     * @param data The RequestData object from which to obtain configuration
     * @return a Credential object corresponding to the (validated) Username Token
     * @throws WSSecurityException
     */
    private Credential 
    handleUsernameToken(
        Element token, 
        Validator validator,
        RequestData data
    ) throws WSSecurityException {
        boolean allowNamespaceQualifiedPasswordTypes = false;
        boolean bspCompliant = true;
        WSSConfig wssConfig = data.getWssConfig();
        int utTTL = 300;
        int futureTimeToLive = 60;
        if (wssConfig != null) {
            allowNamespaceQualifiedPasswordTypes = 
                wssConfig.getAllowNamespaceQualifiedPasswordTypes();
            bspCompliant = wssConfig.isWsiBSPCompliant();
            utTTL = wssConfig.getUtTTL();
            futureTimeToLive = wssConfig.getUtFutureTTL();
        }
        
        //
        // Parse and validate the UsernameToken element
        //
        UsernameToken ut = 
            new UsernameToken(token, allowNamespaceQualifiedPasswordTypes, bspCompliant);
        
        // Test for replay attacks
        ReplayCache replayCache = data.getNonceReplayCache();
        if (replayCache != null && ut.getNonce() != null) {
            if (replayCache.contains(ut.getNonce())) {
                throw new WSSecurityException(
                    WSSecurityException.INVALID_SECURITY,
                    "badUsernameToken",
                    new Object[] {"A replay attack has been detected"}
                );
            }
            
            // If no Created, then just cache for the default time
            // Otherwise, cache for the configured TTL of the UsernameToken Created time, as any
            // older token will just get rejected anyway
            Date created = ut.getCreatedDate();
            if (created == null || utTTL <= 0) {
                replayCache.add(ut.getNonce());
            } else {
                replayCache.add(ut.getNonce(), utTTL + 1L);
            }
        }
        
        // Validate whether the security semantics have expired
        if (!ut.verifyCreated(utTTL, futureTimeToLive)) {
            throw new WSSecurityException(WSSecurityException.MESSAGE_EXPIRED);
        }
        
        Credential credential = new Credential();
        credential.setUsernametoken(ut);
        if (validator != null) {
            return validator.validate(credential, data);
        }
        return credential;
    }

}
