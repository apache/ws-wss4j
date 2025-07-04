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

package org.apache.wss4j.dom.misc;

import java.security.Principal;


import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.principal.UsernameTokenPrincipal;
import org.apache.wss4j.common.util.SOAPUtil;
import org.apache.wss4j.common.util.XMLUtils;
import org.apache.wss4j.api.dom.WSConstants;

import org.apache.wss4j.dom.common.UsernamePasswordCallbackHandler;
import org.apache.wss4j.api.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.api.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.api.dom.RequestData;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.api.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.WSSecUsernameToken;
import org.apache.wss4j.api.dom.validate.Validator;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Test various principal objects after processing a security token.
 */
public class PrincipalTest {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(PrincipalTest.class);

    private CallbackHandler callbackHandler = new UsernamePasswordCallbackHandler();

    /**
     * Test the principal that is created after processing a Username Token
     */
    @Test
    public void testUsernameToken() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecUsernameToken builder = new WSSecUsernameToken(secHeader);
        builder.setUserInfo("wernerd", "verySecret");
        Document signedDoc = builder.build();

        if (LOG.isDebugEnabled()) {
            String outputString =
                XMLUtils.prettyDocumentToString(signedDoc);
            LOG.debug(outputString);
        }
        WSHandlerResult results = verify(signedDoc, null);

        Principal principal =
            (Principal)results.getResults().get(0).get(WSSecurityEngineResult.TAG_PRINCIPAL);
        assertTrue(principal instanceof UsernameTokenPrincipal);
        assertTrue("wernerd".equals(principal.getName()));
        UsernameTokenPrincipal userPrincipal = (UsernameTokenPrincipal)principal;
        assertNotNull(userPrincipal.getCreatedTime());
        assertNotNull(userPrincipal.getNonce());
        assertNotNull(userPrincipal.getPassword());
        assertTrue(userPrincipal.isPasswordDigest());
        assertTrue(WSConstants.PASSWORD_DIGEST.equals(userPrincipal.getPasswordType()));
    }

    /**
     * Verifies the soap envelope
     */
    private WSHandlerResult verify(
        Document doc,
        Crypto crypto
    ) throws Exception {
        return verify(doc, null, null, crypto);
    }

    /**
     * Verifies the soap envelope
     */
    private WSHandlerResult verify(
        Document doc,
        Validator validator,
        QName validatorName,
        Crypto crypto
    ) throws Exception {
        RequestData requestData = new RequestData();
        requestData.setCallbackHandler(callbackHandler);
        requestData.setDecCrypto(crypto);
        requestData.setSigVerCrypto(crypto);
        requestData.setValidateSamlSubjectConfirmation(false);

        WSSecurityEngine secEngine = new WSSecurityEngine();
        WSSConfig config = WSSConfig.getNewInstance();
        secEngine.setWssConfig(config);

        if (validator != null && validatorName != null) {
            config.setValidator(validatorName, validator);
        }
        return secEngine.processSecurityHeader(doc, requestData);
    }

}