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

package org.apache.wss4j.dom.saml.action;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.api.dom.action.SecurityActionToken;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.saml.SAMLCallback;
import org.apache.wss4j.dom.saml.SAMLUtil;
import org.apache.wss4j.api.dom.WSConstants;
import org.apache.wss4j.api.dom.RequestData;
import org.apache.wss4j.api.dom.action.Action;
import org.apache.wss4j.dom.saml.message.WSSecSAMLToken;

public class SAMLTokenUnsignedAction implements Action {

    public void execute(SecurityActionToken actionToken, RequestData reqData)
            throws WSSecurityException {
        WSSecSAMLToken builder = new WSSecSAMLToken(reqData.getSecHeader());
        builder.setIdAllocator(reqData.getWssConfig().getIdAllocator());
        builder.setWsDocInfo(reqData.getWsDocInfo());
        builder.setExpandXopInclude(reqData.isExpandXopInclude());

        CallbackHandler samlCallbackHandler = reqData.getSamlCallbackHandler();
        if (samlCallbackHandler == null) {
            throw new WSSecurityException(
                WSSecurityException.ErrorCode.FAILURE,
                "noSAMLCallbackHandler"
            );
        }
        SAMLCallback samlCallback = new SAMLCallback();
        SAMLUtil.doSAMLCallback(samlCallbackHandler, samlCallback);

        SamlAssertionWrapper samlAssertion = new SamlAssertionWrapper(samlCallback);
        if (samlCallback.isSignAssertion()) {
            samlAssertion.signAssertion(
                samlCallback.getIssuerKeyName(),
                samlCallback.getIssuerKeyPassword(),
                samlCallback.getIssuerCrypto(),
                samlCallback.isSendKeyValue(),
                samlCallback.getCanonicalizationAlgorithm(),
                samlCallback.getSignatureAlgorithm()
            );
        }

        // add the SAMLAssertion Token to the SOAP Envelope
        builder.build(samlAssertion);

        byte[] signatureValue = samlAssertion.getSignatureValue();
        if (signatureValue != null) {
            reqData.getSignatureValues().add(signatureValue);
        }
    }

    @Override
    public Integer[] getSupportedActions() {
        return new Integer[]{WSConstants.ST_UNSIGNED};
    }
}
