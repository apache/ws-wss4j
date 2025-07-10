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
import org.apache.wss4j.api.dom.action.SignatureActionToken;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.saml.SamlAssertionWrapper;
import org.apache.wss4j.dom.saml.SAMLCallback;
import org.apache.wss4j.dom.saml.SAMLUtil;
import org.apache.wss4j.api.dom.WSConstants;
import org.apache.wss4j.api.dom.RequestData;
import org.apache.wss4j.api.dom.action.Action;
import org.apache.wss4j.dom.saml.message.WSSecSignatureSAML;
import org.apache.wss4j.api.dom.action.ActionUtils;

public class SAMLTokenSignedAction implements Action {

    public void execute(SecurityActionToken actionToken, RequestData reqData)
            throws WSSecurityException {

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
                samlCallback.getSignatureAlgorithm(),
                samlCallback.getSignatureDigestAlgorithm()
            );
        }
        WSSecSignatureSAML wsSign = new WSSecSignatureSAML(reqData.getSecHeader());
        wsSign.setIdAllocator(reqData.getWssConfig().getIdAllocator());
        wsSign.setAddInclusivePrefixes(reqData.isAddInclusivePrefixes());
        wsSign.setWsDocInfo(reqData.getWsDocInfo());
        wsSign.setExpandXopInclude(reqData.isExpandXopInclude());
        wsSign.setSignatureProvider(reqData.getSignatureProvider());

        CallbackHandler callbackHandler = reqData.getCallbackHandler();

        SignatureActionToken signatureToken = reqData.getSignatureToken();
        WSPasswordCallback pwCb = ActionUtils.constructPasswordCallback(signatureToken.getUser(), WSConstants.ST_SIGNED);
        ActionUtils.performPasswordCallback(callbackHandler, pwCb, reqData);

        wsSign.setUserInfo(signatureToken.getUser(), pwCb.getPassword());

        if (signatureToken.getKeyIdentifierId() != 0) {
            wsSign.setKeyIdentifierType(signatureToken.getKeyIdentifierId());
        }
        if (signatureToken.getSignatureAlgorithm() != null) {
            wsSign.setSignatureAlgorithm(signatureToken.getSignatureAlgorithm());
        }
        if (signatureToken.getDigestAlgorithm() != null) {
            wsSign.setDigestAlgo(signatureToken.getDigestAlgorithm());
        }
        if (signatureToken.getC14nAlgorithm() != null) {
            wsSign.setSigCanonicalization(signatureToken.getC14nAlgorithm());
        }
        if (signatureToken.getKeyInfoElement() != null) {
            wsSign.setCustomKeyInfoElement(signatureToken.getKeyInfoElement());
        }

        if (!signatureToken.getParts().isEmpty()) {
            wsSign.getParts().addAll(signatureToken.getParts());
        }

        try {
            wsSign.build(
                    actionToken.getCrypto(),
                    samlAssertion,
                    samlCallback.getIssuerCrypto(),
                    samlCallback.getIssuerKeyName(),
                    samlCallback.getIssuerKeyPassword());

            reqData.getSignatureValues().add(wsSign.getSignatureValue());
            byte[] signatureValue = samlAssertion.getSignatureValue();
            if (signatureValue != null) {
                reqData.getSignatureValues().add(signatureValue);
            }
        } catch (WSSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e, "empty",
                                          new Object[] {"Error when signing the SAML token: "});
        }
    }

    @Override
    public Integer[] getSupportedActions() {
        return new Integer[]{WSConstants.ST_SIGNED};
    }

}
