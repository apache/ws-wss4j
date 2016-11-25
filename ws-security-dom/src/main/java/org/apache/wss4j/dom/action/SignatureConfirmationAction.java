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

package org.apache.wss4j.dom.action;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.common.SecurityActionToken;
import org.apache.wss4j.common.SignatureActionToken;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.handler.WSHandler;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecSignatureConfirmation;
import org.w3c.dom.Document;

import java.util.List;

public class SignatureConfirmationAction implements Action {
    private static final org.slf4j.Logger LOG =
        org.slf4j.LoggerFactory.getLogger(SignatureConfirmationAction.class);

    @SuppressWarnings("unchecked")
    public void execute(WSHandler handler, SecurityActionToken actionToken,
                        Document doc, RequestData reqData)
            throws WSSecurityException {
        if (LOG.isDebugEnabled()) {
            LOG.debug("Perform Signature confirmation");
        }

        List<WSHandlerResult> results =
            (List<WSHandlerResult>) handler.getProperty(
                reqData.getMsgContext(), WSHandlerConstants.RECV_RESULTS
            );
        if (results == null || results.isEmpty()) {
            return;
        }

        //
        // prepare a SignatureConfirmation token
        //
        WSSecSignatureConfirmation wsc = new WSSecSignatureConfirmation(reqData.getSecHeader());
        wsc.setIdAllocator(reqData.getWssConfig().getIdAllocator());
        SignatureActionToken signatureToken = (SignatureActionToken)actionToken;
        if (signatureToken == null) {
            signatureToken = reqData.getSignatureToken();
        }
        List<WSEncryptionPart> signatureParts = signatureToken.getParts();

        //
        // Loop over all the (signature) results gathered by all the processors
        //
        boolean signatureAdded = false;
        for (WSHandlerResult wshResult : results) {
            List<WSSecurityEngineResult> resultList = wshResult.getResults();

            for (WSSecurityEngineResult result : resultList) {
                Integer resultAction = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);

                // See if it's a signature action
                if (resultAction != null
                    && (WSConstants.SIGN == resultAction.intValue()
                        || WSConstants.ST_SIGNED == resultAction.intValue()
                        || WSConstants.UT_SIGN == resultAction.intValue())) {
                    byte[] sigVal = (byte[]) result.get(WSSecurityEngineResult.TAG_SIGNATURE_VALUE);
                    wsc.build(doc, sigVal);
                    signatureParts.add(new WSEncryptionPart(wsc.getId()));
                    signatureAdded = true;
                }
            }
        }

        if (!signatureAdded) {
            wsc.build(doc, null);
            signatureParts.add(new WSEncryptionPart(wsc.getId()));
        }
        handler.setProperty(
            reqData.getMsgContext(), WSHandlerConstants.SIG_CONF_DONE, ""
        );
    }

}
