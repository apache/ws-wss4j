/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.security.action;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.saml.SAMLIssuer;
import org.apache.ws.security.saml.SAMLIssuerFactory;
import org.apache.ws.security.saml.WSSecSignatureSAML;
import org.opensaml.SAMLAssertion;
import org.w3c.dom.Document;

public class SAMLTokenSignedAction implements Action {
    private static Log log = LogFactory.getLog(SAMLTokenSignedAction.class.getName());

    public void execute(WSHandler handler, int actionToDo, Document doc, RequestData reqData)
            throws WSSecurityException {
        Crypto crypto = null;
        /*
        * it is possible and legal that we do not have a signature
        * crypto here - thus ignore the exception. This is usually
        * the case for the SAML option "sender vouches". In this case
        * no user crypto is required.
        */
        try {
            crypto = handler.loadSignatureCrypto(reqData);
        } catch (Throwable t){
        }

        SAMLIssuer saml = loadSamlIssuer(handler, reqData);
        saml.setUsername(reqData.getUsername());
        saml.setUserCrypto(crypto);
        saml.setInstanceDoc(doc);

        SAMLAssertion assertion = saml.newAssertion();
        if (assertion == null) {
            throw new WSSecurityException("WSHandler: Signed SAML: no SAML token received");
        }
        String issuerKeyName = null;
        String issuerKeyPW = null;
        Crypto issuerCrypto = null;

        WSSecSignatureSAML wsSign = new WSSecSignatureSAML();
        wsSign.setWsConfig(reqData.getWssConfig());

        String password = null;
        if (saml.isSenderVouches()) {
            issuerKeyName = saml.getIssuerKeyName();
            issuerKeyPW = saml.getIssuerKeyPassword();
            issuerCrypto = saml.getIssuerCrypto();
        } else {
            password =
                    handler.getPassword(reqData.getUsername(),
                            actionToDo,
                            WSHandlerConstants.PW_CALLBACK_CLASS,
                            WSHandlerConstants.PW_CALLBACK_REF, reqData)
                            .getPassword();
            wsSign.setUserInfo(reqData.getUsername(), password);
        }
        if (reqData.getSigKeyId() != 0) {
            wsSign.setKeyIdentifierType(reqData.getSigKeyId());
        }
        try {
            wsSign.build(
                    doc,
                    crypto,
                    assertion,
                    issuerCrypto,
                    issuerKeyName,
                    issuerKeyPW,
                    reqData.getSecHeader());
            reqData.getSignatureValues().add(wsSign.getSignatureValue());
        } catch (WSSecurityException e) {
            throw new WSSecurityException("WSHandler: Signed SAML: error during message processing"
                    + e);
        }
    }

    protected SAMLIssuer loadSamlIssuer(WSHandler handler, 
					RequestData reqData) {
        String samlPropFile 
	    = handler.getString(WSHandlerConstants.SAML_PROP_FILE,
				reqData.getMsgContext());
        return SAMLIssuerFactory.getInstance(samlPropFile);
    }

}
