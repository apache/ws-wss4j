package org.apache.ws.security.action;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.WSSignEnvelope;
import org.w3c.dom.Document;

public class SignatureAction implements Action {
    public void execute(WSHandler handler, int actionToDo, boolean mu, Document doc, RequestData reqData)
            throws WSSecurityException {
        String password;
        password =
                handler.getPassword(reqData.getUsername(),
                        actionToDo,
                        WSHandlerConstants.PW_CALLBACK_CLASS,
                        WSHandlerConstants.PW_CALLBACK_REF, reqData)
                        .getPassword();

        WSSignEnvelope wsSign = new WSSignEnvelope(reqData.getActor(), mu);
        wsSign.setWsConfig(reqData.getWssConfig());

        if (reqData.getSigKeyId() != 0) {
            wsSign.setKeyIdentifierType(reqData.getSigKeyId());
        }
        if (reqData.getSigAlgorithm() != null) {
            wsSign.setSignatureAlgorithm(reqData.getSigAlgorithm());
        }

        wsSign.setUserInfo(reqData.getUsername(), password);
        if (reqData.getSignatureParts().size() > 0) {
            wsSign.setParts(reqData.getSignatureParts());
        }

        try {
            wsSign.build(doc, reqData.getSigCrypto());
            reqData.getSignatureValues().add(wsSign.getSignatureValue());
        } catch (WSSecurityException e) {
            throw new WSSecurityException("WSHandler: Signature: error during message procesing" + e);
        }
    }

}
