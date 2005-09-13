package org.apache.ws.security.action;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.WSSAddUsernameToken;
import org.apache.ws.security.message.WSSignEnvelope;
import org.apache.xml.security.signature.XMLSignature;
import org.w3c.dom.Document;

public class UsernameTokenSignedAction implements Action {
    public void execute(WSHandler handler, int actionToDo, boolean mu, Document doc, RequestData reqData)
            throws WSSecurityException {
        String password;
        password = handler.getPassword(reqData.getUsername(), actionToDo,
                WSHandlerConstants.PW_CALLBACK_CLASS,
                WSHandlerConstants.PW_CALLBACK_REF, reqData).getPassword();

        WSSAddUsernameToken builder = new WSSAddUsernameToken(reqData.getActor(), mu);
        builder.setWsConfig(reqData.getWssConfig());

        builder.setPasswordType(WSConstants.PASSWORD_TEXT);
        builder.preSetUsernameToken(doc, reqData.getUsername(), password);
        builder.addCreated(doc);
        builder.addNonce(doc);

        WSSignEnvelope sign = new WSSignEnvelope(reqData.getActor(), mu);
        sign.setWsConfig(reqData.getWssConfig());

        if (reqData.getSignatureParts().size() > 0) {
            sign.setParts(reqData.getSignatureParts());
        }
        sign.setUsernameToken(builder);
        sign.setKeyIdentifierType(WSConstants.UT_SIGNING);
        sign.setSignatureAlgorithm(XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
        try {
            sign.build(doc, null);
            reqData.getSignatureValues().add(sign.getSignatureValue());
        } catch (WSSecurityException e) {
            throw new WSSecurityException("WSHandler: Error during Signatur with UsernameToken secret"
                    + e);
        }
        builder.build(doc, null, null);
    }
}
