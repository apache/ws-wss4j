package org.apache.ws.security.action;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.message.WSEncryptBody;
import org.w3c.dom.Document;

public class EncryptionAction implements Action {
    public void execute(WSHandler handler, int actionToDo, boolean mu, Document doc, RequestData reqData)
            throws WSSecurityException {
        WSEncryptBody wsEncrypt = new WSEncryptBody(reqData.getActor(), mu);
        wsEncrypt.setWsConfig(reqData.getWssConfig());

        if (reqData.getEncKeyId() != 0) {
            wsEncrypt.setKeyIdentifierType(reqData.getEncKeyId());
        }
        if (reqData.getEncKeyId() == WSConstants.EMBEDDED_KEYNAME) {
            String encKeyName = null;
            if ((encKeyName =
                    (String) handler.getOption(WSHandlerConstants.ENC_KEY_NAME))
                    == null) {
                encKeyName =
                        (String) handler.getProperty(reqData.getMsgContext(), WSHandlerConstants.ENC_KEY_NAME);
            }
            wsEncrypt.setEmbeddedKeyName(encKeyName);
            byte[] embeddedKey =
                    handler.getPassword(reqData.getEncUser(),
                            actionToDo,
                            WSHandlerConstants.ENC_CALLBACK_CLASS,
                            WSHandlerConstants.ENC_CALLBACK_REF, reqData)
                            .getKey();
            wsEncrypt.setKey(embeddedKey);
        }
        if (reqData.getEncSymmAlgo() != null) {
            wsEncrypt.setSymmetricEncAlgorithm(reqData.getEncSymmAlgo());
        }
        if (reqData.getEncKeyTransport() != null) {
            wsEncrypt.setKeyEnc(reqData.getEncKeyTransport());
        }
        wsEncrypt.setUserInfo(reqData.getEncUser());
        wsEncrypt.setUseThisCert(reqData.getEncCert());
        if (reqData.getEncryptParts().size() > 0) {
            wsEncrypt.setParts(reqData.getEncryptParts());
        }
        try {
            wsEncrypt.build(doc, reqData.getEncCrypto());
        } catch (WSSecurityException e) {
            throw new WSSecurityException("WSHandler: Encryption: error during message processing"
                    + e);
        }
    }
}
