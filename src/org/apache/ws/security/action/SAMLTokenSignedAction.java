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
import org.apache.ws.security.saml.WSSignSAMLEnvelope;
import org.opensaml.SAMLAssertion;
import org.w3c.dom.Document;

public class SAMLTokenSignedAction implements Action {
    private static Log log = LogFactory.getLog(SAMLTokenSignedAction.class.getName());
    private static Log tlog =
            LogFactory.getLog("org.apache.ws.security.TIME");

    public void execute(WSHandler handler, int actionToDo, boolean mu, Document doc, RequestData reqData)
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

        WSSignSAMLEnvelope wsSign = new WSSignSAMLEnvelope(reqData.getActor(), mu);
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
                    issuerKeyPW);
            reqData.getSignatureValues().add(wsSign.getSignatureValue());
        } catch (WSSecurityException e) {
            throw new WSSecurityException("WSHandler: Signed SAML: error during message processing"
                    + e);
        }
    }

    protected SAMLIssuer loadSamlIssuer(WSHandler handler, RequestData reqData) {
        String samlPropFile = null;

        if ((samlPropFile =
                (String) handler.getOption(WSHandlerConstants.SAML_PROP_FILE))
                == null) {
            samlPropFile =
                    (String) handler.getProperty(reqData.getMsgContext(), WSHandlerConstants.SAML_PROP_FILE);
        }
        return SAMLIssuerFactory.getInstance(samlPropFile);
    }

}
