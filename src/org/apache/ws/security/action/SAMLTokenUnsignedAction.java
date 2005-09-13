package org.apache.ws.security.action;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.message.WSSAddSAMLToken;
import org.apache.ws.security.saml.SAMLIssuer;
import org.opensaml.SAMLAssertion;
import org.w3c.dom.Document;

public class SAMLTokenUnsignedAction extends SAMLTokenSignedAction implements Action {

    public void execute(WSHandler handler, int actionToDo, boolean mu, Document doc, RequestData reqData)
            throws WSSecurityException {
        WSSAddSAMLToken builder = new WSSAddSAMLToken(reqData.getActor(), mu);
        builder.setWsConfig(reqData.getWssConfig());

        SAMLIssuer saml = loadSamlIssuer(handler, reqData);
        saml.setUsername(reqData.getUsername());
        SAMLAssertion assertion = saml.newAssertion();

        // add the SAMLAssertion Token to the SOAP Enevelope
        builder.build(doc, assertion);
    }
}
