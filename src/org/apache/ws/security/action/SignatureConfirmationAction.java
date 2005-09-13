package org.apache.ws.security.action;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.ws.security.message.WSAddSignatureConfirmation;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;

import java.util.Vector;

public class SignatureConfirmationAction implements Action {
    protected static Log log = LogFactory.getLog(WSHandler.class.getName());

    public void execute(WSHandler handler, int actionToDo, boolean mu, Document doc, RequestData reqData)
            throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Perform Signature confirmation");
        }

        Vector results = (Vector) handler.getProperty(reqData.getMsgContext(),
                WSHandlerConstants.RECV_RESULTS);
        /*
         * loop over all results gathered by all handlers in the chain. For each
         * handler result get the various actions. After that loop we have all
         * signature results in the signatureActions vector
         */
        Vector signatureActions = new Vector();
        for (int i = 0; i < results.size(); i++) {
            WSHandlerResult wshResult = (WSHandlerResult) results.get(i);

            WSSecurityUtil.fetchAllActionResults(wshResult.getResults(),
                    WSConstants.SIGN, signatureActions);
            WSSecurityUtil.fetchAllActionResults(wshResult.getResults(),
                    WSConstants.ST_SIGNED, signatureActions);
            WSSecurityUtil.fetchAllActionResults(wshResult.getResults(),
                    WSConstants.UT_SIGN, signatureActions);
        }
        Vector signatureParts = reqData.getSignatureParts();
        // prepare a SignatureConfirmation token
        WSAddSignatureConfirmation wsc = new WSAddSignatureConfirmation(reqData
                .getActor(), mu);
        int idHash = wsc.hashCode();
        if (signatureActions.size() > 0) {
            if (log.isDebugEnabled()) {
                log.debug("Signature Confirmation: number of Signature results: "
                        + signatureActions.size());
            }
            for (int i = 0; i < signatureActions.size(); i++) {
                WSSecurityEngineResult wsr = (WSSecurityEngineResult) signatureActions
                        .get(i);
                byte[] sigVal = wsr.getSignatureValue();
                String id = "sigcon-" + (idHash + i);
                wsc.setId(id);
                wsc.build(doc, sigVal);
                signatureParts.add(new WSEncryptionPart(id));
            }
        } else {
            String id = "sigcon-" + idHash;
            wsc.setId(id);
            wsc.build(doc, null);
            signatureParts.add(new WSEncryptionPart(id));
        }
        handler.setProperty(reqData.getMsgContext(), WSHandlerConstants.SIG_CONF_DONE,
                handler.DONE);
    }
}
