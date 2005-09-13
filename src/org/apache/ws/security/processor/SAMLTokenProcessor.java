package org.apache.ws.security.processor;

import org.w3c.dom.Element;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSDocInfo;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLException;

import java.util.Vector;

public class SAMLTokenProcessor implements Processor {
    private static Log log = LogFactory.getLog(SAMLTokenProcessor.class.getName());
    public void handleToken(Element elem, WSDocInfo wsDocInfo, Vector returnResults) throws WSSecurityException {
        if (log.isDebugEnabled()) {
            log.debug("Found SAML Assertion element");
        }
        SAMLAssertion assertion = handleSAMLToken((Element) elem);
        wsDocInfo.setAssertion((Element) elem);
        returnResults.add(0,
                new WSSecurityEngineResult(WSConstants.ST_UNSIGNED, assertion));

    }

    public SAMLAssertion handleSAMLToken(Element token) throws WSSecurityException {
        boolean result = false;
        SAMLAssertion assertion = null;
        try {
            assertion = new SAMLAssertion(token);
            result = true;
            if (log.isDebugEnabled()) {
                log.debug("SAML Assertion issuer " + assertion.getIssuer());
            }
        } catch (SAMLException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLsecurity", null, e);
        }
        if (!result) {
            throw new WSSecurityException(WSSecurityException.FAILED_AUTHENTICATION);
        }
        return assertion;
    }

}
