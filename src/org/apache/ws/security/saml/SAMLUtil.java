package org.apache.ws.security.saml;

import org.w3c.dom.Element;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLException;
import org.opensaml.SAMLSubjectStatement;
import org.opensaml.SAMLObject;
import org.opensaml.SAMLSubject;

import java.security.cert.X509Certificate;
import java.util.Iterator;

/**
 * Utility methods for SAML stuff
 */
public class SAMLUtil {
    private static Log log = LogFactory.getLog(SAMLUtil.class.getName());

    /**
     * Extracts the certificate(s) from the SAML token reference.
     * <p/>
     *
     * @param elem The element containing the SAML token.
     * @return an array of X509 certificates
     * @throws org.apache.ws.security.WSSecurityException
     */
    public static X509Certificate[] getCertificatesFromSAML(Element elem)
            throws WSSecurityException {

        /*
         * Get some information about the SAML token content. This controls how
         * to deal with the whole stuff. First get the Authentication statement
         * (includes Subject), then get the _first_ confirmation method only.
         */
        SAMLAssertion assertion;
        try {
            assertion = new SAMLAssertion(elem);
        } catch (SAMLException e) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLToken", new Object[]{"for Signature (cannot parse)"});
        }
        SAMLSubjectStatement samlSubjS = null;
        Iterator it = assertion.getStatements();
        while (it.hasNext()) {
            SAMLObject so = (SAMLObject) it.next();
            if (so instanceof SAMLSubjectStatement) {
                samlSubjS = (SAMLSubjectStatement) so;
                break;
            }
        }
        SAMLSubject samlSubj = null;
        if (samlSubjS != null) {
            samlSubj = samlSubjS.getSubject();
        }
        if (samlSubj == null) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLToken", new Object[]{"for Signature (no Subject)"});
        }

//        String confirmMethod = null;
//        it = samlSubj.getConfirmationMethods();
//        if (it.hasNext()) {
//            confirmMethod = (String) it.next();
//        }
//        boolean senderVouches = false;
//        if (SAMLSubject.CONF_SENDER_VOUCHES.equals(confirmMethod)) {
//            senderVouches = true;
//        }
        Element e = samlSubj.getKeyInfo();
        X509Certificate[] certs = null;
        try {
            KeyInfo ki = new KeyInfo(e, null);

            if (ki.containsX509Data()) {
                X509Data data = ki.itemX509Data(0);
                XMLX509Certificate certElem = null;
                if (data != null && data.containsCertificate()) {
                    certElem = data.itemCertificate(0);
                }
                if (certElem != null) {
                    X509Certificate cert = certElem.getX509Certificate();
                    certs = new X509Certificate[1];
                    certs[0] = cert;
                }
            }
            // TODO: get alias name for cert, check against username set by caller
        } catch (XMLSecurityException e3) {
            throw new WSSecurityException(WSSecurityException.FAILURE,
                    "invalidSAMLsecurity",
                    new Object[]{"cannot get certificate (key holder)"});
        }
        return certs;
    }

    public static String getAssertionId(Element envelope, String elemName, String nmSpace) throws WSSecurityException {
        String id;
        // Make the AssertionID the wsu:Id and the signature reference the same
        SAMLAssertion assertion;

        Element assertionElement = (Element) WSSecurityUtil
                .findElement(envelope, elemName, nmSpace);

        try {
            assertion = new SAMLAssertion(assertionElement);
            id = assertion.getId();
        } catch (Exception e1) {
            log.error(e1);
            throw new WSSecurityException(
                    WSSecurityException.FAILED_SIGNATURE,
                    "noXMLSig", null, e1);
        }
        return id;
    }

}
