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

package org.apache.ws.axis.security;

/**
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 *
 */

import org.apache.axis.AxisFault;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.SOAPPart;
import org.apache.axis.handlers.BasicHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.axis.security.util.AxisUtil;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.token.Timestamp;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.TimeZone;
import java.util.Vector;

public class WSDoAllReceiver extends BasicHandler {
    static Log log = LogFactory.getLog(WSDoAllReceiver.class.getName());
    static final WSSecurityEngine secEngine = WSSecurityEngine.getInstance();

    private boolean doDebug = false;

    private static Hashtable cryptos = new Hashtable(5);

    /**
     * This nested private class hold per request data.
     *
     * @author wdi
     */
    private class RequestData {
        MessageContext msgContext = null;

        Crypto sigCrypto = null;
        String sigPropFile = null;

        Crypto decCrypto = null;
        String decPropFile = null;

        int timeToLive = 300; 	// Timestamp: time in seconds between creation
        // and expiery
        void clear() {
            decCrypto = null;
            decPropFile = null;
            msgContext = null;
            sigCrypto = null;
            sigPropFile = null;
        }
    }
    /**
     * Axis calls invoke to handle a message.
     * <p/>
     *
     * @param mc message context.
     * @throws AxisFault
     */
    public void invoke(MessageContext msgContext) throws AxisFault {

        if (doDebug) {
            log.debug("WSDoAllReceiver: enter invoke() with msg type: "
                    + msgContext.getCurrentMessage().getMessageType());
        }

        RequestData reqData = new RequestData();
        /*
        * The overall try, just to have a finally at the end to perform some
        * housekeeping.
        */
        try {
            reqData.msgContext = msgContext;

            Vector actions = new Vector();
            String action = null;
            if ((action = (String) getOption(WSHandlerConstants.ACTION)) == null) {
                action = (String) msgContext
                        .getProperty(WSHandlerConstants.ACTION);
            }
            if (action == null) {
                throw new AxisFault("WSDoAllReceiver: No action defined");
            }
            int doAction = AxisUtil.decodeAction(action, actions);

            String actor = (String) getOption(WSHandlerConstants.ACTOR);

            Message sm = msgContext.getCurrentMessage();
            Document doc = null;
            try {
                doc = sm.getSOAPEnvelope().getAsDocument();
                if (doDebug) {
                    log.debug("Received SOAP request: ");
                    log.debug(org.apache.axis.utils.XMLUtils
                            .PrettyDocumentToString(doc));
                }
            } catch (Exception ex) {
                throw new AxisFault(
                        "WSDoAllReceiver: cannot convert into document", ex);
            }
            /*
            * Check if it's a response and if its a fault. Don't process
            * faults.
            */
            String msgType = sm.getMessageType();
            if (msgType != null && msgType.equals(Message.RESPONSE)) {
                SOAPConstants soapConstants = WSSecurityUtil
                        .getSOAPConstants(doc.getDocumentElement());
                if (WSSecurityUtil.findElement(doc.getDocumentElement(),
                        "Fault", soapConstants.getEnvelopeURI()) != null) {
                    return;
                }
            }

            /*
            * To check a UsernameToken or to decrypt an encrypted message we
            * need a password.
            */
            CallbackHandler cbHandler = null;
            if ((doAction & (WSConstants.ENCR | WSConstants.UT)) != 0) {
                cbHandler = getPasswordCB(reqData);
            }

            /*
            * Get and check the Signature specific parameters first because
            * they may be used for encryption too.
            */

            if ((doAction & WSConstants.SIGN) == WSConstants.SIGN) {
                decodeSignatureParameter(reqData);
            }

            if ((doAction & WSConstants.ENCR) == WSConstants.ENCR) {
                decodeDecryptionParameter(reqData);
            }

            Vector wsResult = null;
            try {
                wsResult = secEngine.processSecurityHeader(doc, actor,
                        cbHandler, reqData.sigCrypto, reqData.decCrypto);
            } catch (WSSecurityException ex) {
                ex.printStackTrace();
                throw new AxisFault(
                        "WSDoAllReceiver: security processing failed", ex);
            }
            if (wsResult == null) { // no security header found
                if (doAction == WSConstants.NO_SECURITY) {
                    return;
                } else {
                    throw new AxisFault(
                            "WSDoAllReceiver: Request does not contain required Security header");
                }
            }

            /*
            * save the processed-header flags
            */
            ArrayList processedHeaders = new ArrayList();
            Iterator iterator = sm.getSOAPEnvelope().getHeaders().iterator();
            while (iterator.hasNext()) {
                org.apache.axis.message.SOAPHeaderElement tempHeader = (org.apache.axis.message.SOAPHeaderElement) iterator
                        .next();
                if (tempHeader.isProcessed()) {
                    processedHeaders.add(tempHeader.getQName());
                }
            }

            /*
            * If we had some security processing, get the original SOAP part of
            * Axis' message and replace it with new SOAP part. This new part
            * may contain decrypted elements.
            */
            SOAPPart sPart = (org.apache.axis.SOAPPart) sm.getSOAPPart();

            ByteArrayOutputStream os = new ByteArrayOutputStream();
            XMLUtils.outputDOM(doc, os, true);
            sPart.setCurrentMessage(os.toByteArray(), SOAPPart.FORM_BYTES);
            if (doDebug) {
                log.debug("Processed received SOAP request");
                log.debug(org.apache.axis.utils.XMLUtils
                        .PrettyDocumentToString(doc));
            }

            /*
            * set the original processed-header flags
            */
            iterator = processedHeaders.iterator();
            while (iterator.hasNext()) {
                QName qname = (QName) iterator.next();
                org.apache.axis.message.SOAPHeaderElement tempHeader = (org.apache.axis.message.SOAPHeaderElement) sm
                        .getSOAPEnvelope().getHeadersByName(
                                qname.getNamespaceURI(), qname.getLocalPart());
                tempHeader.setProcessed(true);
            }

            /*
            * After setting the new current message, probably modified because
            * of decryption, we need to locate the security header. That is, we
            * force Axis (with getSOAPEnvelope()) to parse the string, build
            * the new header. Then we examine, look up the security header and
            * set the header as processed.
            *
            * Please note: find all header elements that contain the same actor
            * that was given to processSecurityHeader(). Then check if there is
            * a security header with this actor.
            */

            SOAPHeader sHeader = null;
            try {
                sHeader = sm.getSOAPEnvelope().getHeader();
            } catch (Exception ex) {
                throw new AxisFault(
                        "WSDoAllReceiver: cannot get SOAP header after security processing",
                        ex);
            }

            Iterator headers = sHeader.examineHeaderElements(actor);

            SOAPHeaderElement headerElement = null;
            while (headers.hasNext()) {
                SOAPHeaderElement hE = (SOAPHeaderElement) headers.next();
                if (hE.getLocalName().equals(WSConstants.WSSE_LN)
                        && hE.getNamespaceURI().equals(WSConstants.WSSE_NS)) {
                    headerElement = hE;
                    break;
                }
            }
            ((org.apache.axis.message.SOAPHeaderElement) headerElement)
                    .setProcessed(true);

            /*
            * Now we can check the certificate used to sign the message. In the
            * following implementation the certificate is only trusted if
            * either it itself or the certificate of the issuer is installed in
            * the keystore.
            *
            * Note: the method verifyTrust(X509Certificate) allows custom
            * implementations with other validation algorithms for subclasses.
            */

            // Extract the signature action result from the action vector
            WSSecurityEngineResult actionResult = WSSecurityUtil
                    .fetchActionResult(wsResult, WSConstants.SIGN);

            if (actionResult != null) {
                X509Certificate returnCert = actionResult.getCertificate();

                if (returnCert != null) {
                    if (!verifyTrust(returnCert, reqData)) {
                        throw new AxisFault(
                                "WSDoAllReceiver: The certificate used for the signature is not trusted");
                    }
                }
            }

            /*
            * Perform further checks on the timestamp that was transmitted in
            * the header. In the following implementation the timestamp is
            * valid if it was created after (now-ttl), where ttl is set on
            * server side, not by the client.
            *
            * Note: the method verifyTimestamp(Timestamp) allows custom
            * implementations with other validation algorithms for subclasses.
            */

            // Extract the timestamp action result from the action vector
            actionResult = WSSecurityUtil.fetchActionResult(wsResult,
                    WSConstants.TS);

            if (actionResult != null) {
                Timestamp timestamp = actionResult.getTimestamp();

                if (timestamp != null) {
                    String ttl = null;
                    if ((ttl = (String) getOption(WSHandlerConstants.TTL_TIMESTAMP)) == null) {
                        ttl = (String) msgContext
                                .getProperty(WSHandlerConstants.TTL_TIMESTAMP);
                    }
                    int ttl_i = 0;
                    if (ttl != null) {
                        try {
                            ttl_i = Integer.parseInt(ttl);
                        } catch (NumberFormatException e) {
                            ttl_i = reqData.timeToLive;
                        }
                    }
                    if (ttl_i <= 0) {
                        ttl_i = reqData.timeToLive;
                    }

                    if (!verifyTimestamp(timestamp, reqData.timeToLive)) {
                        throw new AxisFault(
                                "WSDoAllReceiver: The timestamp could not be validated");
                    }
                }
            }

            /*
            * now check the security actions: do they match, in right order?
            */
            int resultActions = wsResult.size();
            int size = actions.size();
            if (size != resultActions) {
                throw new AxisFault(
                        "WSDoAllReceiver: security processing failed (actions number mismatch)");
            }
            for (int i = 0; i < size; i++) {
                if (((Integer) actions.get(i)).intValue() != ((WSSecurityEngineResult) wsResult
                        .get(i)).getAction()) {
                    throw new AxisFault(
                            "WSDoAllReceiver: security processing failed (actions mismatch)");
                }
            }

            /*
            * All ok up to this point. Now construct and setup the security
            * result structure. The service may fetch this and check it.
            */
            Vector results = null;
            if ((results = (Vector) msgContext
                    .getProperty(WSHandlerConstants.RECV_RESULTS)) == null) {
                results = new Vector();
                msgContext
                        .setProperty(WSHandlerConstants.RECV_RESULTS, results);
            }
            WSHandlerResult rResult = new WSHandlerResult(actor, wsResult);
            results.add(0, rResult);
            if (doDebug) {
                log.debug("WSDoAllReceiver: exit invoke()");
            }
        } finally {
            reqData.clear();
            reqData = null;
        }

    }

    /**
     * Hook to allow subclasses to load their Signature Crypto however they see
     * fit.
     */
    protected Crypto loadSignatureCrypto(RequestData reqData) throws AxisFault {
        Crypto crypto = null;
        if ((reqData.sigPropFile = (String) getOption(WSHandlerConstants.SIG_PROP_FILE))
                == null) {
            reqData.sigPropFile =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.SIG_PROP_FILE);
        }
        if (reqData.sigPropFile != null) {
            if ((crypto = (Crypto) cryptos.get(reqData.sigPropFile)) == null) {
                crypto = CryptoFactory.getInstance(reqData.sigPropFile);
                cryptos.put(reqData.sigPropFile, crypto);
            }
        } else {
            throw new AxisFault("WSDoAllReceiver: Signature: no crypto property file");
        }
        return crypto;
    }

    /**
     * Hook to allow subclasses to load their Decryption Crypto however they see
     * fit.
     */
    protected Crypto loadDecryptionCrypto(RequestData reqData) throws AxisFault {
        Crypto crypto = null;
        if ((reqData.decPropFile = (String) getOption(WSHandlerConstants.DEC_PROP_FILE))
                == null) {
            reqData.decPropFile =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.DEC_PROP_FILE);
        }
        if (reqData.decPropFile != null) {
            if ((crypto = (Crypto) cryptos.get(reqData.decPropFile)) == null) {
                crypto = CryptoFactory.getInstance(reqData.decPropFile);
                cryptos.put(reqData.decPropFile, crypto);
            }
        } else if ((crypto = reqData.sigCrypto) == null) {
            throw new AxisFault("WSDoAllReceiver: Encryption: no crypto property file");
        }
        return crypto;
    }

    private void decodeSignatureParameter(RequestData reqData) throws AxisFault {
        reqData.sigCrypto = loadSignatureCrypto(reqData);
        /* There are currently no other signature parameters that need to be handled
        * here, but we call the load crypto hook rather than just changing the visibility
        * of this method to maintain parity with WSDoAllSender.
        */
    }

    /*
    * Set and check the decryption specific parameters, if necessary
    * take over signatur crypto instance.
    */

    private void decodeDecryptionParameter(RequestData reqData) throws AxisFault {
        reqData.decCrypto = loadDecryptionCrypto(reqData);
        /* There are currently no other decryption parameters that need to be handled
        * here, but we call the load crypto hook rather than just changing the visibility
        * of this method to maintain parity with WSDoAllSender.
        */
    }

    /**
     * Get the password callback class and get an instance
     * <p/>
     */
    private CallbackHandler getPasswordCB(RequestData reqData) throws AxisFault {

        String callback = null;
        CallbackHandler cbHandler = null;
        if ((callback = (String) getOption(WSHandlerConstants.PW_CALLBACK_CLASS))
                == null) {
            callback =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.PW_CALLBACK_CLASS);
        }
        if (callback != null) {
            Class cbClass = null;
            try {
                cbClass = java.lang.Class.forName(callback);
            } catch (ClassNotFoundException e) {
                throw new AxisFault("WSDoAllReceiver: cannot load password callback class: "
                        + callback,
                        e);
            }
            try {
                cbHandler = (CallbackHandler) cbClass.newInstance();
            } catch (java.lang.Exception e) {
                throw new AxisFault("WSDoAllReceiver: cannot create instance of password callback: "
                        + callback,
                        e);
            }
        } else {
            cbHandler =
                    (CallbackHandler) reqData.msgContext.getProperty(WSHandlerConstants.PW_CALLBACK_REF);
            if (cbHandler == null) {
                throw new AxisFault("WSDoAllReceiver: no reference in callback property");
            }
        }
        return cbHandler;
    }

    /**
     * Evaluate whether a given certificate should be trusted.
     * Hook to allow subclasses to implement custom validation methods however they see fit.
     * <p/>
     * Policy used in this implementation:
     * 1. Search the keystore for the transmitted certificate
     * 2. Search the keystore for a connection to the transmitted certificate
     * (that is, search for certificate(s) of the issuer of the transmitted certificate
     * 3. Verify the trust path for those certificates found because the search for the issuer might be fooled by a phony DN (String!)
     *
     * @param cert the certificate that should be validated against the keystore
     * @return true if the certificate is trusted, false if not (AxisFault is thrown for exceptions during CertPathValidation)
     * @throws AxisFault
     */
    private boolean verifyTrust(X509Certificate cert, RequestData reqData) throws AxisFault {

        // If no certificate was transmitted, do not trust the signature
        if (cert == null) {
            return false;
        }

        String[] aliases = null;
        String alias = null;
        X509Certificate[] certs;

        String subjectString = cert.getSubjectDN().getName();
        String issuerString = cert.getIssuerDN().getName();
        BigInteger issuerSerial = cert.getSerialNumber();

        if (doDebug) {
            log.debug("WSDoAllReceiver: Transmitted certificate has subject " + subjectString);
            log.debug("WSDoAllReceiver: Transmitted certificate has issuer " + issuerString + " (serial " + issuerSerial + ")");
        }

        // FIRST step
        // Search the keystore for the transmitted certificate

        // Search the keystore for the alias of the transmitted certificate
        try {
            alias = reqData.sigCrypto.getAliasForX509Cert(issuerString, issuerSerial);
        } catch (WSSecurityException ex) {
            throw new AxisFault("WSDoAllReceiver: Could not get alias for certificate with " + subjectString, ex);
        }

        if (alias != null) {
            // Retrieve the certificate for the alias from the keystore
            try {
                certs = reqData.sigCrypto.getCertificates(alias);
            } catch (WSSecurityException ex) {
                throw new AxisFault("WSDoAllReceiver: Could not get certificates for alias " + alias, ex);
            }

            // If certificates have been found, the certificates must be compared
            // to ensure againgst phony DNs (compare encoded form including signature)
            if (certs != null && certs.length > 0 && cert.equals(certs[0])) {
                if (doDebug) {
                    log.debug("Direct trust for certificate with " + subjectString);
                }
                return true;
            }
        } else {
            if (doDebug) {
                log.debug("No alias found for subject from issuer with " + issuerString + " (serial " + issuerSerial + ")");
            }
        }

        // SECOND step
        // Search for the issuer of the transmitted certificate in the keystore

        // Search the keystore for the alias of the transmitted certificates issuer
        try {
            aliases = reqData.sigCrypto.getAliasesForDN(issuerString);
        } catch (WSSecurityException ex) {
            throw new AxisFault("WSDoAllReceiver: Could not get alias for certificate with " + issuerString, ex);
        }

        // If the alias has not been found, the issuer is not in the keystore
        // As a direct result, do not trust the transmitted certificate
        if (aliases == null || aliases.length < 1) {
            if (doDebug) {
                log.debug("No aliases found in keystore for issuer " + issuerString + " of certificate for " + subjectString);
            }
            return false;
        }

        // THIRD step
        // Check the certificate trust path for every alias of the issuer found in the keystore
        for (int i = 0; i < aliases.length; i++) {
            alias = aliases[i];

            if (doDebug) {
                log.debug("Preparing to validate certificate path with alias " + alias + " for issuer " + issuerString);
            }

            // Retrieve the certificate(s) for the alias from the keystore
            try {
                certs = reqData.sigCrypto.getCertificates(alias);
            } catch (WSSecurityException ex) {
                throw new AxisFault("WSDoAllReceiver: Could not get certificates for alias " + alias, ex);
            }

            // If no certificates have been found, there has to be an error:
            // The keystore can find an alias but no certificate(s)
            if (certs == null | certs.length < 1) {
                throw new AxisFault("WSDoAllReceiver: Could not get certificates for alias " + alias);
            }

            // Form a certificate chain from the transmitted certificate
            // and the certificate(s) of the issuer from the keystore

            // First, create new array
            X509Certificate[] x509certs = new X509Certificate[certs.length + 1];

            /* The following conversion into provider specific format seems not to be necessary
            // Create new certificate, possibly provider-specific
            try {
            cert = sigCrypto.loadCertificate(new ByteArrayInputStream(cert.getEncoded()));
            } catch (CertificateEncodingException ex) {
            throw new AxisFault("WSDoAllReceiver: Combination of subject and issuers certificates failed", ex);
            } catch (WSSecurityException ex) {
            throw new AxisFault("WSDoAllReceiver: Combination of subject and issuers certificates failed", ex);
            }
            */

            // Then add the first certificate ...
            x509certs[0] = cert;

            // ... and the other certificates
            for (int j = 0; j < certs.length; j++) {
                cert = certs[i];

                /* The following conversion into provider specific format seems not to be necessary
                // Create new certificate, possibly provider-specific
                try {
                cert = sigCrypto.loadCertificate(new ByteArrayInputStream(cert.getEncoded()));
                } catch (CertificateEncodingException ex) {
                throw new AxisFault("WSDoAllReceiver: Combination of subject and issuers certificates failed", ex);
                } catch (WSSecurityException ex) {
                throw new AxisFault("WSDoAllReceiver: Combination of subject and issuers certificates failed", ex);
                }
                */

                x509certs[certs.length + j] = cert;
            }
            certs = x509certs;

            // Use the validation method from the crypto to check whether the subjects certificate was really signed by the issuer stated in the certificate
            try {
                if (reqData.sigCrypto.validateCertPath(certs)) {
                    if (doDebug) {
                        log.debug("WSDoAllReceiver: Certificate path has been verified for certificate with subject " + subjectString);
                    }
                    return true;
                }
            } catch (WSSecurityException ex) {
                throw new AxisFault("WSDoAllReceiver: Certificate path verification failed for certificate with subject " + subjectString, ex);
            }
        }

        log.debug("WSDoAllReceiver: Certificate path could not be verified for certificate with subject " + subjectString);
        return false;
    }

    /**
     * Evaluate whether a timestamp is considered valid on receiverside.
     * Hook to allow subclasses to implement custom validation methods however they see fit.
     * <p/>
     * Policy used in this implementation:
     * 1. The receiver can set its own time to live (besides from that set on sender side)
     * 2. If the message was created before (now-ttl) the message is rejected
     *
     * @param timestamp  the timestamp that is validated
     * @param timeToLive the limit on receiverside, the timestamp is validated against
     * @return true if the timestamp is before (now-timeToLive), false otherwise
     * @throws AxisFault
     */
    protected boolean verifyTimestamp(Timestamp timestamp, int timeToLive) throws AxisFault {

        // Calculate the time that is allowed for the message to travel
        Calendar validCreation = Calendar.getInstance();
        long currentTime = validCreation.getTimeInMillis();
        currentTime -= timeToLive * 1000;
        validCreation.setTimeInMillis(currentTime);

        if (doDebug) {
            log.debug("Preparing to verify the timestamp");
            SimpleDateFormat zulu = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
            zulu.setTimeZone(TimeZone.getTimeZone("GMT"));
            log.debug("Validation of Timestamp: Current time is "
                    + zulu.format(Calendar.getInstance().getTime()));
            log.debug("Validation of Timestamp: Valid creation is "
                    + zulu.format(validCreation.getTime()));
            log.debug("Validation of Timestamp: Timestamp created is "
                    + zulu.format(timestamp.getCreated().getTime()));
        }
        // Validate the time it took the message to travel
        //        if (timestamp.getCreated().before(validCreation) ||
        // !timestamp.getCreated().equals(validCreation)) {
        if (!timestamp.getCreated().after(validCreation)) {
            if (doDebug) {
                log.debug("Validation of Timestamp: The message was created too long ago");
            }
            return false;
        }

        log.debug("Validation of Timestamp: Everything is ok");
        return true;
    }
}
