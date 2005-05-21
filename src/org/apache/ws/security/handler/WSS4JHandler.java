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

package org.apache.ws.security.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSAddTimestamp;
import org.apache.ws.security.message.WSEncryptBody;
import org.apache.ws.security.message.WSSAddSAMLToken;
import org.apache.ws.security.message.WSSAddUsernameToken;
import org.apache.ws.security.message.WSSignEnvelope;
import org.apache.ws.security.message.token.Timestamp;
import org.apache.ws.security.saml.SAMLIssuer;
import org.apache.ws.security.saml.SAMLIssuerFactory;
import org.apache.ws.security.util.StringUtil;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.XMLUtils;
import org.opensaml.SAMLAssertion;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.rpc.Call;
import javax.xml.rpc.JAXRPCException;
import javax.xml.rpc.handler.Handler;
import javax.xml.rpc.handler.HandlerInfo;
import javax.xml.rpc.handler.MessageContext;
import javax.xml.rpc.handler.soap.SOAPMessageContext;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.TimeZone;
import java.util.Vector;

/**
 * Merged and converted the the axis handlers WSDoAllReceiver and WSDoAllSender
 * into a single JAX-RPC Handler. All the axis dependencies are removed.
 *
 * @author Venkat Reddy (vreddyp@gmail.com).
 */
public class WSS4JHandler implements Handler {
    private HandlerInfo handlerInfo;
    static Log log = LogFactory.getLog(WSS4JHandler.class.getName());
    static final WSSecurityEngine secEngine = new WSSecurityEngine();

    private boolean doDebug = true;
    private static Hashtable cryptos = new Hashtable(5);
    private SOAPMessageContext msgContext = null;

    Crypto sigCrypto = null;
    String sigPropFile = null;

    Crypto decCrypto = null;
    String decPropFile = null;

    protected int timeToLive = 300;
    private boolean noSerialization = false;
    private SOAPConstants soapConstants = null;

    String actor = null;
    String username = null;
    String pwType = null;
    String[] utElements = null;

    int sigKeyId = 0;
    String sigAlgorithm = null;
    Vector signatureParts = new Vector();

    Crypto encCrypto = null;
    int encKeyId = 0;
    String encSymmAlgo = null;
    String encKeyTransport = null;
    String encUser = null;
    Vector encryptParts = new Vector();
    X509Certificate encCert = null;

    static final String DEPLOYMENT = "deployment";
    static final String CLIENT_DEPLOYMENT = "client";
    static final String SERVER_DEPLOYMENT = "server";

    /**
     * Initializes the instance of the handler.
     */
    public void init(HandlerInfo hi) {
        handlerInfo = hi;
    }

    /**
     * Destroys the Handler instance.
     */
    public void destroy() {
    }

    public QName[] getHeaders() {
        return handlerInfo.getHeaders();
    }

    private void initialize() {
        signatureParts.removeAllElements();
        encryptParts.removeAllElements();
    }

    public boolean handleRequest(MessageContext mc) {
        return processMessage(mc, true);
    }

    public boolean handleResponse(MessageContext mc) {
        return processMessage(mc, false);
    }

    /**
     * Switch for transfering control to doReceiver and doSender
     */
    public boolean processMessage(MessageContext mc, boolean messageType) {
        String deployment = null;
        if ((deployment = (String) handlerInfo.getHandlerConfig().get(DEPLOYMENT)) == null) {
            deployment = (String) msgContext.getProperty(DEPLOYMENT);
        }

        if (deployment == null) {
            throw new JAXRPCException("WSS4JHandler.processMessage: No deployment defined");
        }

        // call doSender if we are -
        // (handling request and client-side deployment) or (handling response and server-side deployment).
        // call doReceiver if we are -
        // (handling request and server-side deployment) or (handling response and client-side deployment).
        if (deployment.equals(CLIENT_DEPLOYMENT) ^ messageType) {
            return doReceiver(mc);
        } else {
            return doSender(mc);
        }
    }

    /**
     * Handles incoming web service requests and outgoing responses
     */
    public boolean doSender(MessageContext mc) {
        msgContext = (SOAPMessageContext) mc;

        initialize();
        noSerialization = false;
        /*
        * Get the action first.
        */
        Vector actions = new Vector();
        String action = null;
        if ((action = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.ACTION)) == null) {
            action = (String) msgContext.getProperty(WSHandlerConstants.ACTION);
        }
        if (action == null) {
            throw new JAXRPCException("WSS4JHandler: No action defined");
        }
        int doAction = decodeAction(action, actions);
        if (doAction == WSConstants.NO_SECURITY) {
            return true;
        }

        boolean mu = decodeMustUnderstand();

        if ((actor = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.ACTOR)) == null) {
            actor = (String) msgContext.getProperty(WSHandlerConstants.ACTOR);
        }
        /*
        * For every action we need a username, so get this now. The username
        * defined in the deployment descriptor takes precedence.
        */
        username = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.USER);
        if (username == null || username.equals("")) {
            username = (String) msgContext.getProperty(WSHandlerConstants.USER);
            msgContext.setProperty(WSHandlerConstants.USER, null);
        }
        /*
        * Now we perform some set-up for UsernameToken and Signature
        * functions. No need to do it for encryption only. Check if username
        * is available and then get a passowrd.
        */
        if ((doAction & (WSConstants.SIGN | WSConstants.UT | WSConstants.UT_SIGN)) != 0) {
            /*
            * We need a username - if none throw an JAXRPCException. For encryption
            * there is a specific parameter to get a username.
            */
            if (username == null || username.equals("")) {
                throw new JAXRPCException("WSS4JHandler: Empty username for specified action");
            }
        }
        if (doDebug) {
            log.debug("Action: " + doAction);
            log.debug("Actor: " + actor + ", mu: " + mu);
        }
        /*
        * Now get the SOAP part from the request message and convert it into a
        * Document.
        *
        * This forces Axis to serialize the SOAP request into FORM_STRING.
        * This string is converted into a document.
        *
        * During the FORM_STRING serialization Axis performs multi-ref of
        * complex data types (if requested), generates and inserts references
        * for attachements and so on. The resulting Document MUST be the
        * complete and final SOAP request as Axis would send it over the wire.
        * Therefore this must shall be the last (or only) handler in a chain.
        *
        * Now we can perform our security operations on this request.
        */
        Document doc = null;
        SOAPMessage message = msgContext.getMessage();

        /*
        * If the message context property conatins a document then this is a
        * chained handler.
        */
        SOAPPart sPart = message.getSOAPPart();
        if ((doc = (Document) msgContext.getProperty(WSHandlerConstants.SND_SECURITY))
                == null) {
            try {
                doc = messageToDocument(message);
            } catch (Exception e) {
                throw new JAXRPCException("WSS4JHandler: cannot get SOAP envlope from message" + e);
            }
        }
        soapConstants =
                WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        /*
        * Here we have action, username, password, and actor, mustUnderstand.
        * Now get the action specific parameters.
        */
        if ((doAction & WSConstants.UT) == WSConstants.UT) {
            decodeUTParameter();
        }
        /*
        * Here we have action, username, password, and actor, mustUnderstand.
        * Now get the action specific parameters.
        */
        if ((doAction & WSConstants.UT_SIGN) == WSConstants.UT_SIGN) {
            decodeUTParameter();
            decodeSignatureParameter();
        }
        /*
        * Get and check the Signature specific parameters first because they
        * may be used for encryption too.
        */
        if ((doAction & WSConstants.SIGN) == WSConstants.SIGN) {
            decodeSignatureParameter();
        }
        /*
        * If we need to handle signed SAML token then we need may of the
        * Signature parameters. The handle procedure loads the signature
        * crypto file on demand, thus don't do it here.
        */
        if ((doAction & WSConstants.ST_SIGNED) == WSConstants.ST_SIGNED) {
            decodeSignatureParameter();
        }
        /*
        * Set and check the encryption specific parameters, if necessary take
        * over signature parameters username and crypto instance.
        */
        if ((doAction & WSConstants.ENCR) == WSConstants.ENCR) {
            encCrypto = loadEncryptionCrypto();
            decodeEncryptionParameter();
        }
        /*
        * Here we have all necessary information to perform the requested
        * action(s).
        */
        for (int i = 0; i < actions.size(); i++) {

            int actionToDo = ((Integer) actions.get(i)).intValue();
            if (doDebug) {
                log.debug("Performing Action: " + actionToDo);
            }

            switch (actionToDo) {
                case WSConstants.UT:
                    performUTAction(actionToDo, mu, doc);
                    break;

                case WSConstants.ENCR:
                    performENCRAction(mu, actionToDo, doc);
                    break;

                case WSConstants.SIGN:
                    performSIGNAction(actionToDo, mu, doc);
                    break;

                case WSConstants.ST_SIGNED:
                    performST_SIGNAction(actionToDo, mu, doc);
                    break;

                case WSConstants.ST_UNSIGNED:
                    performSTAction(mu, doc);
                    break;

                case WSConstants.TS:
                    performTSAction(mu, doc);
                    break;

                case WSConstants.UT_SIGN:
                    performUT_SIGNAction(actionToDo, mu, doc);
                    break;

                case WSConstants.NO_SERIALIZE:
                    noSerialization = true;
                    break;
            }
        }

        /*
        * If required convert the resulting document into a message first. The
        * outputDOM() method performs the necessary c14n call. After that we
        * extract it as a string for further processing.
        *
        * Set the resulting byte array as the new SOAP message.
        *
        * If noSerialization is false, this handler shall be the last (or only)
        * one in a handler chain. If noSerialization is true, just set the
        * processed Document in the transfer property. The next Axis WSS4J
        * handler takes it and performs additional security processing steps.
        *
        */
        if (noSerialization) {
            msgContext.setProperty(WSHandlerConstants.SND_SECURITY, doc);
        } else {
            ByteArrayOutputStream os = new ByteArrayOutputStream();
            // documentToStream(doc, os);
			XMLUtils.outputDOM(doc, os, true);

            try {
                sPart.setContent(new StreamSource(new ByteArrayInputStream(os.toByteArray())));
            } catch (SOAPException se) {
                throw new JAXRPCException("Couldn't set content on SOAPPart" + se.getMessage());
            }
            if (doDebug) {
                String osStr = null;
                try {
                    osStr = os.toString("UTF-8");
                } catch (UnsupportedEncodingException e) {
                    osStr = os.toString();
                }
                log.debug("Send request:");
                log.debug(osStr);
            }
            msgContext.setProperty(WSHandlerConstants.SND_SECURITY, null);
        }
        if (doDebug) {
            log.debug("WSS4JHandler: exit invoke()");
        }
        return true;
    }

/*
handle response
*/
    public boolean doReceiver(MessageContext mc) {
        msgContext = (SOAPMessageContext) mc;

        Vector actions = new Vector();
        String action = null;
        if ((action = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.ACTION)) == null) {
            action = (String) msgContext.getProperty(WSHandlerConstants.ACTION);
        }
        if (action == null) {
            throw new JAXRPCException("WSS4JHandler: No action defined");
        }
        int doAction = decodeAction(action, actions);

        String actor = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.ACTOR);

        SOAPMessage message = msgContext.getMessage();
        SOAPPart sPart = message.getSOAPPart();
        Document doc = null;
        try {
            doc = messageToDocument(message);
        } catch (Exception ex) {
            throw new JAXRPCException("WSS4JHandler: cannot convert into document",
                    ex);
        }
        /*
        * Check if it's a fault. Don't process faults.
        *
        */
        SOAPConstants soapConstants =
                WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
        if (WSSecurityUtil
                .findElement(doc.getDocumentElement(),
                        "Fault",
                        soapConstants.getEnvelopeURI())
                != null) {
            return false;
        }

        /*
        * To check a UsernameToken or to decrypt an encrypted message we need
        * a password.
        */
        CallbackHandler cbHandler = null;
        if ((doAction & (WSConstants.ENCR | WSConstants.UT)) != 0) {
            cbHandler = getPasswordCB();
        }

        /*
        * Get and check the Signature specific parameters first because they
        * may be used for encryption too.
        */

        if ((doAction & WSConstants.SIGN) == WSConstants.SIGN) {
            decodeSignatureParameter();
        }

        if ((doAction & WSConstants.ENCR) == WSConstants.ENCR) {
            decodeDecryptionParameter();
        }

        Vector wsResult = null;
        try {
            wsResult =
                    secEngine.processSecurityHeader(doc,
                            actor,
                            cbHandler,
                            sigCrypto,
                            decCrypto);
        } catch (WSSecurityException ex) {
            ex.printStackTrace();
            throw new JAXRPCException("WSS4JHandler: security processing failed",
                    ex);
        }
        if (wsResult == null) {			// no security header found
            if (doAction == WSConstants.NO_SECURITY) {
                return true;
            } else {
                throw new JAXRPCException("WSS4JHandler: Request does not contain required Security header");
            }
        }

        /*
        * If we had some security processing, get the original
        * SOAP part of Axis' message and replace it with new SOAP
        * part. This new part may contain decrypted elements.
        */

        ByteArrayOutputStream os = new ByteArrayOutputStream();
        // documentToStream(doc, os);
		XMLUtils.outputDOM(doc, os, true);
        try {
            sPart.setContent(new StreamSource(new ByteArrayInputStream(os.toByteArray())));
        } catch (SOAPException se) {
            throw new JAXRPCException("Couldn't set content on SOAPPart" + se.getMessage());
        }

        if (doDebug) {
            log.debug("Processed received SOAP request");
        }

        /*
        * After setting the new current message, probably modified because
        * of decryption, we need to locate the security header. That is,
        * we force Axis (with getSOAPEnvelope()) to parse the string, build
        * the new header. Then we examine, look up the security header
        * and set the header as processed.
        *
        * Please note: find all header elements that contain the same
        * actor that was given to processSecurityHeader(). Then
        * check if there is a security header with this actor.
        */

        SOAPHeader sHeader = null;
        try {
            sHeader = message.getSOAPPart().getEnvelope().getHeader();
        } catch (Exception ex) {
            throw new JAXRPCException("WSS4JHandler: cannot get SOAP header after security processing", ex);
        }

        Iterator headers = sHeader.examineHeaderElements(actor);

        SOAPHeaderElement headerElement = null;
        while (headers.hasNext()) {
            SOAPHeaderElement hE = (SOAPHeaderElement) headers.next();
            if (hE.getElementName().getLocalName().equals(WSConstants.WSSE_LN)
                    && ((Node) hE).getNamespaceURI().equals(WSConstants.WSSE_NS)) {
                headerElement = hE;
                break;
            }
        }

/* JAXRPC conversion changes */
/* commented axis specific code */
//		((org.apache.axis.message.SOAPHeaderElement) headerElement).setProcessed(true);
        headerElement.setMustUnderstand(false); // is this sufficient?

        /*
        * Now we can check the certificate used to sign the message.
        * In the following implementation the certificate is only trusted
        * if either it itself or the certificate of the issuer is installed
        * in the keystore.
        *
        * Note: the method verifyTrust(X509Certificate) allows custom
        * implementations with other validation algorithms for subclasses.
        */

        // Extract the signature action result from the action vector

        WSSecurityEngineResult actionResult = WSSecurityUtil.fetchActionResult(wsResult, WSConstants.SIGN);

        if (actionResult != null) {
            X509Certificate returnCert = actionResult.getCertificate();

            if (returnCert != null) {
                if (!verifyTrust(returnCert)) {
                    throw new JAXRPCException("WSS4JHandler: The certificate used for the signature is not trusted");
                }
            }
        }

        /*
        * Perform further checks on the timestamp that was transmitted in the header.
        * In the following implementation the timestamp is valid if it was
        * created after (now-ttl), where ttl is set on server side, not by the client.
        *
        * Note: the method verifyTimestamp(Timestamp) allows custom
        * implementations with other validation algorithms for subclasses.
        */

        // Extract the timestamp action result from the action vector
        actionResult = WSSecurityUtil.fetchActionResult(wsResult, WSConstants.TS);

        if (actionResult != null) {
            Timestamp timestamp = actionResult.getTimestamp();

            if (timestamp != null) {
                String ttl = null;
                if ((ttl =
                        (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.TTL_TIMESTAMP))
                        == null) {
                    ttl =
                            (String) msgContext.getProperty(WSHandlerConstants.TTL_TIMESTAMP);
                }
                int ttl_i = 0;
                if (ttl != null) {
                    try {
                        ttl_i = Integer.parseInt(ttl);
                    } catch (NumberFormatException e) {
                        ttl_i = timeToLive;
                    }
                }
                if (ttl_i <= 0) {
                    ttl_i = timeToLive;
                }

                if (!verifyTimestamp(timestamp, timeToLive)) {
                    throw new JAXRPCException("WSS4JHandler: The timestamp could not be validated");
                }
            }
        }

        /*
        * now check the security actions: do they match, in right order?
        */
        int resultActions = wsResult.size();
        int size = actions.size();
        if (size != resultActions) {
            throw new JAXRPCException("WSS4JHandler: security processing failed (actions number mismatch)");
        }
        for (int i = 0; i < size; i++) {
            if (((Integer) actions.get(i)).intValue()
                    != ((WSSecurityEngineResult) wsResult.get(i)).getAction()) {
                throw new JAXRPCException("WSS4JHandler: security processing failed (actions mismatch)");
            }
        }

        /*
        * All ok up to this point. Now construct and setup the
        * security result structure. The service may fetch this
        * and check it.
        */
        Vector results = null;
        if ((results = (Vector) mc.getProperty(WSHandlerConstants.RECV_RESULTS))
                == null) {
            results = new Vector();
            mc.setProperty(WSHandlerConstants.RECV_RESULTS, results);
        }
        WSHandlerResult rResult =
                new WSHandlerResult(actor,
                        wsResult);
        results.add(0, rResult);
        if (doDebug) {
            log.debug("WSS4JHandler: exit invoke()");
        }

        return true;
    }

    private void performSIGNAction(int actionToDo, boolean mu, Document doc)
            throws JAXRPCException {
        String password;
        password =
                getPassword(username,
                        actionToDo,
                        WSHandlerConstants.PW_CALLBACK_CLASS,
                        WSHandlerConstants.PW_CALLBACK_REF)
                .getPassword();

        WSSignEnvelope wsSign = new WSSignEnvelope(actor, mu);
        if (sigKeyId != 0) {
            wsSign.setKeyIdentifierType(sigKeyId);
        }
        if (sigAlgorithm != null) {
            wsSign.setSignatureAlgorithm(sigAlgorithm);
        }

        wsSign.setUserInfo(username, password);
        if (signatureParts.size() > 0) {
            wsSign.setParts(signatureParts);
        }

        try {
            wsSign.build(doc, sigCrypto);
        } catch (WSSecurityException e) {
            throw new JAXRPCException("WSS4JHandler: Signature: error during message procesing" + e);
        }

    }

    public static String parseToString(Node node) throws JAXRPCException {
        StringBuffer buffer = new StringBuffer();
        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            StringWriter stringWriter = new StringWriter(128);
            transformer.transform(new DOMSource(node), new StreamResult(stringWriter));
            buffer = stringWriter.getBuffer();
        } catch (TransformerException te) {
            throw new JAXRPCException("WSS4JHandler: couldn't convert Node into String: ", te);
        }
        return buffer.toString();
    }

    /**
     * Get the password callback class and get an instance
     * <p/>
     */
    private CallbackHandler getPasswordCB() throws JAXRPCException {

        String callback = null;
        CallbackHandler cbHandler = null;
        if ((callback = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.PW_CALLBACK_CLASS))
                == null) {
            callback =
                    (String) msgContext.getProperty(WSHandlerConstants.PW_CALLBACK_CLASS);
        }
        if (callback != null) {
            Class cbClass = null;
            try {
                cbClass = java.lang.Class.forName(callback);
            } catch (ClassNotFoundException e) {
                throw new JAXRPCException("WSS4JHandler: cannot load password callback class: "
                        + callback,
                        e);
            }
            try {
                cbHandler = (CallbackHandler) cbClass.newInstance();
            } catch (java.lang.Exception e) {
                throw new JAXRPCException("WSS4JHandler: cannot create instance of password callback: "
                        + callback,
                        e);
            }
        } else {
            cbHandler =
                    (CallbackHandler) msgContext.getProperty(WSHandlerConstants.PW_CALLBACK_REF);
            if (cbHandler == null) {
                throw new JAXRPCException("WSS4JHandler: no reference in callback property");
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
     * @return true if the certificate is trusted, false if not (JAXRPCException is thrown for exceptions during CertPathValidation)
     * @throws JAXRPCException
     */
    private boolean verifyTrust(X509Certificate cert) throws JAXRPCException {

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
            log.debug("WSS4JHandler: Transmitted certificate has subject " + subjectString);
            log.debug("WSS4JHandler: Transmitted certificate has issuer " + issuerString + " (serial " + issuerSerial + ")");
        }

        // FIRST step
        // Search the keystore for the transmitted certificate

        // Search the keystore for the alias of the transmitted certificate
        try {
            alias = sigCrypto.getAliasForX509Cert(issuerString, issuerSerial);
        } catch (WSSecurityException ex) {
            throw new JAXRPCException("WSS4JHandler: Could not get alias for certificate with " + subjectString, ex);
        }

        if (alias != null) {
            // Retrieve the certificate for the alias from the keystore
            try {
                certs = sigCrypto.getCertificates(alias);
            } catch (WSSecurityException ex) {
                throw new JAXRPCException("WSS4JHandler: Could not get certificates for alias " + alias, ex);
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
            aliases = sigCrypto.getAliasesForDN(issuerString);
        } catch (WSSecurityException ex) {
            throw new JAXRPCException("WSS4JHandler: Could not get alias for certificate with " + issuerString, ex);
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
                certs = sigCrypto.getCertificates(alias);
            } catch (WSSecurityException ex) {
                throw new JAXRPCException("WSS4JHandler: Could not get certificates for alias " + alias, ex);
            }

            // If no certificates have been found, there has to be an error:
            // The keystore can find an alias but no certificate(s)
            if (certs == null | certs.length < 1) {
                throw new JAXRPCException("WSS4JHandler: Could not get certificates for alias " + alias);
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
            throw new JAXRPCException("WSS4JHandler: Combination of subject and issuers certificates failed", ex);
            } catch (WSSecurityException ex) {
            throw new JAXRPCException("WSS4JHandler: Combination of subject and issuers certificates failed", ex);
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
                throw new JAXRPCException("WSS4JHandler: Combination of subject and issuers certificates failed", ex);
                } catch (WSSecurityException ex) {
                throw new JAXRPCException("WSS4JHandler: Combination of subject and issuers certificates failed", ex);
                }
                */

                x509certs[certs.length + j] = cert;
            }
            certs = x509certs;

            // Use the validation method from the crypto to check whether the subjects certificate was really signed by the issuer stated in the certificate
            try {
                if (sigCrypto.validateCertPath(certs)) {
                    if (doDebug) {
                        log.debug("WSS4JHandler: Certificate path has been verified for certificate with subject " + subjectString);
                    }
                    return true;
                }
            } catch (WSSecurityException ex) {
                throw new JAXRPCException("WSS4JHandler: Certificate path verification failed for certificate with subject " + subjectString, ex);
            }
        }

        log.debug("WSS4JHandler: Certificate path could not be verified for certificate with subject " + subjectString);
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
     * @throws JAXRPCException
     */
    protected boolean verifyTimestamp(Timestamp timestamp, int timeToLive) throws JAXRPCException {

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

    /**
     * Hook to allow subclasses to load their Signature Crypto however they see fit.
     */
    protected Crypto loadSignatureCrypto() throws JAXRPCException {
        Crypto crypto = null;
        if ((sigPropFile = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.SIG_PROP_FILE))
                == null) {
            sigPropFile =
                    (String) msgContext.getProperty(WSHandlerConstants.SIG_PROP_FILE);
        }
        if (sigPropFile != null) {
            if ((crypto = (Crypto) cryptos.get(sigPropFile)) == null) {
                crypto = CryptoFactory.getInstance(sigPropFile);
                cryptos.put(sigPropFile, crypto);
            }
        } else {
            throw new JAXRPCException("WSS4JHandler: Signature: no crypto property file");
        }
        return crypto;
    }

    /**
     * Hook to allow subclasses to load their Decryption Crypto however they see fit.
     */
    protected Crypto loadDecryptionCrypto() throws JAXRPCException {
        Crypto crypto = null;
        if ((decPropFile = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.DEC_PROP_FILE))
                == null) {
            decPropFile =
                    (String) msgContext.getProperty(WSHandlerConstants.DEC_PROP_FILE);
        }
        if (decPropFile != null) {
            if ((crypto = (Crypto) cryptos.get(decPropFile)) == null) {
                crypto = CryptoFactory.getInstance(decPropFile);
                cryptos.put(decPropFile, crypto);
            }
        } else if ((crypto = sigCrypto) == null) {
            throw new JAXRPCException("WSS4JHandler: Encryption: no crypto property file");
        }
        return crypto;
    }
    
    protected SAMLIssuer loadSamlIssuer() throws JAXRPCException{
        String samlPropFile = null;
        if ((samlPropFile =
                (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.SAML_PROP_FILE))
                == null) {
            samlPropFile =
                    (String) msgContext.getProperty(WSHandlerConstants.SAML_PROP_FILE);
        }
        return SAMLIssuerFactory.getInstance(samlPropFile);  
    }
    
    private void decodeSignatureParameter() throws JAXRPCException {
        sigCrypto = loadSignatureCrypto();
        /* There are currently no other signature parameters that need to be handled
        * here, but we call the load crypto hook rather than just changing the visibility
        * of this method to maintain parity with WSS4JHandler.
        */

        String tmpS = null;
        if ((tmpS = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.SIG_KEY_ID)) == null) {
            tmpS = (String) msgContext.getProperty(WSHandlerConstants.SIG_KEY_ID);
        }
        if (tmpS != null) {
            Integer I = (Integer) WSHandlerConstants.keyIdentifier.get(tmpS);
            if (I == null) {
                throw new JAXRPCException("WSS4JHandler: Signature: unknown key identification");
            }
            sigKeyId = I.intValue();
            if (!(sigKeyId == WSConstants.ISSUER_SERIAL
                    || sigKeyId == WSConstants.BST_DIRECT_REFERENCE
                    || sigKeyId == WSConstants.X509_KEY_IDENTIFIER
                    || sigKeyId == WSConstants.SKI_KEY_IDENTIFIER)) {
                throw new JAXRPCException("WSS4JHandler: Signature: illegal key identification");
            }
        }
        if ((sigAlgorithm = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.SIG_ALGO))
                == null) {
            tmpS = (String) msgContext.getProperty(WSHandlerConstants.SIG_ALGO);
        }
        if ((tmpS = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.SIGNATURE_PARTS))
                == null) {
            tmpS =
                    (String) msgContext.getProperty(WSHandlerConstants.SIGNATURE_PARTS);
        }
        if (tmpS != null) {
            splitEncParts(tmpS, signatureParts);
        }
    }

    /*
    * Set and check the decryption specific parameters, if necessary
    * take over signatur crypto instance.
    */

    private void decodeDecryptionParameter() throws JAXRPCException {
        decCrypto = loadDecryptionCrypto();
        /* There are currently no other decryption parameters that need to be handled
        * here, but we call the load crypto hook rather than just changing the visibility
        * of this method to maintain parity with WSS4JHandler.
        */
    }

    /**
     * Handles SOAP Faults that may occur during message processing
     */
    public boolean handleFault(MessageContext mc) {
        if (doDebug) {
            log.debug("Entered handleFault");
        }
        return true;
    }

    private void performENCRAction(boolean mu, int actionToDo, Document doc)
            throws JAXRPCException {
        WSEncryptBody wsEncrypt = new WSEncryptBody(actor, mu);
        if (encKeyId != 0) {
            wsEncrypt.setKeyIdentifierType(encKeyId);
        }
        if (encKeyId == WSConstants.EMBEDDED_KEYNAME) {
            String encKeyName = null;
            if ((encKeyName =
                    (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.ENC_KEY_NAME))
                    == null) {
                encKeyName =
                        (String) msgContext.getProperty(WSHandlerConstants.ENC_KEY_NAME);
            }
            wsEncrypt.setEmbeddedKeyName(encKeyName);
            byte[] embeddedKey =
                    getPassword(encUser,
                            actionToDo,
                            WSHandlerConstants.ENC_CALLBACK_CLASS,
                            WSHandlerConstants.ENC_CALLBACK_REF)
                    .getKey();
            wsEncrypt.setKey(embeddedKey);
        }
        if (encSymmAlgo != null) {
            wsEncrypt.setSymmetricEncAlgorithm(encSymmAlgo);
        }
        if (encKeyTransport != null) {
            wsEncrypt.setKeyEnc(encKeyTransport);
        }
        wsEncrypt.setUserInfo(encUser);
        wsEncrypt.setUseThisCert(encCert);
        if (encryptParts.size() > 0) {
            wsEncrypt.setParts(encryptParts);
        }
        try {
            wsEncrypt.build(doc, encCrypto);
        } catch (WSSecurityException e) {
            throw new JAXRPCException("WSS4JHandler: Encryption: error during message processing"
                    + e);
        }
    }

    private void performUTAction(int actionToDo, boolean mu, Document doc)
            throws JAXRPCException {
        String password;
        password =
                getPassword(username,
                        actionToDo,
                        WSHandlerConstants.PW_CALLBACK_CLASS,
                        WSHandlerConstants.PW_CALLBACK_REF)
                .getPassword();

        WSSAddUsernameToken builder = new WSSAddUsernameToken(actor, mu);
        builder.setPasswordType(pwType);
        // add the UsernameToken to the SOAP Enevelope
        builder.build(doc, username, password);

        if (utElements != null && utElements.length > 0) {
            for (int j = 0; j < utElements.length; j++) {
                utElements[j].trim();
                if (utElements[j].equals("Nonce")) {
                    builder.addNonce(doc);
                }
                if (utElements[j].equals("Created")) {
                    builder.addCreated(doc);
                }
            }
        }
    }

    private void performUT_SIGNAction(int actionToDo, boolean mu, Document doc)
            throws JAXRPCException {
        String password;
        password = getPassword(username, actionToDo,
                WSHandlerConstants.PW_CALLBACK_CLASS,
                WSHandlerConstants.PW_CALLBACK_REF).getPassword();

        WSSAddUsernameToken builder = new WSSAddUsernameToken(actor, mu);
        builder.setPasswordType(WSConstants.PASSWORD_TEXT);
        builder.preSetUsernameToken(doc, username, password);
        builder.addCreated(doc);
        builder.addNonce(doc);

        WSSignEnvelope sign = new WSSignEnvelope(actor, mu);
        sign.setUsernameToken(builder);
        if (signatureParts.size() > 0) {
            sign.setParts(signatureParts);
        }
        sign.setKeyIdentifierType(WSConstants.UT_SIGNING);
        sign.setSignatureAlgorithm(XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
        try {
            sign.build(doc, null);
        } catch (WSSecurityException e) {
            throw new JAXRPCException("WSS4JHandler: Error during Signatur with UsernameToken secret"
                    + e);
        }
        builder.build(doc, null, null);
    }

    private void performSTAction(boolean mu, Document doc)
            throws JAXRPCException {
        WSSAddSAMLToken builder = new WSSAddSAMLToken(actor, mu);
        SAMLIssuer saml = loadSamlIssuer();
        saml.setUsername(username);
        SAMLAssertion assertion = saml.newAssertion();

        // add the SAMLAssertion Token to the SOAP Enevelope
        builder.build(doc, assertion);
    }

    private void performST_SIGNAction(int actionToDo, boolean mu, Document doc)
            throws JAXRPCException {
        Crypto crypto = null;
        crypto = loadSignatureCrypto();
        SAMLIssuer saml = loadSamlIssuer();

        saml.setUsername(username);
        saml.setUserCrypto(crypto);
        saml.setInstanceDoc(doc);

        SAMLAssertion assertion = saml.newAssertion();
        if (assertion == null) {
            throw new JAXRPCException("WSS4JHandler: Signed SAML: no SAML token received");
        }
        String issuerKeyName = null;
        String issuerKeyPW = null;
        Crypto issuerCrypto = null;

        WSSignEnvelope wsSign = new WSSignEnvelope(actor, mu);
        String password = null;
        if (saml.isSenderVouches()) {
            issuerKeyName = saml.getIssuerKeyName();
            issuerKeyPW = saml.getIssuerKeyPassword();
            issuerCrypto = saml.getIssuerCrypto();
        } else {
            password =
                    getPassword(username,
                            actionToDo,
                            WSHandlerConstants.PW_CALLBACK_CLASS,
                            WSHandlerConstants.PW_CALLBACK_REF)
                    .getPassword();
            wsSign.setUserInfo(username, password);
        }
        if (sigKeyId != 0) {
            wsSign.setKeyIdentifierType(sigKeyId);
        }
        try {
            wsSign.build(doc,
                    crypto,
                    assertion,
                    issuerCrypto,
                    issuerKeyName,
                    issuerKeyPW);
        } catch (WSSecurityException e) {
            throw new JAXRPCException("WSS4JHandler: Signed SAML: error during message processing"
                    + e);
        }
    }

    private void performTSAction(boolean mu, Document doc) throws JAXRPCException {
        String ttl = null;
        if ((ttl =
                (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.TTL_TIMESTAMP))
                == null) {
            ttl =
                    (String) msgContext.getProperty(WSHandlerConstants.TTL_TIMESTAMP);
        }
        int ttl_i = 0;
        if (ttl != null) {
            try {
                ttl_i = Integer.parseInt(ttl);
            } catch (NumberFormatException e) {
                ttl_i = timeToLive;
            }
        }
        if (ttl_i <= 0) {
            ttl_i = timeToLive;
        }
        WSAddTimestamp timeStampBuilder =
                new WSAddTimestamp(actor, mu);
        // add the Timestamp to the SOAP Enevelope
        timeStampBuilder.build(doc, ttl_i);
    }

    static public int decodeAction(String action, Vector actions)
            throws JAXRPCException {

        int doAction = 0;

        if (action == null) {
            return doAction;
        }
        String single[] = StringUtil.split(action, ' ');
        for (int i = 0; i < single.length; i++) {
            if (single[i].equals(WSHandlerConstants.NO_SECURITY)) {
                doAction = WSConstants.NO_SECURITY;
                return doAction;
            } else if (single[i].equals(WSHandlerConstants.USERNAME_TOKEN)) {
                doAction |= WSConstants.UT;
                actions.add(new Integer(WSConstants.UT));
            } else if (single[i].equals(WSHandlerConstants.SIGNATURE)) {
                doAction |= WSConstants.SIGN;
                actions.add(new Integer(WSConstants.SIGN));
            } else if (single[i].equals(WSHandlerConstants.ENCRYPT)) {
                doAction |= WSConstants.ENCR;
                actions.add(new Integer(WSConstants.ENCR));
            } else if (single[i].equals(WSHandlerConstants.SAML_TOKEN_UNSIGNED)) {
                doAction |= WSConstants.ST_UNSIGNED;
                actions.add(new Integer(WSConstants.ST_UNSIGNED));
            } else if (single[i].equals(WSHandlerConstants.SAML_TOKEN_SIGNED)) {
                doAction |= WSConstants.ST_SIGNED;
                actions.add(new Integer(WSConstants.ST_SIGNED));
            } else if (single[i].equals(WSHandlerConstants.TIMESTAMP)) {
                doAction |= WSConstants.TS;
                actions.add(new Integer(WSConstants.TS));
            } else if (single[i].equals(WSHandlerConstants.NO_SERIALIZATION)) {
                doAction |= WSConstants.NO_SERIALIZE;
                actions.add(new Integer(WSConstants.NO_SERIALIZE));
            } else if (single[i].equals(WSHandlerConstants.SIGN_WITH_UT_KEY)) {
                doAction |= WSConstants.UT_SIGN;
                actions.add(new Integer(WSConstants.UT_SIGN));
            } else {
                throw new JAXRPCException("WSS4JHandler: Unknown action defined" + single[i]);
            }
        }
        return doAction;
    }

    private boolean decodeMustUnderstand() throws JAXRPCException {
        boolean mu = true;
        String mustUnderstand = null;
        if ((mustUnderstand =
                (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.MUST_UNDERSTAND))
                == null) {
            mustUnderstand =
                    (String) msgContext.getProperty(WSHandlerConstants.MUST_UNDERSTAND);
        }
        if (mustUnderstand != null) {
            if (mustUnderstand.equals("0") || mustUnderstand.equals("false")) {
                mu = false;
            } else if (
                    mustUnderstand.equals("1") || mustUnderstand.equals("true")) {
                mu = true;
            } else {
                throw new JAXRPCException("WSS4JHandler: illegal mustUnderstand parameter");
            }
        }
        return mu;
    }

    private void decodeUTParameter() throws JAXRPCException {
        if ((pwType = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.PASSWORD_TYPE))
                == null) {
            pwType =
                    (String) msgContext.getProperty(WSHandlerConstants.PASSWORD_TYPE);
        }
        if (pwType != null) {
            pwType =
                    pwType.equals(WSConstants.PW_TEXT)
                    ? WSConstants.PASSWORD_TEXT
                    : WSConstants.PASSWORD_DIGEST;
        }
        String tmpS = null;
        if ((tmpS = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.ADD_UT_ELEMENTS))
                == null) {
            tmpS =
                    (String) msgContext.getProperty(WSHandlerConstants.ADD_UT_ELEMENTS);
        }
        if (tmpS != null) {
            utElements = StringUtil.split(tmpS, ' ');
        }
    }

    /**
     * Hook to allow subclasses to load their Encryption Crypto however they
     * see fit.
     */
    protected Crypto loadEncryptionCrypto() throws JAXRPCException {
        Crypto crypto = null;
        /*
        * Get encryption crypto property file. If non specified take crypto
        * instance from signature, if that fails: throw fault
        */
        String encPropFile = null;
        if ((encPropFile = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.ENC_PROP_FILE))
                == null) {
            encPropFile =
                    (String) msgContext.getProperty(WSHandlerConstants.ENC_PROP_FILE);
        }
        if (encPropFile != null) {
            if ((crypto = (Crypto) cryptos.get(encPropFile)) == null) {
                crypto = CryptoFactory.getInstance(encPropFile);
                cryptos.put(encPropFile, crypto);
            }
        } else if ((crypto = sigCrypto) == null) {
            throw new JAXRPCException("WSS4JHandler: Encryption: no crypto property file");
        }
        return crypto;
    }

    private void decodeEncryptionParameter() throws JAXRPCException {
        if ((encUser = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.ENCRYPTION_USER))
                == null) {
            encUser =
                    (String) msgContext.getProperty(WSHandlerConstants.ENCRYPTION_USER);
        }

        if (encUser == null && (encUser = username) == null) {
            throw new JAXRPCException("WSS4JHandler: Encryption: no username");
        }
        /*
        * String msgType = msgContext.getCurrentMessage().getMessageType(); if
        * (msgType != null && msgType.equals(Message.RESPONSE)) {
        * handleSpecialUser(encUser); }
        */
        handleSpecialUser(encUser);

        /*
        * If the following parameters are no used (they return null) then the
        * default values of WSS4J are used.
        */
        String tmpS = null;
        if ((tmpS = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.ENC_KEY_ID)) == null) {
            tmpS = (String) msgContext.getProperty(WSHandlerConstants.ENC_KEY_ID);
        }
        if (tmpS != null) {
            Integer I = (Integer) WSHandlerConstants.keyIdentifier.get(tmpS);
            if (I == null) {
                throw new JAXRPCException("WSS4JHandler: Encryption: unknown key identification");
            }
            encKeyId = I.intValue();
            if (!(encKeyId == WSConstants.ISSUER_SERIAL
                    || encKeyId == WSConstants.X509_KEY_IDENTIFIER
                    || encKeyId == WSConstants.SKI_KEY_IDENTIFIER
                    || encKeyId == WSConstants.BST_DIRECT_REFERENCE
                    || encKeyId == WSConstants.EMBEDDED_KEYNAME)) {
                throw new JAXRPCException("WSS4JHandler: Encryption: illegal key identification");
            }
        }
        if ((encSymmAlgo = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.ENC_SYM_ALGO))
                == null) {
            encSymmAlgo =
                    (String) msgContext.getProperty(WSHandlerConstants.ENC_SYM_ALGO);
        }
        if ((encKeyTransport =
                (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.ENC_KEY_TRANSPORT))
                == null) {
            encKeyTransport =
                    (String) msgContext.getProperty(WSHandlerConstants.ENC_KEY_TRANSPORT);
        }
        if ((tmpS = (String) handlerInfo.getHandlerConfig().get(WSHandlerConstants.ENCRYPTION_PARTS))
                == null) {
            tmpS =
                    (String) msgContext.getProperty(WSHandlerConstants.ENCRYPTION_PARTS);
        }
        if (tmpS != null) {
            splitEncParts(tmpS, encryptParts);
        }
    }

    private void handleSpecialUser(String encUser) {
        if (!WSHandlerConstants.USE_REQ_SIG_CERT.equals(encUser)) {
            return;
        }
        Vector results = null;
        if ((results =
                (Vector) msgContext.getProperty(WSHandlerConstants.RECV_RESULTS))
                == null) {
            return;
        }
        /*
        * Scan the results for a matching actor. Use results only if the
        * receiving Actor and the sending Actor match.
        */
        for (int i = 0; i < results.size(); i++) {
            WSHandlerResult rResult =
                    (WSHandlerResult) results.get(i);
            String hActor = rResult.getActor();
            if (!WSSecurityUtil.isActorEqual(actor, hActor)) {
                continue;
            }
            Vector wsSecEngineResults = rResult.getResults();
            /*
            * Scan the results for the first Signature action. Use the
            * certificate of this Signature to set the certificate for the
            * encryption action :-).
            */
            for (int j = 0; j < wsSecEngineResults.size(); j++) {
                WSSecurityEngineResult wser =
                        (WSSecurityEngineResult) wsSecEngineResults.get(j);
                if (wser.getAction() == WSConstants.SIGN) {
                    encCert = wser.getCertificate();
                    return;
                }
            }
        }
    }

    private void splitEncParts(String tmpS, Vector encryptParts)
            throws JAXRPCException {
        WSEncryptionPart encPart = null;
        String[] rawParts = StringUtil.split(tmpS, ';');

        for (int i = 0; i < rawParts.length; i++) {
            String[] partDef = StringUtil.split(rawParts[i], '}');

            if (partDef.length == 1) {
                if (doDebug) {
                    log.debug("single partDef: '" + partDef[0] + "'");
                }
                encPart =
                        new WSEncryptionPart(partDef[0].trim(),
                                soapConstants.getEnvelopeURI(),
                                "Content");
            } else if (partDef.length == 3) {
                String mode = partDef[0].trim();
                if (mode.length() <= 1) {
                    mode = "Content";
                } else {
                    mode = mode.substring(1);
                }
                String nmSpace = partDef[1].trim();
                if (nmSpace.length() <= 1) {
                    nmSpace = soapConstants.getEnvelopeURI();
                } else {
                    nmSpace = nmSpace.substring(1);
                }
                String element = partDef[2].trim();
                if (doDebug) {
                    log.debug("partDefs: '"
                            + mode
                            + "' ,'"
                            + nmSpace
                            + "' ,'"
                            + element
                            + "'");
                }
                encPart = new WSEncryptionPart(element, nmSpace, mode);
            } else {
                throw new JAXRPCException("WSS4JHandler: wrong part definition: " + tmpS);
            }
            encryptParts.add(encPart);
        }
    }

    /**
     * Get a password to construct a UsernameToken or sign a message.
     * <p/>
     * Try all possible sources to get a password.
     */
    private WSPasswordCallback getPassword(String username,
                                           int doAction,
                                           String clsProp,
                                           String refProp)
            throws JAXRPCException {
        WSPasswordCallback pwCb = null;
        String password = null;
        String callback = null;
        CallbackHandler cbHandler = null;

        if ((callback = (String) handlerInfo.getHandlerConfig().get(clsProp)) == null) {
            callback = (String) msgContext.getProperty(clsProp);
        }
        if (callback != null) { // we have a password callback class
            pwCb = readPwViaCallbackClass(callback, username, doAction);
            if ((pwCb.getPassword() == null) && (pwCb.getKey() == null)) {
                throw new JAXRPCException("WSS4JHandler: password callback class provided null or empty password");
            }
        } else if (
                (cbHandler = (CallbackHandler) msgContext.getProperty(refProp))
                != null) {
            pwCb = performCallback(cbHandler, username, doAction);
            if ((pwCb.getPassword() == null) && (pwCb.getKey() == null)) {
                throw new JAXRPCException("WSS4JHandler: password callback provided null or empty password");
            }
        } else if ((password = (String) msgContext.getProperty(Call.PASSWORD_PROPERTY)) == null) {
            throw new JAXRPCException("WSS4JHandler: application provided null or empty password");
        } else {
            msgContext.setProperty(Call.PASSWORD_PROPERTY, null);
            pwCb = new WSPasswordCallback("", WSPasswordCallback.UNKNOWN);
            pwCb.setPassword(password);
        }
        return pwCb;
    }

    private WSPasswordCallback readPwViaCallbackClass(String callback,
                                                      String username,
                                                      int doAction)
            throws JAXRPCException {

        Class cbClass = null;
        CallbackHandler cbHandler = null;
        try {
            cbClass = java.lang.Class.forName(callback);
        } catch (ClassNotFoundException e) {
            throw new JAXRPCException("WSS4JHandler: cannot load password callback class: "
                    + callback,
                    e);
        }
        try {
            cbHandler = (CallbackHandler) cbClass.newInstance();
        } catch (java.lang.Exception e) {
            throw new JAXRPCException("WSS4JHandler: cannot create instance of password callback: "
                    + callback,
                    e);
        }
        return (performCallback(cbHandler, username, doAction));
    }

    /**
     * Perform a callback to get a password.
     * <p/>
     * The called back function gets an indication why to provide a password:
     * to produce a UsernameToken, Signature, or a password (key) for a given
     * name.
     */
    private WSPasswordCallback performCallback(CallbackHandler cbHandler,
                                               String username,
                                               int doAction)
            throws JAXRPCException {

        WSPasswordCallback pwCb = null;
        int reason = 0;

        switch (doAction) {
            case WSConstants.UT:
            case WSConstants.UT_SIGN:
                reason = WSPasswordCallback.USERNAME_TOKEN;
                break;
            case WSConstants.SIGN:
                reason = WSPasswordCallback.SIGNATURE;
                break;
            case WSConstants.ENCR:
                reason = WSPasswordCallback.KEY_NAME;
                break;
        }
        pwCb = new WSPasswordCallback(username, reason);
        Callback[] callbacks = new Callback[1];
        callbacks[0] = pwCb;
        /*
        * Call back the application to get the password
        */
        try {
            cbHandler.handle(callbacks);
        } catch (java.lang.Exception e) {
            throw new JAXRPCException("WSS4JHandler: password callback failed", e);
        }
        return pwCb;
    }

    /**
     * Utility method to convert SOAPMessage to org.w3c.dom.Document
     */
    public static Document messageToDocument(SOAPMessage message) {

        Document doc = null;
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            message.writeTo(baos);
            ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());

            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            dbf.setNamespaceAware(true);
            DocumentBuilder builder = dbf.newDocumentBuilder();

            doc = builder.parse(bais);

        } catch (Exception ex) {
            throw new JAXRPCException("messageToDocument: cannot convert SOAPMessage into Document", ex);
        }

        return doc;
    }

    /**
     * Utility method to convert org.w3c.dom.Document into java.io.OutputStream
     */
    public static void documentToStream(Document doc, OutputStream os) {
        try {
            DOMSource domSource = new DOMSource(doc);
            StreamResult result = new StreamResult(os);
            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();
            transformer.transform(domSource, result);
        } catch (Exception ex) {
            throw new JAXRPCException("documentToStream : cannot convert document into stream", ex);
        }
    }
}
