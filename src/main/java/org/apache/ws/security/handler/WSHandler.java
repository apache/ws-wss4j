/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ws.security.handler;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.action.Action;
import org.apache.ws.security.components.crypto.AlgorithmSuite;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.token.SignatureConfirmation;
import org.apache.ws.security.util.Loader;
import org.apache.ws.security.util.StringUtil;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;


/**
 * Extracted from WSDoAllReceiver and WSDoAllSender
 * Extended to all passwordless UsernameTokens and configurable identities.
 *
 * @author Davanum Srinivas (dims@yahoo.com).
 * @author Werner Dittmann (Werner.Dittmann@t-online.de).
 * @author Marcel Ammerlaan (marcel.ammerlaan@gmail.com).
 */
public abstract class WSHandler {
    private static org.apache.commons.logging.Log log = 
        org.apache.commons.logging.LogFactory.getLog(WSHandler.class);
    protected WSSecurityEngine secEngine = new WSSecurityEngine();
    protected Map<String, Crypto> cryptos = new ConcurrentHashMap<String, Crypto>();

    private boolean doDebug = log.isDebugEnabled();

    /**                                                             
     * Performs all defined security actions to set-up the SOAP request.
     * 
     * 
     * @param doAction a set defining the actions to do 
     * @param doc   the request as DOM document 
     * @param reqData a data storage to pass values around between methods
     * @param actions a list holding the actions to do in the order defined
     *                in the deployment file or property
     * @throws WSSecurityException
     */
    @SuppressWarnings("unchecked")
    protected void doSenderAction(
            int doAction, 
            Document doc,
            RequestData reqData, 
            List<Integer> actions, 
            boolean isRequest
    ) throws WSSecurityException {

        boolean mu = decodeMustUnderstand(reqData);

        WSSConfig wssConfig = reqData.getWssConfig();
        if (wssConfig == null) {
            wssConfig = secEngine.getWssConfig();
        }

        boolean enableSigConf = decodeEnableSignatureConfirmation(reqData);
        wssConfig.setEnableSignatureConfirmation(
            enableSigConf || ((doAction & WSConstants.SC) != 0)
        );
        wssConfig.setPasswordsAreEncoded(decodeUseEncodedPasswords(reqData));

        wssConfig.setPrecisionInMilliSeconds(
            decodeTimestampPrecision(reqData)
        );
        reqData.setWssConfig(wssConfig);

        Object mc = reqData.getMsgContext();
        String actor = getString(WSHandlerConstants.ACTOR, mc);
        reqData.setActor(actor);

        WSSecHeader secHeader = new WSSecHeader(actor, mu);
        secHeader.insertSecurityHeader(doc);

        reqData.setSecHeader(secHeader);
        reqData.setSoapConstants(
            WSSecurityUtil.getSOAPConstants(doc.getDocumentElement())
        );
        wssConfig.setWsiBSPCompliant(decodeBSPCompliance(reqData));
        /*
         * Here we have action, username, password, and actor, mustUnderstand.
         * Now get the action specific parameters.
         */
        if ((doAction & WSConstants.UT) == WSConstants.UT) {
            decodeUTParameter(reqData);
        }
        /*
         * Here we have action, username, password, and actor, mustUnderstand.
         * Now get the action specific parameters.
         */
        if ((doAction & WSConstants.UT_SIGN) == WSConstants.UT_SIGN) {
            decodeUTParameter(reqData);
            decodeSignatureParameter(reqData);
        }
        /*
         * Get and check the Signature specific parameters first because they
         * may be used for encryption too.
         */
        if ((doAction & WSConstants.SIGN) == WSConstants.SIGN) {
            if (reqData.getSigCrypto() == null) {
                reqData.setSigCrypto(loadSignatureCrypto(reqData));
            }
            decodeSignatureParameter(reqData);
        }
        /*
         * If we need to handle signed SAML token then we may need the
         * Signature parameters. The handle procedure loads the signature crypto
         * file on demand, thus don't do it here.
         */
        if ((doAction & WSConstants.ST_SIGNED) == WSConstants.ST_SIGNED) {
            decodeSignatureParameter(reqData);
        }
        /*
         * Set and check the encryption specific parameters, if necessary take
         * over signature parameters username and crypto instance.
         */
        if ((doAction & WSConstants.ENCR) == WSConstants.ENCR) {
            if (reqData.getEncCrypto() == null) {
                reqData.setEncCrypto(loadEncryptionCrypto(reqData));
            }
            decodeEncryptionParameter(reqData);
        }
        /*
         * If after all the parsing no Signature parts defined, set here a
         * default set. This is necessary because we add SignatureConfirmation
         * and therefore the default (Body) must be set here. The default setting
         * in WSSignEnvelope doesn't work because the vector is not empty anymore.
         */
        if (reqData.getSignatureParts().isEmpty()) {
            WSEncryptionPart encP = new WSEncryptionPart(reqData.getSoapConstants()
                    .getBodyQName().getLocalPart(), reqData.getSoapConstants()
                    .getEnvelopeURI(), "Content");
            reqData.getSignatureParts().add(encP);
        }
        /*
         * If SignatureConfirmation is enabled and this is a response then
         * insert SignatureConfirmation elements, note their wsu:id in the signature
         * parts. They will be signed automatically during a (probably) defined
         * SIGN action.
         */
        if (wssConfig.isEnableSignatureConfirmation() && !isRequest) {
            String done = 
                (String)getProperty(reqData.getMsgContext(), WSHandlerConstants.SIG_CONF_DONE);
            if (done == null) {
                wssConfig.getAction(WSConstants.SC).execute(this, WSConstants.SC, doc, reqData);
            }
        }
        
        // See if the Signature and Timestamp actions (in that order) are defined, and if
        // the Timestamp is to be signed. In this case we need to swap the actions, as the 
        // Timestamp must appear in the security header first for signature creation to work.
        List<Integer> actionsToPerform = actions;
        if (actions.contains(WSConstants.SIGN) && actions.contains(WSConstants.TS)
            && (actions.indexOf(WSConstants.SIGN) < actions.indexOf(WSConstants.TS))) {
            boolean signTimestamp = false;
            for (WSEncryptionPart encP : reqData.getSignatureParts()) {
                if (WSConstants.WSU_NS.equals(encP.getNamespace()) 
                    && "Timestamp".equals(encP.getName())) {
                    signTimestamp = true;
                }
            }
            if (signTimestamp) {
                actionsToPerform = new ArrayList<Integer>(actions);
                Collections.copy(actionsToPerform, actions);
                actionsToPerform.remove(actions.indexOf(WSConstants.SIGN));
                actionsToPerform.add(WSConstants.SIGN);
                reqData.setAppendSignatureAfterTimestamp(true);
            }
        }
        
        /*
         * Here we have all necessary information to perform the requested
         * action(s).
         */
        for (Integer actionToDo : actionsToPerform) {
            if (doDebug) {
                log.debug("Performing Action: " + actionToDo);
            }

            switch (actionToDo) {
            case WSConstants.UT:
            case WSConstants.ENCR:
            case WSConstants.SIGN:
            case WSConstants.ST_SIGNED:
            case WSConstants.ST_UNSIGNED:
            case WSConstants.TS:
            case WSConstants.UT_SIGN:
                wssConfig.getAction(actionToDo).execute(this, actionToDo, doc, reqData);
                break;
                //
                // Handle any "custom" actions, similarly,
                // but to preserve behavior from previous
                // versions, consume (but log) action lookup failures.
                //
            default:
                Action doit = null;
            try {
                doit = wssConfig.getAction(actionToDo);
            } catch (final WSSecurityException e) {
                log.warn(
                        "Error trying to locate a custom action (" + actionToDo + ")", 
                        e
                );
            }
            if (doit != null) {
                doit.execute(this, actionToDo, doc, reqData);
            }
            }
        }
        
        /*
         * If this is a request then store all signature values. Add ours to
         * already gathered values because of chained handlers, e.g. for
         * other actors.
         */
        if (wssConfig.isEnableSignatureConfirmation() 
            && isRequest && reqData.getSignatureValues().size() > 0) {
            List<byte[]> savedSignatures = 
                (List<byte[]>)getProperty(reqData.getMsgContext(), WSHandlerConstants.SEND_SIGV);
            if (savedSignatures == null) {
                savedSignatures = new ArrayList<byte[]>();
                setProperty(
                    reqData.getMsgContext(), WSHandlerConstants.SEND_SIGV, savedSignatures
                );
            }
            savedSignatures.addAll(reqData.getSignatureValues());
        }
    }

    protected void doReceiverAction(int doAction, RequestData reqData)
        throws WSSecurityException {

        WSSConfig wssConfig = reqData.getWssConfig();
        if (wssConfig == null) {
            wssConfig = secEngine.getWssConfig();
        }
        boolean enableSigConf = decodeEnableSignatureConfirmation(reqData);
        wssConfig.setEnableSignatureConfirmation(
            enableSigConf || ((doAction & WSConstants.SC) != 0)
        );
        wssConfig.setTimeStampStrict(decodeTimestampStrict(reqData));
        if (decodePasswordTypeStrict(reqData)) {
            String passwordType = decodePasswordType(reqData);
            wssConfig.setRequiredPasswordType(passwordType);
        }
        wssConfig.setTimeStampTTL(decodeTimeToLive(reqData));
        wssConfig.setTimeStampFutureTTL(decodeFutureTimeToLive(reqData));
        wssConfig.setHandleCustomPasswordTypes(decodeCustomPasswordTypes(reqData));
        wssConfig.setPasswordsAreEncoded(decodeUseEncodedPasswords(reqData));
        wssConfig.setAllowNamespaceQualifiedPasswordTypes(
            decodeNamespaceQualifiedPasswordTypes(reqData)
        );
        wssConfig.setSecretKeyLength(reqData.getSecretKeyLength());
        wssConfig.setWsiBSPCompliant(decodeBSPCompliance(reqData));
        reqData.setWssConfig(wssConfig);

        if ((doAction & WSConstants.SIGN) == WSConstants.SIGN) {
            decodeSignatureParameter2(reqData);
        }
        
        if (((doAction & WSConstants.ST_SIGNED) == WSConstants.ST_SIGNED)
            || ((doAction & WSConstants.ST_UNSIGNED) == WSConstants.ST_UNSIGNED)) {
            decodeSignatureParameter2(reqData);
        }
        
        if ((doAction & WSConstants.ENCR) == WSConstants.ENCR) {
            decodeDecryptionParameter(reqData);
        }
        decodeRequireSignedEncryptedDataElements(reqData);
    }

    protected boolean checkReceiverResults(
        List<WSSecurityEngineResult> wsResult, List<Integer> actions
    ) {
        int size = actions.size();
        int ai = 0;
        for (WSSecurityEngineResult result : wsResult) {
            final Integer actInt = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            int act = actInt.intValue();
            if (act == WSConstants.SC || act == WSConstants.BST) {
                continue;
            }
            
            if (ai >= size || actions.get(ai++).intValue() != act) {
                return false;
            }
        }

        if (ai != size) {
            return false;
        }

        return true;
    }
    
    protected boolean checkReceiverResultsAnyOrder(
        List<WSSecurityEngineResult> wsResult, List<Integer> actions
    ) {
        List<Integer> recordedActions = new ArrayList<Integer>(actions.size());
        for (Integer action : actions) {
            recordedActions.add(action);
        }
        
        for (WSSecurityEngineResult result : wsResult) {
            final Integer actInt = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            int act = actInt.intValue();
            if (act == WSConstants.SC || act == WSConstants.BST) {
                continue;
            }
            
            if (!recordedActions.remove(actInt)) {
                return false;
            }
        }

        if (!recordedActions.isEmpty()) {
            return false;
        }

        return true;
    }

    @SuppressWarnings("unchecked")
    protected void checkSignatureConfirmation(
        RequestData reqData,
        List<WSSecurityEngineResult> resultList
    ) throws WSSecurityException{
        if (doDebug) {
            log.debug("Check Signature confirmation");
        }
        //
        // First get all Signature values stored during sending the request
        //
        List<byte[]> savedSignatures = 
            (List<byte[]>) getProperty(reqData.getMsgContext(), WSHandlerConstants.SEND_SIGV);
        //
        // Now get all results that hold a SignatureConfirmation element from
        // the current run of receiver (we can have more than one run: if we
        // have several security header blocks with different actors/roles)
        //
        List<WSSecurityEngineResult> sigConf = new ArrayList<WSSecurityEngineResult>();
        WSSecurityUtil.fetchAllActionResults(resultList, WSConstants.SC, sigConf);
        //
        // now loop over all SignatureConfirmation results and check:
        // - if there is a signature value and no Signature value generated in request: error
        // - if there is a signature value and no matching Signature value found: error
        // 
        //  If a matching value found: remove from vector of stored signature values
        //
        for (WSSecurityEngineResult result : sigConf) {
            SignatureConfirmation sc = 
                (SignatureConfirmation)result.get(
                    WSSecurityEngineResult.TAG_SIGNATURE_CONFIRMATION
                );

            byte[] sigVal = sc.getSignatureValue();
            if (sigVal != null) {
                if (savedSignatures == null || savedSignatures.size() == 0) {
                    //
                    // If there are no stored signature values, and we've received a 
                    // SignatureConfirmation element then throw an Exception
                    //
                    if (sigVal.length != 0) {
                        throw new WSSecurityException(
                            "Received a SignatureConfirmation element, but there are no stored"
                             + " signature values"
                        );
                    }
                } else {
                    boolean found = false;
                    for (int j = 0; j < savedSignatures.size(); j++) {
                        byte[] storedValue = (byte[]) savedSignatures.get(j);
                        if (Arrays.equals(sigVal, storedValue)) {
                            found = true;
                            savedSignatures.remove(j);
                            break;
                        }
                    }
                    if (!found) {
                        throw new WSSecurityException(
                            "Received a SignatureConfirmation element, but there are no matching"
                            + " stored signature values"
                        );
                    } 
                }
            }
        }

        //
        // This indicates this is the last handler: the list holding the
        // stored Signature values must be empty, otherwise we have an error
        //
        if (!reqData.isNoSerialization()) {
            if (doDebug) {
                log.debug("Check Signature confirmation - last handler");
            }
            if (savedSignatures != null && !savedSignatures.isEmpty()) {
                throw new WSSecurityException(
                    "Check Signature confirmation: the stored signature values list is not empty"
                );
            }
        }
    }
    
    protected void decodeUTParameter(RequestData reqData) 
        throws WSSecurityException {
        Object mc = reqData.getMsgContext();
        
        String type = getString(WSHandlerConstants.PASSWORD_TYPE, mc);
        if (type != null) {
            if (WSConstants.PW_TEXT.equals(type)) {
                reqData.setPwType(WSConstants.PASSWORD_TEXT);
            } else if (WSConstants.PW_DIGEST.equals(type)) {
                reqData.setPwType(WSConstants.PASSWORD_DIGEST);
            } else if (WSConstants.PW_NONE.equals(type)) {
                reqData.setPwType(null);
            } else {
                throw new WSSecurityException("Unknown password type encoding: " + type);
            }
        }
        
        String add = getString(WSHandlerConstants.ADD_UT_ELEMENTS, mc);
        if (add != null) {
            reqData.setUtElements(StringUtil.split(add, ' '));
        }
        
        String derived = getString(WSHandlerConstants.USE_DERIVED_KEY, mc);
        if (derived != null) {
            boolean useDerivedKey = Boolean.parseBoolean(derived);
            reqData.setUseDerivedKey(useDerivedKey);
        }
        
        String derivedMAC = getString(WSHandlerConstants.USE_DERIVED_KEY_FOR_MAC, mc);
        boolean useDerivedKeyForMAC = Boolean.parseBoolean(derivedMAC);
        if (useDerivedKeyForMAC) {
            reqData.setUseDerivedKeyForMAC(useDerivedKeyForMAC);
        }
        
        String iterations = getString(WSHandlerConstants.DERIVED_KEY_ITERATIONS, mc);
        if (iterations != null) {
            int iIterations = Integer.parseInt(iterations);
            reqData.setDerivedKeyIterations(iIterations);
        }
    }

    protected void decodeSignatureParameter(RequestData reqData) 
        throws WSSecurityException {
        Object mc = reqData.getMsgContext();
        String signatureUser = getString(WSHandlerConstants.SIGNATURE_USER, mc);

        if (signatureUser != null) {
            reqData.setSignatureUser(signatureUser);
        } else {
            reqData.setSignatureUser(reqData.getUsername());
        }
        
        String keyId = getString(WSHandlerConstants.SIG_KEY_ID, mc);
        if (keyId != null) {
            Integer id = (Integer) WSHandlerConstants.getKeyIdentifier(keyId);
            if (id == null) {
                throw new WSSecurityException(
                    "WSHandler: Signature: unknown key identification"
                );
            }
            int tmp = id.intValue();
            if (!(tmp == WSConstants.ISSUER_SERIAL
                    || tmp == WSConstants.BST_DIRECT_REFERENCE
                    || tmp == WSConstants.X509_KEY_IDENTIFIER
                    || tmp == WSConstants.SKI_KEY_IDENTIFIER
                    || tmp == WSConstants.THUMBPRINT_IDENTIFIER
                    || tmp == WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER)) {
                throw new WSSecurityException(
                    "WSHandler: Signature: illegal key identification"
                );
            }
            reqData.setSigKeyId(tmp);
        }
        String algo = getString(WSHandlerConstants.SIG_ALGO, mc);
        reqData.setSigAlgorithm(algo);
        
        String digestAlgo = getString(WSHandlerConstants.SIG_DIGEST_ALGO, mc);
        reqData.setSigDigestAlgorithm(digestAlgo);

        String parts = getString(WSHandlerConstants.SIGNATURE_PARTS, mc);
        if (parts != null) {
            splitEncParts(parts, reqData.getSignatureParts(), reqData);
        }
        
        String secretKeyLength = getString(WSHandlerConstants.WSE_SECRET_KEY_LENGTH, mc);
        if (secretKeyLength != null) {
            int iSecretKeyLength = Integer.parseInt(secretKeyLength);
            reqData.setSecretKeyLength(iSecretKeyLength);
        }
        
        boolean useSingleCert = decodeUseSingleCertificate(reqData);
        reqData.setUseSingleCert(useSingleCert);
    }

    protected void decodeAlgorithmSuite(RequestData reqData) throws WSSecurityException {
        Object mc = reqData.getMsgContext();
        if (mc == null || reqData.getAlgorithmSuite() != null) {
            return;
        }
        
        AlgorithmSuite algorithmSuite = new AlgorithmSuite();
        
        String signatureAlgorithm = getString(WSHandlerConstants.SIG_ALGO, mc);
        if (signatureAlgorithm != null && !"".equals(signatureAlgorithm)) {
            algorithmSuite.addSignatureMethod(signatureAlgorithm);
        }
        String signatureDigestAlgorithm = getString(WSHandlerConstants.SIG_DIGEST_ALGO, mc);
        if (signatureDigestAlgorithm != null && !"".equals(signatureDigestAlgorithm)) {
            algorithmSuite.addDigestAlgorithm(signatureDigestAlgorithm);
        }
        
        String encrAlgorithm = getString(WSHandlerConstants.ENC_SYM_ALGO, mc);
        if (encrAlgorithm != null && !"".equals(encrAlgorithm)) {
            algorithmSuite.addEncryptionMethod(encrAlgorithm);
        }
        String transportAlgorithm = getString(WSHandlerConstants.ENC_KEY_TRANSPORT, mc);
        if (transportAlgorithm != null && !"".equals(transportAlgorithm)) {
            algorithmSuite.addKeyWrapAlgorithm(transportAlgorithm);
        }
        
        reqData.setAlgorithmSuite(algorithmSuite);
    }
    
    protected void decodeEncryptionParameter(RequestData reqData) 
        throws WSSecurityException {
        Object mc = reqData.getMsgContext();
        String encUser = getString(WSHandlerConstants.ENCRYPTION_USER, mc);

        if (encUser != null) {
            reqData.setEncUser(encUser);
        } else {
            reqData.setEncUser(reqData.getUsername());
        }
        if (reqData.getEncUser() == null) {
            throw new WSSecurityException("WSHandler: Encryption: no username");
        }
        /*
         * String msgType = msgContext.getCurrentMessage().getMessageType(); if
         * (msgType != null && msgType.equals(Message.RESPONSE)) {
         * handleSpecialUser(encUser); }
         */
        handleSpecialUser(reqData);

        /*
         * If the following parameters are no used (they return null) then the
         * default values of WSS4J are used.
         */
        String encKeyId = getString(WSHandlerConstants.ENC_KEY_ID, mc);
        if (encKeyId != null) {
            Integer id = (Integer) WSHandlerConstants.getKeyIdentifier(encKeyId);
            if (id == null) {
                throw new WSSecurityException(
                    "WSHandler: Encryption: unknown key identification"
                );
            }
            int tmp = id.intValue();
            reqData.setEncKeyId(tmp);
            if (!(tmp == WSConstants.ISSUER_SERIAL
                    || tmp == WSConstants.X509_KEY_IDENTIFIER
                    || tmp == WSConstants.SKI_KEY_IDENTIFIER
                    || tmp == WSConstants.BST_DIRECT_REFERENCE
                    || tmp == WSConstants.EMBEDDED_KEYNAME
                    || tmp == WSConstants.THUMBPRINT_IDENTIFIER
                    || tmp == WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER)) {
                throw new WSSecurityException(
                    "WSHandler: Encryption: illegal key identification"
                );
            }
        }
        String encSymAlgo = getString(WSHandlerConstants.ENC_SYM_ALGO, mc);
        reqData.setEncSymmAlgo(encSymAlgo);

        String encKeyTransport = 
            getString(WSHandlerConstants.ENC_KEY_TRANSPORT, mc);
        reqData.setEncKeyTransport(encKeyTransport);
        
        String digestAlgo = getString(WSHandlerConstants.ENC_DIGEST_ALGO, mc);
        reqData.setEncDigestAlgorithm(digestAlgo);
        
        String encSymEncKey = getString(WSHandlerConstants.ENC_SYM_ENC_KEY, mc);
        if (encSymEncKey != null) {
            boolean encSymEndKeyBoolean = Boolean.parseBoolean(encSymEncKey);
            reqData.setEncryptSymmetricEncryptionKey(encSymEndKeyBoolean);
        }

        String encParts = getString(WSHandlerConstants.ENCRYPTION_PARTS, mc);
        if (encParts != null) {
            splitEncParts(encParts, reqData.getEncryptParts(), reqData);
        }
    }

    public int decodeTimeToLive(RequestData reqData) {
        String ttl = 
            getString(WSHandlerConstants.TTL_TIMESTAMP, reqData.getMsgContext());
        int ttlI = 0;
        if (ttl != null) {
            try {
                ttlI = Integer.parseInt(ttl);
            } catch (NumberFormatException e) {
                ttlI = reqData.getTimeToLive();
            }
        }
        if (ttlI <= 0) {
            ttlI = reqData.getTimeToLive();
        }
        return ttlI;
    }
    
    protected int decodeFutureTimeToLive(RequestData reqData) {
        String ttl = 
            getString(WSHandlerConstants.TTL_FUTURE_TIMESTAMP, reqData.getMsgContext());
        int defaultFutureTimeToLive = 60;
        if (ttl != null) {
            try {
                int ttlI = Integer.parseInt(ttl);
                if (ttlI < 0) {
                    return defaultFutureTimeToLive;
                }
                return ttlI;
            } catch (NumberFormatException e) {
                return defaultFutureTimeToLive;
            }
        }
        return defaultFutureTimeToLive;
    }
    
    protected boolean decodeBSPCompliance(RequestData reqData)
        throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.IS_BSP_COMPLIANT, true
        );
    }
    
    protected String decodePasswordType(RequestData reqData) throws WSSecurityException {
        String type = getString(WSHandlerConstants.PASSWORD_TYPE, reqData.getMsgContext());
        if (type != null) {
            if (WSConstants.PW_TEXT.equals(type)) {
                return WSConstants.PASSWORD_TEXT;
            } else if (WSConstants.PW_DIGEST.equals(type)) {
                return WSConstants.PASSWORD_DIGEST;
            }
        }
        return null;
    }
    
    protected boolean decodeMustUnderstand(RequestData reqData) 
        throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.MUST_UNDERSTAND, true
        );
    }

    protected boolean decodeEnableSignatureConfirmation(
        RequestData reqData
    ) throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.ENABLE_SIGNATURE_CONFIRMATION, false
        );
    }
    
    protected boolean decodeTimestampPrecision(
        RequestData reqData
    ) throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.TIMESTAMP_PRECISION, true
        );
    }
    
    protected boolean decodeCustomPasswordTypes(
        RequestData reqData
    ) throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.HANDLE_CUSTOM_PASSWORD_TYPES, false
        );
    }
    
    protected boolean decodeUseEncodedPasswords(RequestData reqData) 
        throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.USE_ENCODED_PASSWORDS, false
        );
    }
    
    protected boolean decodeNamespaceQualifiedPasswordTypes(RequestData reqData) 
        throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.ALLOW_NAMESPACE_QUALIFIED_PASSWORD_TYPES, false
        );
    }

    protected boolean decodeTimestampStrict(RequestData reqData) 
        throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.TIMESTAMP_STRICT, true
        );
    }
    
    protected boolean decodePasswordTypeStrict(RequestData reqData) 
        throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.PASSWORD_TYPE_STRICT, false
        );
    }
    
    protected boolean decodeUseSingleCertificate(RequestData reqData) 
        throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.USE_SINGLE_CERTIFICATE, true
        );
    }
    
    protected void decodeRequireSignedEncryptedDataElements(RequestData reqData) 
        throws WSSecurityException {
        reqData.setRequireSignedEncryptedDataElements(decodeBooleanConfigValue(
            reqData, WSHandlerConstants.REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS, false
        ));
    }

    protected boolean decodeBooleanConfigValue(
        RequestData reqData, String configTag, boolean defaultToTrue
    ) throws WSSecurityException {

        String value = getString(configTag, reqData.getMsgContext());

        if (value == null) {
            return defaultToTrue;
        }
        if ("0".equals(value) || "false".equals(value)) {
            return false;
        } 
        if ("1".equals(value) || "true".equals(value)) {
            return true;
        }

        throw new WSSecurityException(
            "WSHandler: illegal " + configTag + " parameter"
        );
    }
    
    /**
     * Hook to allow subclasses to load their Signature Crypto however they see
     * fit. 
     * 
     * @param requestData the RequestData object
     * @return a Crypto instance to use for Signature creation/verification
     */
    public Crypto loadSignatureCrypto(RequestData requestData) throws WSSecurityException {
        return 
            loadCrypto(
                WSHandlerConstants.SIG_PROP_FILE,
                WSHandlerConstants.SIG_PROP_REF_ID,
                requestData
            );
    }
    
    /**
     * Hook to allow subclasses to load their Decryption Crypto however they see
     * fit. 
     * 
     * @param requestData the RequestData object
     * @return a Crypto instance to use for Decryption creation/verification
     */
    protected Crypto loadDecryptionCrypto(RequestData requestData) throws WSSecurityException {
        return 
            loadCrypto(
                WSHandlerConstants.DEC_PROP_FILE,
                WSHandlerConstants.DEC_PROP_REF_ID,
                requestData
            );
    }
    
    /**
     * Hook to allow subclasses to load their Encryption Crypto however they see
     * fit. 
     * 
     * @param requestData the RequestData object
     * @return a Crypto instance to use for Encryption creation/verification
     */
    protected Crypto loadEncryptionCrypto(RequestData requestData) throws WSSecurityException {
        return 
            loadCrypto(
                WSHandlerConstants.ENC_PROP_FILE,
                WSHandlerConstants.ENC_PROP_REF_ID,
                requestData
            );
    }
    
    /**
     * Load a Crypto instance. Firstly, it tries to use the cryptoPropertyRefId tag to retrieve
     * a Crypto object via a custom reference Id. Failing this, it tries to load the crypto 
     * instance via the cryptoPropertyFile tag.
     * 
     * @param requestData the RequestData object
     * @return a Crypto instance to use for Encryption creation/verification
     */
    protected Crypto loadCrypto(
        String cryptoPropertyFile,
        String cryptoPropertyRefId,
        RequestData requestData
    ) throws WSSecurityException {
        Object mc = requestData.getMsgContext();
        Crypto crypto = null;
        
        //
        // Try the Property Ref Id first
        //
        String refId = getString(cryptoPropertyRefId, mc);
        if (refId != null) {
            crypto = cryptos.get(refId);
            if (crypto == null) {
                Object obj = getProperty(mc, refId);
                if (obj instanceof Properties) {
                    crypto = CryptoFactory.getInstance((Properties)obj);
                    cryptos.put(refId, crypto);
                } else if (obj instanceof Crypto) {
                    crypto = (Crypto)obj;
                    cryptos.put(refId, crypto);
                }
            }
        }
        
        //
        // Now try loading the properties file
        //
        if (crypto == null) {
            String propFile = getString(cryptoPropertyFile, mc);
            if (propFile != null) {
                crypto = cryptos.get(propFile);
                if (crypto == null) {
                    crypto = loadCryptoFromPropertiesFile(propFile, requestData);
                    cryptos.put(propFile, crypto);
                }
            } 
        }
        return crypto;
    }

    /**
     * A hook to allow subclass to load Crypto instances from property files in a different
     * way.
     * @param propFilename The property file name
     * @param reqData The RequestData object
     * @return A Crypto instance that has been loaded
     */
    protected Crypto loadCryptoFromPropertiesFile(
        String propFilename, 
        RequestData reqData
    ) throws WSSecurityException {
        return 
            CryptoFactory.getInstance(
                propFilename, this.getClassLoader(reqData.getMsgContext())
            );
    }

    /**
     * Get a CallbackHandler instance. First try to get an instance via the 
     * callbackHandlerRef on the message context. Failing that, try to load a new 
     * instance of the CallbackHandler via the callbackHandlerClass argument.
     * 
     * @param callbackHandlerClass The class name of the CallbackHandler instance
     * @param callbackHandlerRef The reference name of the CallbackHandler instance
     * @param requestData The RequestData which supplies the message context
     * @return a CallbackHandler instance
     * @throws WSSecurityException
     */
    public CallbackHandler getCallbackHandler(
        String callbackHandlerClass,
        String callbackHandlerRef,
        RequestData requestData
    ) throws WSSecurityException {
        Object mc = requestData.getMsgContext();
        CallbackHandler cbHandler = (CallbackHandler) getOption(callbackHandlerRef);
        if (cbHandler == null) {
            cbHandler = (CallbackHandler) getProperty(mc, callbackHandlerRef);
        }
        if (cbHandler == null) {
            String callback = getString(callbackHandlerClass, mc);
            if (callback != null) {
                cbHandler = loadCallbackHandler(callback, requestData);
            }
        }
        return cbHandler;
    }
    
    /**
     * Get a CallbackHandler instance to obtain passwords.
     * @param reqData The RequestData which supplies the message context
     * @return the CallbackHandler instance to obtain passwords.
     * @throws WSSecurityException
     */
    public CallbackHandler getPasswordCallbackHandler(RequestData reqData) 
        throws WSSecurityException {
        return 
            getCallbackHandler(
                WSHandlerConstants.PW_CALLBACK_CLASS,
                WSHandlerConstants.PW_CALLBACK_REF,
                reqData
            );
    }
    
    /**
     * Load a CallbackHandler instance.
     * @param callbackHandlerClass The class name of the CallbackHandler instance
     * @param requestData The RequestData which supplies the message context
     * @return a CallbackHandler instance
     * @throws WSSecurityException
     */
    private CallbackHandler loadCallbackHandler(
        String callbackHandlerClass,
        RequestData requestData
    ) throws WSSecurityException {

        Class<? extends CallbackHandler> cbClass = null;
        CallbackHandler cbHandler = null;
        try {
            cbClass = 
                Loader.loadClass(getClassLoader(requestData.getMsgContext()), 
                                 callbackHandlerClass,
                                 CallbackHandler.class);
        } catch (ClassNotFoundException e) {
            throw new WSSecurityException(
                "WSHandler: cannot load callback handler class: " + callbackHandlerClass, e
            );
        }
        try {
            cbHandler = (CallbackHandler) cbClass.newInstance();
        } catch (Exception e) {
            throw new WSSecurityException(
                "WSHandler: cannot create instance of callback handler: " + callbackHandlerClass, e
            );
        }
        return cbHandler;
    }
    
    /**
     * Get a password callback (WSPasswordCallback object) from a CallbackHandler instance
     * @param username The username to supply to the CallbackHandler
     * @param doAction The action to perform
     * @param callbackHandler The CallbackHandler instance
     * @param requestData The RequestData which supplies the message context
     * @return the WSPasswordCallback object containing the password
     * @throws WSSecurityException
     */
    public WSPasswordCallback getPasswordCB(
         String username,
         int doAction,
         CallbackHandler callbackHandler,
         RequestData requestData
    ) throws WSSecurityException {
        
        if (callbackHandler != null) { 
            return performPasswordCallback(callbackHandler, username, doAction);
        } else {
            //
            // If a callback isn't configured then try to get the password
            // from the message context
            //
            String password = getPassword(requestData.getMsgContext());
            if (password == null) {
                String err = "provided null or empty password";
                throw new WSSecurityException("WSHandler: application " + err);
            }
            WSPasswordCallback pwCb = constructPasswordCallback(username, doAction);
            pwCb.setPassword(password);
            return pwCb;
        }
    }

    /**
     * Perform a callback on a CallbackHandler instance
     * @param cbHandler the CallbackHandler instance
     * @param username The username to supply to the CallbackHandler
     * @param doAction The action to perform
     * @return a WSPasswordCallback instance
     * @throws WSSecurityException
     */
    private WSPasswordCallback performPasswordCallback(
        CallbackHandler cbHandler,
        String username,
        int doAction
    ) throws WSSecurityException {

        WSPasswordCallback pwCb = constructPasswordCallback(username, doAction);
        Callback[] callbacks = new Callback[1];
        callbacks[0] = pwCb;
        //
        // Call back the application to get the password
        //
        try {
            cbHandler.handle(callbacks);
        } catch (Exception e) {
            throw new WSSecurityException("WSHandler: password callback failed", e);
        }
        return pwCb;
    }

    /**
     * Construct a WSPasswordCallback instance
     * @param username The username
     * @param doAction The action to perform
     * @return a WSPasswordCallback instance
     * @throws WSSecurityException
     */
    private WSPasswordCallback constructPasswordCallback(
        String username,
        int doAction
    ) throws WSSecurityException {

        int reason = WSPasswordCallback.UNKNOWN;

        switch (doAction) {
        case WSConstants.UT:
        case WSConstants.UT_SIGN:
            reason = WSPasswordCallback.USERNAME_TOKEN;
            break;
        case WSConstants.SIGN:
            reason = WSPasswordCallback.SIGNATURE;
            break;
        case WSConstants.ENCR:
            reason = WSPasswordCallback.SECRET_KEY;
            break;
        }
        return new WSPasswordCallback(username, reason);
    }

    private void splitEncParts(String tmpS, List<WSEncryptionPart> parts, RequestData reqData)
        throws WSSecurityException {
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
                            reqData.getSoapConstants().getEnvelopeURI(),
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
                    nmSpace = reqData.getSoapConstants().getEnvelopeURI();
                } else {
                    nmSpace = nmSpace.substring(1);
                    if (nmSpace.equals(WSConstants.NULL_NS)) {
                        nmSpace = null;
                    }
                }
                String element = partDef[2].trim();
                if (doDebug) {
                    log.debug(
                        "partDefs: '" + mode + "' ,'" + nmSpace + "' ,'" + element + "'"
                    );
                }
                encPart = new WSEncryptionPart(element, nmSpace, mode);
            } else {
                throw new WSSecurityException("WSHandler: wrong part definition: " + tmpS);
            }
            parts.add(encPart);
        }
    }

    @SuppressWarnings("unchecked")
    private void handleSpecialUser(RequestData reqData) {
        if (!WSHandlerConstants.USE_REQ_SIG_CERT.equals(reqData.getEncUser())) {
            return;
        }
        List<WSHandlerResult> results = 
            (List<WSHandlerResult>) getProperty(
                reqData.getMsgContext(), WSHandlerConstants.RECV_RESULTS
            );
        if (results == null) {
            return;
        }
        /*
         * Scan the results for a matching actor. Use results only if the
         * receiving Actor and the sending Actor match.
         */
        for (WSHandlerResult rResult : results) {
            String hActor = rResult.getActor();
            if (!WSSecurityUtil.isActorEqual(reqData.getActor(), hActor)) {
                continue;
            }
            List<WSSecurityEngineResult> wsSecEngineResults = rResult.getResults();
            /*
             * Scan the results for the first Signature action. Use the
             * certificate of this Signature to set the certificate for the
             * encryption action :-).
             */
            for (WSSecurityEngineResult wser : wsSecEngineResults) {
                int wserAction = 
                    ((java.lang.Integer)wser.get(WSSecurityEngineResult.TAG_ACTION)).intValue();
                if (wserAction == WSConstants.SIGN) {
                    X509Certificate cert = 
                        (X509Certificate)wser.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
                    reqData.setEncCert(cert);
                    return;
                }
            }
        }
    }

    protected void decodeSignatureParameter2(RequestData reqData) 
        throws WSSecurityException {
        if (reqData.getSigCrypto() == null) {
            reqData.setSigCrypto(loadSignatureCrypto(reqData));
        }
        boolean enableRevocation = 
            decodeBooleanConfigValue(
                reqData, WSHandlerConstants.ENABLE_REVOCATION, false
            );
        reqData.setEnableRevocation(enableRevocation);
        
        String certConstraints = 
            getString(WSHandlerConstants.SIG_SUBJECT_CERT_CONSTRAINTS, reqData.getMsgContext());
        if (certConstraints != null) {
            String[] certConstraintsList = certConstraints.split(",");
            if (certConstraintsList != null) {
                Collection<Pattern> subjectCertConstraints = 
                    new ArrayList<Pattern>(certConstraintsList.length);
                for (String certConstraint : certConstraintsList) {
                    try {
                        subjectCertConstraints.add(Pattern.compile(certConstraint.trim()));
                    } catch (PatternSyntaxException ex) {
                        log.debug(ex.getMessage(), ex);
                        throw new WSSecurityException(ex.getMessage(), ex);
                    }
                }
                reqData.setSubjectCertConstraints(subjectCertConstraints);
            }
        }
    }

    /*
     * Set and check the decryption specific parameters, if necessary
     * take over signature crypto instance.
     */
    protected void decodeDecryptionParameter(RequestData reqData) 
        throws WSSecurityException {
        if (reqData.getDecCrypto() == null) {
            reqData.setDecCrypto(loadDecryptionCrypto(reqData));
        }
    }

    /**
     * Looks up key first via {@link #getOption(String)} and if not found
     * there, via {@link #getProperty(Object, String)}
     *
     * @param key the key to search for. May not be null.
     * @param mc the message context to search. 
     * @return the value found.
     * @throws IllegalArgumentException if <code>key</code> is null.
     */
    public String getString(String key, Object mc) { 
        if (key == null) {
            throw new IllegalArgumentException("Key cannot be null");
        }
        String s = getStringOption(key);
        if (s != null) {
            return s;
        }
        if (mc == null) {
            throw new IllegalArgumentException("Message context cannot be null");
        }
        return (String) getProperty(mc, key);
    }


    /**
     * Returns the option on <code>name</code>.
     *
     * @param key the non-null key of the option.
     * @return the option on <code>key</code> if <code>key</code>
     *  exists and is of type java.lang.String; otherwise null.
     */
    public String getStringOption(String key) {
        Object o = getOption(key);
        if (o instanceof String){
            return (String) o;
        } else {
            return null;
        }
    }

    /**
     * Returns the classloader to be used for loading the callback class
     * @param msgCtx The MessageContext 
     * @return class loader
     */
    public ClassLoader getClassLoader(Object msgCtx) {
        try {
            return Loader.getTCL();
        } catch (Exception ex) {
            return null;
        }
    }

    public abstract Object getOption(String key);
    public abstract Object getProperty(Object msgContext, String key);

    public abstract void setProperty(Object msgContext, String key, 
            Object value);


    public abstract String getPassword(Object msgContext);

    public abstract void setPassword(Object msgContext, String password);
}
