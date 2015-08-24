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

package org.apache.wss4j.dom.handler;

import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.ArrayList;
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

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.WSSConfig;
import org.apache.wss4j.dom.WSSecurityEngineResult;
import org.apache.wss4j.dom.action.Action;
import org.apache.wss4j.common.EncryptionActionToken;
import org.apache.wss4j.common.SignatureActionToken;
import org.apache.wss4j.common.SignatureEncryptionActionToken;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.AlgorithmSuite;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.JasyptPasswordEncryptor;
import org.apache.wss4j.common.crypto.PasswordEncryptor;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.Loader;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.token.SignatureConfirmation;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Document;

/**
 * Extracted from WSDoAllReceiver and WSDoAllSender
 * Extended to all passwordless UsernameTokens and configurable identities.
 */
public abstract class WSHandler {
    private static final org.slf4j.Logger LOG = 
        org.slf4j.LoggerFactory.getLogger(WSHandler.class);
    protected Map<String, Crypto> cryptos = new ConcurrentHashMap<String, Crypto>();

    private boolean doDebug = LOG.isDebugEnabled();

    /**                                                             
     * Performs all defined security actions to set-up the SOAP request.
     * 
     * @param doc   the request as DOM document 
     * @param reqData a data storage to pass values around between methods
     * @param actions a list holding the actions to do in the order defined
     *                in the deployment file or property, plus an optional 
     *                associated SecurityActionToken object for that Action
     * @throws WSSecurityException
     */
    protected void doSenderAction(
            Document doc,
            RequestData reqData, 
            List<HandlerAction> actions,
            boolean isRequest
    ) throws WSSecurityException {

        boolean mu = decodeMustUnderstand(reqData);

        WSSConfig wssConfig = reqData.getWssConfig();
        if (wssConfig == null) {
            wssConfig = WSSConfig.getNewInstance();
            reqData.setWssConfig(wssConfig);
        }
        wssConfig.setPasswordsAreEncoded(decodeUseEncodedPasswords(reqData));
        wssConfig.setPrecisionInMilliSeconds(decodeTimestampPrecision(reqData));

        Object mc = reqData.getMsgContext();
        String actor = getString(WSHandlerConstants.ACTOR, mc);
        reqData.setActor(actor);

        WSSecHeader secHeader = new WSSecHeader(actor, mu);
        secHeader.insertSecurityHeader(doc);

        reqData.setSecHeader(secHeader);
        reqData.setSoapConstants(WSSecurityUtil.getSOAPConstants(doc.getDocumentElement()));
        wssConfig.setAddInclusivePrefixes(decodeAddInclusivePrefixes(reqData));

        // Load CallbackHandler
        if (reqData.getCallbackHandler() == null) {
            CallbackHandler passwordCallbackHandler = 
                getPasswordCallbackHandler(reqData);
            reqData.setCallbackHandler(passwordCallbackHandler);
        }
        
        boolean enableSigConf = decodeEnableSignatureConfirmation(reqData);
        wssConfig.setEnableSignatureConfirmation(enableSigConf);

        String storeBytes = getString(WSHandlerConstants.STORE_BYTES_IN_ATTACHMENT, mc);
        boolean storeBytesInAttachment = Boolean.parseBoolean(storeBytes);
        reqData.setStoreBytesInAttachment(storeBytesInAttachment);
        
        // Perform configuration
        boolean encryptionFound = false;
        for (HandlerAction actionToDo : actions) {
            if (actionToDo.getAction() == WSConstants.SC) {
                wssConfig.setEnableSignatureConfirmation(true);
            } else if (actionToDo.getAction() == WSConstants.UT 
                && actionToDo.getActionToken() == null) {
                decodeUTParameter(reqData);
            } else if (actionToDo.getAction() == WSConstants.UT_SIGN 
                && actionToDo.getActionToken() == null) {
                decodeUTParameter(reqData);
                decodeSignatureParameter(reqData);
            } else if ((actionToDo.getAction() == WSConstants.SIGN
                || actionToDo.getAction() == WSConstants.DKT_SIGN)
                && actionToDo.getActionToken() == null) {
                SignatureActionToken actionToken = reqData.getSignatureToken();
                if (actionToken == null) {
                    actionToken = new SignatureActionToken();
                    reqData.setSignatureToken(actionToken);
                }
                if (actionToken.getCrypto() == null) {
                    actionToken.setCrypto(loadSignatureCrypto(reqData));
                }
                decodeSignatureParameter(reqData);
                if (encryptionFound && storeBytesInAttachment) {
                    LOG.warn("Turning off storeBytesInAttachment as we have encryption before signature."
                             + " The danger here is that the actual encryption bytes will not be signed");
                    reqData.setStoreBytesInAttachment(false);
                }
            } else if (actionToDo.getAction() == WSConstants.ST_SIGNED 
                && actionToDo.getActionToken() == null) {
                decodeSignatureParameter(reqData);
            } else if ((actionToDo.getAction() == WSConstants.ENCR
                || actionToDo.getAction() == WSConstants.DKT_ENCR)
                && actionToDo.getActionToken() == null) {
                encryptionFound = true;
                EncryptionActionToken actionToken = reqData.getEncryptionToken();
                if (actionToken == null) {
                    actionToken = new EncryptionActionToken();
                    reqData.setEncryptionToken(actionToken);
                }
                if (actionToken.getCrypto() == null) {
                    actionToken.setCrypto(loadEncryptionCrypto(reqData));
                }
                decodeEncryptionParameter(reqData);
            }
        }

        /*
         * If after all the parsing no Signature parts defined, set here a
         * default set. This is necessary because we add SignatureConfirmation
         * and therefore the default (Body) must be set here. The default setting
         * in WSSignEnvelope doesn't work because the vector is not empty anymore.
         */
        SignatureActionToken signatureToken = reqData.getSignatureToken();
        if (signatureToken == null) {
            signatureToken = new SignatureActionToken();
            reqData.setSignatureToken(signatureToken);
        }
        if (signatureToken.getParts().isEmpty()) {
            WSEncryptionPart encP = new WSEncryptionPart(reqData.getSoapConstants()
                    .getBodyQName().getLocalPart(), reqData.getSoapConstants()
                    .getEnvelopeURI(), "Content");
            signatureToken.getParts().add(encP);
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
                wssConfig.getAction(WSConstants.SC).execute(this, null, doc, reqData);
            }
        }
        
        // See if the Signature and Timestamp actions (in that order) are defined, and if
        // the Timestamp is to be signed. In this case we need to swap the actions, as the 
        // Timestamp must appear in the security header first for signature creation to work.
        List<HandlerAction> actionsToPerform = actions;
        HandlerAction signingAction = getSignatureActionThatSignsATimestamp(actions, reqData);

        if (signingAction != null) {
            actionsToPerform = new ArrayList<HandlerAction>(actions);
            Collections.copy(actionsToPerform, actions);

            int signatureIndex = actions.indexOf(WSConstants.SIGN);
            actionsToPerform.remove(signingAction);
            actionsToPerform.add(signingAction);
            reqData.setAppendSignatureAfterTimestamp(true);
            reqData.setOriginalSignatureActionPosition(signatureIndex);
        }
        
        /*
         * Here we have all necessary information to perform the requested
         * action(s).
         */
        for (HandlerAction actionToDo : actionsToPerform) {
            if (doDebug) {
                LOG.debug("Performing Action: " + actionToDo.getAction());
            }

            switch (actionToDo.getAction()) {
            case WSConstants.UT:
            case WSConstants.ENCR:
            case WSConstants.SIGN:
            case WSConstants.DKT_SIGN:
            case WSConstants.DKT_ENCR:
            case WSConstants.ST_SIGNED:
            case WSConstants.ST_UNSIGNED:
            case WSConstants.TS:
            case WSConstants.UT_SIGN:
            case WSConstants.CUSTOM_TOKEN:
                wssConfig.getAction(actionToDo.getAction()).execute(
                    this, actionToDo.getActionToken(), doc, reqData);
                break;
                //
                // Handle any "custom" actions, similarly,
                // but to preserve behavior from previous
                // versions, consume (but LOG. action lookup failures.
                //
            default:
                Action doit = null;
            try {
                doit = wssConfig.getAction(actionToDo.getAction());
            } catch (final WSSecurityException e) {
                LOG.warn(
                        "Error trying to locate a custom action (" + actionToDo + ")", 
                        e
                );
            }
            if (doit != null) {
                doit.execute(this, actionToDo.getActionToken(), doc, reqData);
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
            @SuppressWarnings("unchecked")
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
    
    private HandlerAction getSignatureActionThatSignsATimestamp(
        List<HandlerAction> actions, RequestData reqData
    ) {
        for (HandlerAction action : actions) {
            // Only applies if a Signature is before a Timestamp
            if (action.getAction() == WSConstants.TS) {
                return null;
            } else if (action.getAction() == WSConstants.SIGN) {
                if (action.getActionToken() != null 
                    && ((SignatureEncryptionActionToken)action.getActionToken()).getParts() != null) {
                    for (WSEncryptionPart encP 
                        : ((SignatureEncryptionActionToken)action.getActionToken()).getParts()) {
                        if (WSConstants.WSU_NS.equals(encP.getNamespace()) 
                            && "Timestamp".equals(encP.getName())) {
                            return action;
                        }
                    }
                } else {
                    for (WSEncryptionPart encP : reqData.getSignatureToken().getParts()) {
                        if (WSConstants.WSU_NS.equals(encP.getNamespace()) 
                            && "Timestamp".equals(encP.getName())) {
                            return action;
                        }
                    }
                }
            }
        }
        return null;
    }

    protected void doReceiverAction(List<Integer> actions, RequestData reqData)
        throws WSSecurityException {

        WSSConfig wssConfig = reqData.getWssConfig();
        if (wssConfig == null) {
            wssConfig = WSSConfig.getNewInstance();
            reqData.setWssConfig(wssConfig);
        }
        boolean enableSigConf = decodeEnableSignatureConfirmation(reqData);
        wssConfig.setEnableSignatureConfirmation(
            enableSigConf || actions.contains(WSConstants.SC)
        );
        wssConfig.setTimeStampStrict(decodeTimestampStrict(reqData));
        String passwordType = decodePasswordType(reqData);
        wssConfig.setRequiredPasswordType(passwordType);
            
        wssConfig.setTimeStampTTL(decodeTimeToLive(reqData, true));
        wssConfig.setTimeStampFutureTTL(decodeFutureTimeToLive(reqData, true));
        wssConfig.setUtTTL(decodeTimeToLive(reqData, false));
        wssConfig.setUtFutureTTL(decodeFutureTimeToLive(reqData, false));
        
        wssConfig.setHandleCustomPasswordTypes(decodeCustomPasswordTypes(reqData));
        wssConfig.setPasswordsAreEncoded(decodeUseEncodedPasswords(reqData));
        wssConfig.setAllowNamespaceQualifiedPasswordTypes(
            decodeNamespaceQualifiedPasswordTypes(reqData)
        );
        wssConfig.setAllowUsernameTokenNoPassword(
            decodeAllowUsernameTokenNoPassword(reqData)
        );
        wssConfig.setValidateSamlSubjectConfirmation(
            decodeSamlSubjectConfirmationValidation(reqData)
        );
        
        boolean bspCompliant = decodeBSPCompliance(reqData);
        if (!bspCompliant) {
            reqData.setDisableBSPEnforcement(true);
        }
        
        // Load CallbackHandler
        if (reqData.getCallbackHandler() == null) {
            CallbackHandler passwordCallbackHandler = 
                getPasswordCallbackHandler(reqData);
            reqData.setCallbackHandler(passwordCallbackHandler);
        }

        if (actions.contains(WSConstants.SIGN) || actions.contains(WSConstants.ST_SIGNED)
            || actions.contains(WSConstants.ST_UNSIGNED)) {
            decodeSignatureParameter2(reqData);
        }
        
        if (actions.contains(WSConstants.ENCR)) {
            decodeDecryptionParameter(reqData);
        }
        decodeRequireSignedEncryptedDataElements(reqData);
        decodeRequireTimestampExpires(reqData);
    }

    protected boolean checkReceiverResults(
        List<WSSecurityEngineResult> wsResult, List<Integer> actions
    ) {
        int size = actions.size();
        int ai = 0;
        for (WSSecurityEngineResult result : wsResult) {
            final Integer actInt = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            int act = actInt;
            if (act == WSConstants.SC || act == WSConstants.BST) {
                continue;
            }
            
            if (ai >= size || actions.get(ai++) != act) {
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
            int act = actInt;
            if (act == WSConstants.SC || act == WSConstants.BST) {
                continue;
            } else if (act == WSConstants.ENCR
                && (result.get(WSSecurityEngineResult.TAG_DATA_REF_URIS) == null
                    || ((List<?>)result.get(WSSecurityEngineResult.TAG_DATA_REF_URIS)).isEmpty())) {
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
            LOG.debug("Check Signature confirmation");
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
        List<WSSecurityEngineResult> sigConf = 
            WSSecurityUtil.fetchAllActionResults(resultList, WSConstants.SC);
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
                        throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "empty",
                             new Object[] {"Received a SignatureConfirmation element, but there are no stored"
                             + " signature values"}
                        );
                    }
                } else {
                    boolean found = false;
                    for (int j = 0; j < savedSignatures.size(); j++) {
                        byte[] storedValue = savedSignatures.get(j);
                        if (Arrays.equals(sigVal, storedValue)) {
                            found = true;
                            savedSignatures.remove(j);
                            break;
                        }
                    }
                    if (!found) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                            new Object[] {"Received a SignatureConfirmation element, but there are no matching"
                            + " stored signature values"}
                        );
                    } 
                }
            }
        }

        //
        // the list holding the stored Signature values must be empty, otherwise we have an error
        //
        if (savedSignatures != null && !savedSignatures.isEmpty()) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "empty",
                                          new Object[] {"Check Signature confirmation: the stored signature values"
                                                        + " list is not empty"}
            );
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
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                        "empty", new Object[] {"Unknown password type encoding: " + type});
            }
        }
        
        boolean addNonce = 
            decodeBooleanConfigValue(reqData, WSHandlerConstants.ADD_USERNAMETOKEN_NONCE, false);
        reqData.setAddUsernameTokenNonce(addNonce);
        
        boolean addCreated = 
            decodeBooleanConfigValue(reqData, WSHandlerConstants.ADD_USERNAMETOKEN_CREATED, false);
        reqData.setAddUsernameTokenCreated(addCreated);
        
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

    // Convert various Signature configuration into a single SignatureActionToken to be set on
    // the RequestData object
    protected void decodeSignatureParameter(RequestData reqData) 
        throws WSSecurityException {
        Object mc = reqData.getMsgContext();
        String signatureUser = getString(WSHandlerConstants.SIGNATURE_USER, mc);

        SignatureActionToken actionToken = reqData.getSignatureToken();
        if (actionToken == null) {
            actionToken = new SignatureActionToken();
            reqData.setSignatureToken(actionToken);
        }
        
        if (signatureUser != null) {
            actionToken.setUser(signatureUser);
        } else {
            actionToken.setUser(reqData.getUsername());
        }
        
        String keyId = getString(WSHandlerConstants.SIG_KEY_ID, mc);
        if (keyId != null) {
            Integer id = WSHandlerConstants.getKeyIdentifier(keyId);
            if (id == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                        "empty",
                        new Object[] {"WSHandler: Signature: unknown key identification"}
                );
            }
            int tmp = id;
            if (!(tmp == WSConstants.ISSUER_SERIAL
                    || tmp == WSConstants.BST_DIRECT_REFERENCE
                    || tmp == WSConstants.X509_KEY_IDENTIFIER
                    || tmp == WSConstants.SKI_KEY_IDENTIFIER
                    || tmp == WSConstants.THUMBPRINT_IDENTIFIER
                    || tmp == WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER
                    || tmp == WSConstants.KEY_VALUE)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                        "empty",
                        new Object[] {"WSHandler: Signature: illegal key identification"}
                );
            }
            actionToken.setKeyIdentifierId(tmp);
        }
        String algo = getString(WSHandlerConstants.SIG_ALGO, mc);
        actionToken.setSignatureAlgorithm(algo);
        
        String derivedKeyReference = getString(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, mc);
        actionToken.setDerivedKeyTokenReference(derivedKeyReference);
        
        String derivedKeyIdentifier = getString(WSHandlerConstants.DERIVED_TOKEN_KEY_ID, mc);
        if (derivedKeyIdentifier != null) {
            Integer id = WSHandlerConstants.getKeyIdentifier(derivedKeyIdentifier);
            actionToken.setDerivedKeyIdentifier(id);
        }
        
        String derivedKeyLength = getString(WSHandlerConstants.DERIVED_SIGNATURE_KEY_LENGTH, mc);
        if (derivedKeyLength != null) {
            try {
                int dKL = Integer.parseInt(derivedKeyLength);
                if (dKL > 0) {
                    actionToken.setDerivedKeyLength(dKL);
                }
            } catch (NumberFormatException e) {
                LOG.warn("Error in configuring a derived key length: " + e.getMessage());
            }
        }
        
        String digestAlgo = getString(WSHandlerConstants.SIG_DIGEST_ALGO, mc);
        actionToken.setDigestAlgorithm(digestAlgo);
        
        String c14nAlgo = getString(WSHandlerConstants.SIG_C14N_ALGO, mc);
        actionToken.setC14nAlgorithm(c14nAlgo);
        
        boolean use200512Namespace = decodeUse200512Namespace(reqData);
        reqData.setUse200512Namespace(use200512Namespace);

        String parts = getString(WSHandlerConstants.SIGNATURE_PARTS, mc);
        if (parts != null) {
            splitEncParts(true, parts, actionToken.getParts(), reqData);
        }
        parts = getString(WSHandlerConstants.OPTIONAL_SIGNATURE_PARTS, mc);
        if (parts != null) {
            splitEncParts(false, parts, actionToken.getParts(), reqData);
        }
        
        boolean useSingleCert = decodeUseSingleCertificate(reqData);
        actionToken.setUseSingleCert(useSingleCert);
        
        boolean includeToken = decodeIncludeSignatureToken(reqData);
        actionToken.setIncludeToken(includeToken);
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
    
    // Convert various Encryption configuration into a single EncryptionActionToken to be set on
    // the RequestData object
    protected void decodeEncryptionParameter(RequestData reqData) 
        throws WSSecurityException {
        Object mc = reqData.getMsgContext();

        EncryptionActionToken actionToken = reqData.getEncryptionToken();
        if (actionToken == null) {
            actionToken = new EncryptionActionToken();
            reqData.setEncryptionToken(actionToken);
        }
        //
        // If the following parameters are no used (they return null) then the
        // default values of WSS4J are used.
        //
        String encKeyId = getString(WSHandlerConstants.ENC_KEY_ID, mc);
        if (encKeyId != null) {
            Integer id = WSHandlerConstants.getKeyIdentifier(encKeyId);
            if (id == null) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                        "empty",
                        new Object[] {"WSHandler: Encryption: unknown key identification"}
                );
            }
            int tmp = id;
            actionToken.setKeyIdentifierId(tmp);
            if (!(tmp == WSConstants.ISSUER_SERIAL
                    || tmp == WSConstants.X509_KEY_IDENTIFIER
                    || tmp == WSConstants.SKI_KEY_IDENTIFIER
                    || tmp == WSConstants.BST_DIRECT_REFERENCE
                    || tmp == WSConstants.THUMBPRINT_IDENTIFIER
                    || tmp == WSConstants.ENCRYPTED_KEY_SHA1_IDENTIFIER)) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                        "empty",
                        new Object[] {"WSHandler: Encryption: illegal key identification"}
                );
            }
        }
        String encSymAlgo = getString(WSHandlerConstants.ENC_SYM_ALGO, mc);
        actionToken.setSymmetricAlgorithm(encSymAlgo);

        String encKeyTransport = 
            getString(WSHandlerConstants.ENC_KEY_TRANSPORT, mc);
        actionToken.setKeyTransportAlgorithm(encKeyTransport);
        
        String derivedKeyReference = getString(WSHandlerConstants.DERIVED_TOKEN_REFERENCE, mc);
        actionToken.setDerivedKeyTokenReference(derivedKeyReference);
        
        String derivedKeyIdentifier = getString(WSHandlerConstants.DERIVED_TOKEN_KEY_ID, mc);
        if (derivedKeyIdentifier != null) {
            Integer id = WSHandlerConstants.getKeyIdentifier(derivedKeyIdentifier);
            actionToken.setDerivedKeyIdentifier(id);
        }
        
        String derivedKeyLength = getString(WSHandlerConstants.DERIVED_ENCRYPTION_KEY_LENGTH, mc);
        if (derivedKeyLength != null) {
            try {
                int dKL = Integer.parseInt(derivedKeyLength);
                if (dKL > 0) {
                    actionToken.setDerivedKeyLength(dKL);
                }
            } catch (NumberFormatException e) {
                LOG.warn("Error in configuring a derived key length: " + e.getMessage());
            }
        }
        
        boolean use200512Namespace = decodeUse200512Namespace(reqData);
        reqData.setUse200512Namespace(use200512Namespace);
        
        String getSecretKeyFromCallbackHandler = getString(WSHandlerConstants.GET_SECRET_KEY_FROM_CALLBACK_HANDLER, mc);
        if (getSecretKeyFromCallbackHandler != null) {
            boolean getSecretKeyBoolean = Boolean.parseBoolean(getSecretKeyFromCallbackHandler);
            actionToken.setGetSymmetricKeyFromCallbackHandler(getSecretKeyBoolean);
        }
        
        String digestAlgo = getString(WSHandlerConstants.ENC_DIGEST_ALGO, mc);
        actionToken.setDigestAlgorithm(digestAlgo);

        String mgfAlgo = getString(WSHandlerConstants.ENC_MGF_ALGO, mc);
        actionToken.setMgfAlgorithm(mgfAlgo);
        
        String encSymEncKey = getString(WSHandlerConstants.ENC_SYM_ENC_KEY, mc);
        if (encSymEncKey != null) {
            boolean encSymEndKeyBoolean = Boolean.parseBoolean(encSymEncKey);
            actionToken.setEncSymmetricEncryptionKey(encSymEndKeyBoolean);
        }
        
        String encUser = getString(WSHandlerConstants.ENCRYPTION_USER, mc);
        if (encUser != null) {
            actionToken.setUser(encUser);
        } else {
            actionToken.setUser(reqData.getUsername());
        }
        if (actionToken.isEncSymmetricEncryptionKey() && actionToken.getUser() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                    "empty", 
                    new Object[] {"WSHandler: Encryption: no username"});
        }

        handleSpecialUser(reqData);

        String encParts = getString(WSHandlerConstants.ENCRYPTION_PARTS, mc);
        if (encParts != null) {
            splitEncParts(true, encParts, actionToken.getParts(), reqData);
        }
        encParts = getString(WSHandlerConstants.OPTIONAL_ENCRYPTION_PARTS, mc);
        if (encParts != null) {
            splitEncParts(false, encParts, actionToken.getParts(), reqData);
        }
        
        boolean includeToken = decodeIncludeEncryptionToken(reqData);
        actionToken.setIncludeToken(includeToken);
    }

    /**
     * Decode the TimeToLive parameter for either a Timestamp or a UsernameToken Created element,
     * depending on the boolean argument
     */
    public int decodeTimeToLive(RequestData reqData, boolean timestamp) {
        String tag = WSHandlerConstants.TTL_TIMESTAMP;
        if (!timestamp) {
            tag = WSHandlerConstants.TTL_USERNAMETOKEN;
        }
        String ttl = getString(tag, reqData.getMsgContext());
        int defaultTimeToLive = 300;
        if (ttl != null) {
            try {
                int ttlI = Integer.parseInt(ttl);
                if (ttlI < 0) {
                    return defaultTimeToLive;
                }
                return ttlI;
            } catch (NumberFormatException e) {
                return defaultTimeToLive;
            }
        }
        return defaultTimeToLive;
    }
    
    /**
     * Decode the FutureTimeToLive parameter for either a Timestamp or a UsernameToken Created 
     * element, depending on the boolean argument
     */
    protected int decodeFutureTimeToLive(RequestData reqData, boolean timestamp) {
        String tag = WSHandlerConstants.TTL_FUTURE_TIMESTAMP;
        if (!timestamp) {
            tag = WSHandlerConstants.TTL_FUTURE_USERNAMETOKEN;
        }
        String ttl = getString(tag, reqData.getMsgContext());
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
    
    protected boolean decodeAddInclusivePrefixes(RequestData reqData)
        throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.ADD_INCLUSIVE_PREFIXES, true
        );
    }
    
    protected boolean decodeSamlSubjectConfirmationValidation(RequestData reqData)
        throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.VALIDATE_SAML_SUBJECT_CONFIRMATION, true
        );
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
    
    protected boolean decodeAllowUsernameTokenNoPassword(
        RequestData reqData
        ) throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.ALLOW_USERNAMETOKEN_NOPASSWORD, false
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
    
    protected boolean decodeUse200512Namespace(RequestData reqData) 
        throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.USE_2005_12_NAMESPACE, true
        );
    }
    
    protected boolean decodeUseSingleCertificate(RequestData reqData) 
        throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.USE_SINGLE_CERTIFICATE, true
        );
    }
    
    protected boolean decodeIncludeSignatureToken(RequestData reqData) 
        throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.INCLUDE_SIGNATURE_TOKEN, false
        );
    }
    
    protected boolean decodeIncludeEncryptionToken(RequestData reqData) 
        throws WSSecurityException {
        return decodeBooleanConfigValue(
            reqData, WSHandlerConstants.INCLUDE_ENCRYPTION_TOKEN, false
        );
    }
    
    protected void decodeRequireSignedEncryptedDataElements(RequestData reqData) 
        throws WSSecurityException {
        reqData.setRequireSignedEncryptedDataElements(decodeBooleanConfigValue(
            reqData, WSHandlerConstants.REQUIRE_SIGNED_ENCRYPTED_DATA_ELEMENTS, false
        ));
    }
    
    protected void decodeRequireTimestampExpires(RequestData reqData) 
        throws WSSecurityException {
        reqData.setRequireTimestampExpires(decodeBooleanConfigValue(
            reqData, WSHandlerConstants.REQUIRE_TIMESTAMP_EXPIRES, false
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

        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                "empty",
                new Object[] {"WSHandler: illegal " + configTag + " parameter"}
        );
    }
    
    /**
     * Hook to allow subclasses to load their Signature creation Crypto however they see
     * fit. 
     * 
     * @param requestData the RequestData object
     * @return a Crypto instance to use for Signature creation
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
     * Hook to allow subclasses to load their Signature verification Crypto however they see
     * fit. 
     * 
     * @param requestData the RequestData object
     * @return a Crypto instance to use for Signature verification
     */
    public Crypto loadSignatureVerificationCrypto(RequestData requestData) 
        throws WSSecurityException {
        return 
            loadCrypto(
                WSHandlerConstants.SIG_VER_PROP_FILE,
                WSHandlerConstants.SIG_VER_PROP_REF_ID,
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
                    crypto = CryptoFactory.getInstance((Properties)obj,
                                                       Loader.getClassLoader(CryptoFactory.class),
                                                       getPasswordEncryptor(requestData));
                    cryptos.put(refId, crypto);
                } else if (obj instanceof Crypto) {
                    crypto = (Crypto)obj;
                    cryptos.put(refId, crypto);
                }
            }
            if (crypto == null) {
                LOG.warn("The Crypto reference " + refId + " specified by "
                    + cryptoPropertyRefId + " could not be loaded"
                );
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
                if (crypto == null) {
                    LOG.warn(
                         "The Crypto properties file " + propFile + " specified by "
                         + cryptoPropertyFile + " could not be loaded or found"
                    );
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
        ClassLoader classLoader = this.getClassLoader(reqData.getMsgContext());
        Properties properties = CryptoFactory.getProperties(propFilename, classLoader);
        return 
            CryptoFactory.getInstance(
                properties, classLoader, getPasswordEncryptor(reqData)
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
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e,
                    "empty",
                    new Object[] {"WSHandler: cannot load callback handler class: " 
                    + callbackHandlerClass}
            );
        }
        try {
            cbHandler = cbClass.newInstance();
        } catch (Exception e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e,
                    "empty",
                    new Object[] {"WSHandler: cannot create instance of callback handler: " 
                    + callbackHandlerClass
                    }
            );
        }
        return cbHandler;
    }
    
    protected PasswordEncryptor getPasswordEncryptor(RequestData requestData) {
        PasswordEncryptor passwordEncryptor = requestData.getPasswordEncryptor();
        if (passwordEncryptor == null) {
            Object o = getOption(WSHandlerConstants.PASSWORD_ENCRYPTOR_INSTANCE);
            if (o instanceof PasswordEncryptor) {
                passwordEncryptor = (PasswordEncryptor) o;
            }
        }
        if (passwordEncryptor == null) {
            Object mc = requestData.getMsgContext();
            Object o = getProperty(mc, WSHandlerConstants.PASSWORD_ENCRYPTOR_INSTANCE);
            if (o instanceof PasswordEncryptor) {
                passwordEncryptor = (PasswordEncryptor) o;
            }
        }
        if (passwordEncryptor == null) {
            CallbackHandler callbackHandler = requestData.getCallbackHandler();
            if (callbackHandler != null) {
                passwordEncryptor = new JasyptPasswordEncryptor(callbackHandler);
            }
        }
        
        return passwordEncryptor;
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
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                        "empty", 
                        new Object[] {"WSHandler: application " + err});
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
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e,
                    "empty", new Object[] {"WSHandler: password callback failed"});
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
        case WSConstants.DKT_SIGN:
            reason = WSPasswordCallback.SECRET_KEY;
            break;
        case WSConstants.ENCR:
            reason = WSPasswordCallback.SECRET_KEY;
            break;
        case WSConstants.DKT_ENCR:
            reason = WSPasswordCallback.SECRET_KEY;
            break;
        }
        return new WSPasswordCallback(username, reason);
    }

    private void splitEncParts(boolean required, String tmpS,
                               List<WSEncryptionPart> parts, RequestData reqData)
        throws WSSecurityException {
        WSEncryptionPart encPart = null;
        String[] rawParts = tmpS.split(";");

        for (int i = 0; i < rawParts.length; i++) {
            String[] partDef = rawParts[i].split("}");

            if (partDef.length == 1) {
                if (doDebug) {
                    LOG.debug("single partDef: '" + partDef[0] + "'");
                }
                encPart =
                    new WSEncryptionPart(partDef[0].trim(),
                            reqData.getSoapConstants().getEnvelopeURI(),
                            "Content");
            } else if (partDef.length == 2) {
                String mode = partDef[0].trim().substring(1);
                String element = partDef[1].trim();
                encPart = new WSEncryptionPart(element, mode);
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
                    LOG.debug(
                        "partDefs: '" + mode + "' ,'" + nmSpace + "' ,'" + element + "'"
                    );
                }
                encPart = new WSEncryptionPart(element, nmSpace, mode);
            } else {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                        "empty", 
                        new Object[] {"WSHandler: wrong part definition: " + tmpS});
            }
            encPart.setRequired(required);
            parts.add(encPart);
        }
    }

    @SuppressWarnings("unchecked")
    private void handleSpecialUser(RequestData reqData) {
        EncryptionActionToken actionToken = reqData.getEncryptionToken();
        if (actionToken == null 
            || !WSHandlerConstants.USE_REQ_SIG_CERT.equals(actionToken.getUser())) {
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
                        (Integer) wser.get(WSSecurityEngineResult.TAG_ACTION);
                if (wserAction == WSConstants.SIGN) {
                    X509Certificate cert = 
                        (X509Certificate)wser.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
                    actionToken.setCertificate(cert);
                    return;
                }
            }
        }
    }

    protected void decodeSignatureParameter2(RequestData reqData) 
        throws WSSecurityException {
        if (reqData.getSigVerCrypto() == null) {
            reqData.setSigVerCrypto(loadSignatureVerificationCrypto(reqData));
        }
        if (reqData.getSigVerCrypto() == null) {
            reqData.setSigVerCrypto(loadSignatureCrypto(reqData));
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
                        LOG.debug(ex.getMessage(), ex);
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, ex);
                    }
                }
                reqData.setSubjectCertConstraints(subjectCertConstraints);
            }
        }
        
        boolean expandXOP = 
            decodeBooleanConfigValue(
                reqData, WSHandlerConstants.EXPAND_XOP_INCLUDE_FOR_SIGNATURE, true
            );
        reqData.setExpandXopIncludeForSignature(expandXOP);
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
        
        boolean allowRsa15 = 
            decodeBooleanConfigValue(
                reqData, WSHandlerConstants.ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM, false
            );
        reqData.setAllowRSA15KeyTransportAlgorithm(allowRsa15);
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
