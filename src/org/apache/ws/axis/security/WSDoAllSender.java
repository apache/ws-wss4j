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

import org.apache.axis.AxisFault;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.SOAPPart;
import org.apache.axis.handlers.BasicHandler;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.saml.SAMLIssuer;
import org.apache.ws.security.saml.SAMLIssuerFactory;
import org.apache.ws.axis.security.util.AxisUtil;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSAddTimestamp;
import org.apache.ws.security.message.WSEncryptBody;
import org.apache.ws.security.message.WSSAddSAMLToken;
import org.apache.ws.security.message.WSSAddUsernameToken;
import org.apache.ws.security.message.WSSignEnvelope;
import org.apache.ws.security.util.StringUtil;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.XMLUtils;
import org.opensaml.SAMLAssertion;
import org.w3c.dom.Document;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.security.cert.X509Certificate;
import java.util.Hashtable;
import java.util.Vector;

/**
 * @author Werner Dittmann (werner@apache.org)
 */
public class WSDoAllSender extends BasicHandler {

    static Log log = LogFactory.getLog(WSDoAllSender.class.getName());

    static final WSSecurityEngine secEngine = WSSecurityEngine.getInstance();

    private static boolean doDebug = true;

    private static Hashtable cryptos = new Hashtable(5);
    
    /**
     * This nested private class hold per request data.
     * 
     * @author wdi
     */
    protected class RequestData {
        MessageContext msgContext = null;

        boolean noSerialization = false;

        SOAPConstants soapConstants = null;

        String actor = null;

        String username = null;

        String pwType = null;

        String[] utElements = null;

        Crypto sigCrypto = null;

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

        int timeToLive = 300; 	// Timestamp: time in seconds between creation 
								// and expiery
        void clear() {
        	soapConstants = null;
        	actor = username = pwType = sigAlgorithm = encSymmAlgo = encKeyTransport = encUser = null;
        	sigCrypto = encCrypto = null;
        	signatureParts.clear();
        	encryptParts.clear();
        	signatureParts = encryptParts = null;
        	encCert = null;
        	utElements = null;
        }
    }

    /**
     * Initialize data fields from previous use in case of cached object. Axis
     * may cache the handler object, thus we need to intiailize (reset) some
     * data fields. In particular remove old elements from the vectors. The
     * other fields are initialized implictly using the lookup of the WSDD
     * parameter (getOption()) and properties.
     */
    private RequestData initialize() {
    	RequestData reqData = new RequestData();
    	return reqData;
    }

    /**
     * Axis calls invoke to handle a message. <p/>
     *
     * @param mc message context.
     * @throws AxisFault
     */
    public void invoke(MessageContext mc) throws AxisFault {

		doDebug = log.isDebugEnabled();
		if (doDebug) {
			log.debug("WSDoAllSender: enter invoke() with msg type: "
					+ mc.getCurrentMessage().getMessageType());
		}

		RequestData reqData = initialize();

		reqData.noSerialization = false;
		reqData.msgContext = mc;
		/*
		 * The overall try, just to have a finally at the end to perform some
		 * housekeeping.
		 */
		try {
			/*
			 * Get the action first.
			 */
			Vector actions = new Vector();
			String action = null;
			if ((action = (String) getOption(WSHandlerConstants.ACTION)) == null) {
				action = (String) reqData.msgContext
						.getProperty(WSHandlerConstants.ACTION);
			}
			if (action == null) {
				throw new AxisFault("WSDoAllSender: No action defined");
			}
			int doAction = AxisUtil.decodeAction(action, actions);
			if (doAction == WSConstants.NO_SECURITY) {
				return;
			}

			boolean mu = decodeMustUnderstand(reqData);

            secEngine.setPrecisionInMilliSeconds(decodeTimestampPrecision(reqData));

			if ((reqData.actor = (String) getOption(WSHandlerConstants.ACTOR)) == null) {
				reqData.actor = (String) reqData.msgContext
						.getProperty(WSHandlerConstants.ACTOR);
			}
			/*
			 * For every action we need a username, so get this now. The
			 * username defined in the deployment descriptor takes precedence.
			 */
			reqData.username = (String) getOption(WSHandlerConstants.USER);
			if (reqData.username == null || reqData.username.equals("")) {
                String username = (String) reqData.msgContext.getProperty(WSHandlerConstants.USER);
                if (username != null) {
                    reqData.username = username;
                } else {
                    reqData.username = reqData.msgContext.getUsername();
                    reqData.msgContext.setUsername(null);
                }
			}
			/*
			 * Now we perform some set-up for UsernameToken and Signature
			 * functions. No need to do it for encryption only. Check if
			 * username is available and then get a passowrd.
			 */
			if ((doAction & (WSConstants.SIGN | WSConstants.UT | WSConstants.UT_SIGN)) != 0) {
				/*
				 * We need a username - if none throw an AxisFault. For
				 * encryption there is a specific parameter to get a username.
				 */
				if (reqData.username == null || reqData.username.equals("")) {
					throw new AxisFault(
							"WSDoAllSender: Empty username for specified action");
				}
			}
			if (doDebug) {
				log.debug("Action: " + doAction);
				log.debug("Actor: " + reqData.actor + ", mu: " + mu);
			}
			/*
			 * Now get the SOAP part from the request message and convert it
			 * into a Document.
			 * 
			 * This forces Axis to serialize the SOAP request into FORM_STRING.
			 * This string is converted into a document.
			 * 
			 * During the FORM_STRING serialization Axis performs multi-ref of
			 * complex data types (if requested), generates and inserts
			 * references for attachements and so on. The resulting Document
			 * MUST be the complete and final SOAP request as Axis would send it
			 * over the wire. Therefore this must shall be the last (or only)
			 * handler in a chain.
			 * 
			 * Now we can perform our security operations on this request.
			 */
			Document doc = null;
			Message message = reqData.msgContext.getCurrentMessage();

			/*
			 * If the message context property conatins a document then this is
			 * a chained handler.
			 */
			SOAPPart sPart = (org.apache.axis.SOAPPart) message.getSOAPPart();
			if ((doc = (Document) reqData.msgContext
					.getProperty(WSHandlerConstants.SND_SECURITY)) == null) {
				try {
					doc = ((org.apache.axis.message.SOAPEnvelope) sPart
							.getEnvelope()).getAsDocument();
				} catch (Exception e) {
					throw new AxisFault(
							"WSDoAllSender: cannot get SOAP envlope from message"
									+ e);
				}
			}
			reqData.soapConstants = WSSecurityUtil.getSOAPConstants(doc
					.getDocumentElement());
			/*
			 * Here we have action, username, password, and actor,
			 * mustUnderstand. Now get the action specific parameters.
			 */
			if ((doAction & WSConstants.UT) == WSConstants.UT) {
				decodeUTParameter(reqData);
			}
			/*
			 * Here we have action, username, password, and actor,
			 * mustUnderstand. Now get the action specific parameters.
			 */
			if ((doAction & WSConstants.UT_SIGN) == WSConstants.UT_SIGN) {
				decodeUTParameter(reqData);
				decodeSignatureParameter(reqData);
			}
			/*
			 * Get and check the Signature specific parameters first because
			 * they may be used for encryption too.
			 */
			if ((doAction & WSConstants.SIGN) == WSConstants.SIGN) {
				reqData.sigCrypto = loadSignatureCrypto(reqData);
				decodeSignatureParameter(reqData);
			}
			/*
			 * If we need to handle signed SAML token then we need may of the
			 * Signature parameters. The handle procedure loads the signature
			 * crypto file on demand, thus don't do it here.
			 */
			if ((doAction & WSConstants.ST_SIGNED) == WSConstants.ST_SIGNED) {
				decodeSignatureParameter(reqData);
			}
			/*
			 * Set and check the encryption specific parameters, if necessary
			 * take over signature parameters username and crypto instance.
			 */
			if ((doAction & WSConstants.ENCR) == WSConstants.ENCR) {
				reqData.encCrypto = loadEncryptionCrypto(reqData);
				decodeEncryptionParameter(reqData);
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

				String password = null;
				switch (actionToDo) {
				case WSConstants.UT:
					performUTAction(actionToDo, mu, doc, reqData);
					break;

				case WSConstants.ENCR:
					performENCRAction(mu, actionToDo, doc, reqData);
					break;

				case WSConstants.SIGN:
					performSIGNAction(actionToDo, mu, doc, reqData);
					break;

				case WSConstants.ST_SIGNED:
					performST_SIGNAction(actionToDo, mu, doc, reqData);
					break;

				case WSConstants.ST_UNSIGNED:
					performSTAction(actionToDo, mu, doc, reqData);
					break;

				case WSConstants.TS:
					performTSAction(actionToDo, mu, doc, reqData);
					break;

				case WSConstants.UT_SIGN:
					performUT_SIGNAction(actionToDo, mu, doc, reqData);
					break;

				case WSConstants.NO_SERIALIZE:
					reqData.noSerialization = true;
					break;
				}
			}

			/*
			 * If required convert the resulting document into a message first.
			 * The outputDOM() method performs the necessary c14n call. After
			 * that we extract it as a string for further processing.
			 * 
			 * Set the resulting byte array as the new SOAP message.
			 * 
			 * If noSerialization is false, this handler shall be the last (or
			 * only) one in a handler chain. If noSerialization is true, just
			 * set the processed Document in the transfer property. The next
			 * Axis WSS4J handler takes it and performs additional security
			 * processing steps.
			 *  
			 */
			if (reqData.noSerialization) {
				reqData.msgContext.setProperty(WSHandlerConstants.SND_SECURITY,
						doc);
			} else {
				ByteArrayOutputStream os = new ByteArrayOutputStream();
				XMLUtils.outputDOM(doc, os, true);
				sPart.setCurrentMessage(os.toByteArray(), SOAPPart.FORM_BYTES);
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
				reqData.msgContext.setProperty(WSHandlerConstants.SND_SECURITY,
						null);
			}
			if (doDebug) {
				log.debug("WSDoAllSender: exit invoke()");
			}
		} finally {
			reqData.clear();
			reqData = null;
		}
	}

    private void performSIGNAction(int actionToDo, boolean mu, Document doc, RequestData reqData)
            throws AxisFault {
        String password;
        password =
                getPassword(reqData.username,
                        actionToDo,
                        WSHandlerConstants.PW_CALLBACK_CLASS,
                        WSHandlerConstants.PW_CALLBACK_REF, reqData)
                .getPassword();

        WSSignEnvelope wsSign = new WSSignEnvelope(reqData.actor, mu);
        if (reqData.sigKeyId != 0) {
            wsSign.setKeyIdentifierType(reqData.sigKeyId);
        }
        if (reqData.sigAlgorithm != null) {
            wsSign.setSignatureAlgorithm(reqData.sigAlgorithm);
        }

        wsSign.setUserInfo(reqData.username, password);
        if (reqData.signatureParts.size() > 0) {
            wsSign.setParts(reqData.signatureParts);
        }

        try {
            wsSign.build(doc, reqData.sigCrypto);
        } catch (WSSecurityException e) {
            throw new AxisFault("WSDoAllSender: Signature: error during message procesing" + e);
        }
    }

    private void performENCRAction(boolean mu, int actionToDo, Document doc, RequestData reqData)
            throws AxisFault {
        WSEncryptBody wsEncrypt = new WSEncryptBody(reqData.actor, mu);
        if (reqData.encKeyId != 0) {
            wsEncrypt.setKeyIdentifierType(reqData.encKeyId);
        }
        if (reqData.encKeyId == WSConstants.EMBEDDED_KEYNAME) {
            String encKeyName = null;
            if ((encKeyName =
                    (String) getOption(WSHandlerConstants.ENC_KEY_NAME))
                    == null) {
                encKeyName =
                        (String) reqData.msgContext.getProperty(WSHandlerConstants.ENC_KEY_NAME);
            }
            wsEncrypt.setEmbeddedKeyName(encKeyName);
            byte[] embeddedKey =
                    getPassword(reqData.encUser,
                            actionToDo,
                            WSHandlerConstants.ENC_CALLBACK_CLASS,
                            WSHandlerConstants.ENC_CALLBACK_REF, reqData)
                    .getKey();
            wsEncrypt.setKey(embeddedKey);
        }
        if (reqData.encSymmAlgo != null) {
            wsEncrypt.setSymmetricEncAlgorithm(reqData.encSymmAlgo);
        }
        if (reqData.encKeyTransport != null) {
            wsEncrypt.setKeyEnc(reqData.encKeyTransport);
        }
        wsEncrypt.setUserInfo(reqData.encUser);
        wsEncrypt.setUseThisCert(reqData.encCert);
        if (reqData.encryptParts.size() > 0) {
            wsEncrypt.setParts(reqData.encryptParts);
        }
        try {
            wsEncrypt.build(doc, reqData.encCrypto);
        } catch (WSSecurityException e) {
            throw new AxisFault("WSDoAllSender: Encryption: error during message processing"
                    + e);
        }
    }

    private void performUTAction(int actionToDo, boolean mu, Document doc, RequestData reqData)
            throws AxisFault {
        String password;
        password =
                getPassword(reqData.username,
                        actionToDo,
                        WSHandlerConstants.PW_CALLBACK_CLASS,
                        WSHandlerConstants.PW_CALLBACK_REF, reqData)
                .getPassword();

        WSSAddUsernameToken builder = new WSSAddUsernameToken(reqData.actor, mu);
        builder.setPasswordType(reqData.pwType);
        // add the UsernameToken to the SOAP Enevelope
        builder.build(doc, reqData.username, password);

        if (reqData.utElements != null && reqData.utElements.length > 0) {
            for (int j = 0; j < reqData.utElements.length; j++) {
            	reqData.utElements[j].trim();
                if (reqData.utElements[j].equals("Nonce")) {
                    builder.addNonce(doc);
                }
                if (reqData.utElements[j].equals("Created")) {
                    builder.addCreated(doc);
                }
                reqData.utElements[j] = null;
            }
        }
    }

    private void performUT_SIGNAction(int actionToDo, boolean mu, Document doc, RequestData reqData)
			throws AxisFault {
		String password;
		password = getPassword(reqData.username, actionToDo,
				WSHandlerConstants.PW_CALLBACK_CLASS,
				WSHandlerConstants.PW_CALLBACK_REF, reqData).getPassword();

		WSSAddUsernameToken builder = new WSSAddUsernameToken(reqData.actor, mu);
		builder.setPasswordType(WSConstants.PASSWORD_TEXT);
		builder.preSetUsernameToken(doc, reqData.username, password);
		builder.addCreated(doc);
		builder.addNonce(doc);

		WSSignEnvelope sign = new WSSignEnvelope(reqData.actor, mu);
        if (reqData.signatureParts.size() > 0) {
            sign.setParts(reqData.signatureParts);
        }
		sign.setUsernameToken(builder);
		sign.setKeyIdentifierType(WSConstants.UT_SIGNING);
		sign.setSignatureAlgorithm(XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
		try {
			sign.build(doc, null);
		} catch (WSSecurityException e) {
			throw new AxisFault("WSDoAllSender: Error during Signatur with UsernameToken secret"
					+ e);
		}
		builder.build(doc, null, null);
	}


    private void performSTAction(int actionToDo, boolean mu, Document doc, RequestData reqData)
            throws AxisFault {
        WSSAddSAMLToken builder = new WSSAddSAMLToken(reqData.actor, mu);
        SAMLIssuer saml = loadSamlIssuer(reqData);
        saml.setUsername(reqData.username);
        SAMLAssertion assertion = saml.newAssertion();

        // add the SAMLAssertion Token to the SOAP Enevelope
        builder.build(doc, assertion);
    }

    private void performST_SIGNAction(int actionToDo, boolean mu, Document doc, RequestData reqData)
            throws AxisFault {
        Crypto crypto = null;
        /*
         * it is possible and legal that we do not have a signature
         * crypto here - thus ignore the exception. This is usually
         * the case for the SAML option "sender vouches". In this case
         * no user crypto is required.
         */
        try {
        	crypto = loadSignatureCrypto(reqData);
        } catch (AxisFault ex) {}
        
        SAMLIssuer saml = loadSamlIssuer(reqData);
        saml.setUsername(reqData.username);
        saml.setUserCrypto(crypto);
        saml.setInstanceDoc(doc);

        SAMLAssertion assertion = saml.newAssertion();
        if (assertion == null) {
            throw new AxisFault("WSDoAllSender: Signed SAML: no SAML token received");
        }
        String issuerKeyName = null;
        String issuerKeyPW = null;
        Crypto issuerCrypto = null;

        WSSignEnvelope wsSign = new WSSignEnvelope(reqData.actor, mu);
        String password = null;
        if (saml.isSenderVouches()) {
            issuerKeyName = saml.getIssuerKeyName();
            issuerKeyPW = saml.getIssuerKeyPassword();
            issuerCrypto = saml.getIssuerCrypto();
        } else {
            password =
                    getPassword(reqData.username,
                            actionToDo,
                            WSHandlerConstants.PW_CALLBACK_CLASS,
                            WSHandlerConstants.PW_CALLBACK_REF, reqData)
                    .getPassword();
            wsSign.setUserInfo(reqData.username, password);
        }
        if (reqData.sigKeyId != 0) {
            wsSign.setKeyIdentifierType(reqData.sigKeyId);
        }
        try {
            wsSign.build(doc,
                    crypto,
                    assertion,
                    issuerCrypto,
                    issuerKeyName,
                    issuerKeyPW);
        } catch (WSSecurityException e) {
            throw new AxisFault("WSDoAllSender: Signed SAML: error during message processing"
                    + e);
        }
    }

    private void performTSAction(int actionToDo, boolean mu, Document doc, RequestData reqData) throws AxisFault {
        String ttl = null;
        if ((ttl =
                (String) getOption(WSHandlerConstants.TTL_TIMESTAMP))
                == null) {
            ttl =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.TTL_TIMESTAMP);
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
        WSAddTimestamp timeStampBuilder =
                new WSAddTimestamp(reqData.actor, mu);
        // add the Timestamp to the SOAP Enevelope
        timeStampBuilder.build(doc, ttl_i);
    }

    /**
     * Hook to allow subclasses to load their Signature Crypto however they see
     * fit.
     */
    protected Crypto loadSignatureCrypto(RequestData reqData) throws AxisFault {
        Crypto crypto = null;
        /*
         * Get crypto property file for signature. If none specified throw
         * fault, otherwise get a crypto instance.
         */
        String sigPropFile = null;
        if ((sigPropFile = (String) getOption(WSHandlerConstants.SIG_PROP_FILE))
                == null) {
            sigPropFile =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.SIG_PROP_FILE);
        }
        if (sigPropFile != null) {
            if ((crypto = (Crypto) cryptos.get(sigPropFile)) == null) {
                crypto = CryptoFactory.getInstance(sigPropFile);
                cryptos.put(sigPropFile, crypto);
            }
        } else {
            throw new AxisFault("WSDoAllSender: Signature: no crypto property file");
        }
        return crypto;
    }

    /**
     * Hook to allow subclasses to load their Encryption Crypto however they
     * see fit.
     */
    protected Crypto loadEncryptionCrypto(RequestData reqData) throws AxisFault {
        Crypto crypto = null;
        /*
         * Get encryption crypto property file. If non specified take crypto
         * instance from signature, if that fails: throw fault
         */
        String encPropFile = null;
        if ((encPropFile = (String) getOption(WSHandlerConstants.ENC_PROP_FILE))
                == null) {
            encPropFile =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.ENC_PROP_FILE);
        }
        if (encPropFile != null) {
            if ((crypto = (Crypto) cryptos.get(encPropFile)) == null) {
                crypto = CryptoFactory.getInstance(encPropFile);
                cryptos.put(encPropFile, crypto);
            }
        } else if ((crypto = reqData.sigCrypto) == null) {
            throw new AxisFault("WSDoAllSender: Encryption: no crypto property file");
        }
        return crypto;
    }

    protected SAMLIssuer loadSamlIssuer(RequestData reqData) {
        String samlPropFile = null;
        
        if ((samlPropFile =
            (String) getOption(WSHandlerConstants.SAML_PROP_FILE))
            == null) {
        samlPropFile =
                (String) reqData.msgContext.getProperty(WSHandlerConstants.SAML_PROP_FILE);
    }
        return SAMLIssuerFactory.getInstance(samlPropFile);  
    }

    private void decodeUTParameter(RequestData reqData) throws AxisFault {
        if ((reqData.pwType = (String) getOption(WSHandlerConstants.PASSWORD_TYPE))
                == null) {
        	reqData.pwType =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.PASSWORD_TYPE);
        }
        if (reqData.pwType != null) {
        	reqData.pwType =
        		reqData.pwType.equals(WSConstants.PW_TEXT)
                    ? WSConstants.PASSWORD_TEXT
                    : WSConstants.PASSWORD_DIGEST;
        }
        String tmpS = null;
        if ((tmpS = (String) getOption(WSHandlerConstants.ADD_UT_ELEMENTS))
                == null) {
            tmpS =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.ADD_UT_ELEMENTS);
        }
        if (tmpS != null) {
        	reqData.utElements = StringUtil.split(tmpS, ' ');
        }
    }

    private void decodeSignatureParameter(RequestData reqData) throws AxisFault {
        String tmpS = null;
        if ((tmpS = (String) getOption(WSHandlerConstants.SIG_KEY_ID)) == null) {
            tmpS = (String) reqData.msgContext.getProperty(WSHandlerConstants.SIG_KEY_ID);
        }
        if (tmpS != null) {
            Integer I = (Integer) WSHandlerConstants.keyIdentifier.get(tmpS);
            if (I == null) {
                throw new AxisFault("WSDoAllSender: Signature: unknown key identification");
            }
            reqData.sigKeyId = I.intValue();
            if (!(reqData.sigKeyId == WSConstants.ISSUER_SERIAL
                    || reqData.sigKeyId == WSConstants.BST_DIRECT_REFERENCE
                    || reqData.sigKeyId == WSConstants.X509_KEY_IDENTIFIER
                    || reqData.sigKeyId == WSConstants.SKI_KEY_IDENTIFIER)) {
                throw new AxisFault("WSDoAllSender: Signature: illegal key identification");
            }
        }
        if ((reqData.sigAlgorithm = (String) getOption(WSHandlerConstants.SIG_ALGO))
                == null) {
            tmpS = (String) reqData.msgContext.getProperty(WSHandlerConstants.SIG_ALGO);
        }
        if ((tmpS = (String) getOption(WSHandlerConstants.SIGNATURE_PARTS))
                == null) {
            tmpS =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.SIGNATURE_PARTS);
        }
        if (tmpS != null) {
            splitEncParts(tmpS, reqData.signatureParts, reqData);
        }
    }

    private void decodeEncryptionParameter(RequestData reqData) throws AxisFault {
        if ((reqData.encUser = (String) getOption(WSHandlerConstants.ENCRYPTION_USER))
                == null) {
        	reqData.encUser =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.ENCRYPTION_USER);
        }

        if (reqData.encUser == null && (reqData.encUser = reqData.username) == null) {
            throw new AxisFault("WSDoAllSender: Encryption: no username");
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
        String tmpS = null;
        if ((tmpS = (String) getOption(WSHandlerConstants.ENC_KEY_ID)) == null) {
            tmpS = (String) reqData.msgContext.getProperty(WSHandlerConstants.ENC_KEY_ID);
        }
        if (tmpS != null) {
            Integer I = (Integer) WSHandlerConstants.keyIdentifier.get(tmpS);
            if (I == null) {
                throw new AxisFault("WSDoAllSender: Encryption: unknown key identification");
            }
            reqData.encKeyId = I.intValue();
            if (!(reqData.encKeyId == WSConstants.ISSUER_SERIAL
                    || reqData.encKeyId == WSConstants.X509_KEY_IDENTIFIER
                    || reqData.encKeyId == WSConstants.SKI_KEY_IDENTIFIER
                    || reqData.encKeyId == WSConstants.BST_DIRECT_REFERENCE
                    || reqData.encKeyId == WSConstants.EMBEDDED_KEYNAME)) {
                throw new AxisFault("WSDoAllSender: Encryption: illegal key identification");
            }
        }
        if ((reqData.encSymmAlgo = (String) getOption(WSHandlerConstants.ENC_SYM_ALGO))
                == null) {
        	reqData.encSymmAlgo =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.ENC_SYM_ALGO);
        }
        if ((reqData.encKeyTransport =
                (String) getOption(WSHandlerConstants.ENC_KEY_TRANSPORT))
                == null) {
        	reqData.encKeyTransport =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.ENC_KEY_TRANSPORT);
        }
        if ((tmpS = (String) getOption(WSHandlerConstants.ENCRYPTION_PARTS))
                == null) {
            tmpS =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.ENCRYPTION_PARTS);
        }
        if (tmpS != null) {
            splitEncParts(tmpS, reqData.encryptParts, reqData);
        }
    }

    private boolean decodeMustUnderstand(RequestData reqData) throws AxisFault {
        boolean mu = true;
        String mustUnderstand = null;
        if ((mustUnderstand =
                (String) getOption(WSHandlerConstants.MUST_UNDERSTAND))
                == null) {
            mustUnderstand =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.MUST_UNDERSTAND);
        }
        if (mustUnderstand != null) {
            if (mustUnderstand.equals("0") || mustUnderstand.equals("false")) {
                mu = false;
            } else if (
                    mustUnderstand.equals("1") || mustUnderstand.equals("true")) {
                mu = true;
            } else {
                throw new AxisFault("WSDoAllSender: illegal mustUnderstand parameter");
            }
        }
        return mu;
    }

    private boolean decodeTimestampPrecision(RequestData reqData) throws AxisFault {
        boolean precisionInMilliSeconds = true;
        String value = null;
        if ((value =
                (String) getOption(WSHandlerConstants.TIMESTAMP_PRECISION))
                == null) {
            value =
                    (String) reqData.msgContext.getProperty(WSHandlerConstants.TIMESTAMP_PRECISION);
        }
        if (value != null) {
            if (value.equals("0") || value.equals("false")) {
                precisionInMilliSeconds = false;
            } else if (
                    value.equals("1") || value.equals("true")) {
                precisionInMilliSeconds = true;
            } else {
                throw new AxisFault("WSDoAllSender: illegal precisionInMilliSeconds parameter");
            }
        }
        return precisionInMilliSeconds;
    }

    /**
     * Get a password to construct a UsernameToken or sign a message.
     * <p/>
     * Try all possible sources to get a password.
     */
    private WSPasswordCallback getPassword(String username,
                                           int doAction,
                                           String clsProp,
                                           String refProp,
										   RequestData reqData)
            throws AxisFault {
        WSPasswordCallback pwCb = null;
        String password = null;
        String callback = null;
        CallbackHandler cbHandler = null;

        if ((callback = (String) getOption(clsProp)) == null) {
            callback = (String) reqData.msgContext.getProperty(clsProp);
        }
        if (callback != null) { // we have a password callback class
            pwCb = readPwViaCallbackClass(callback, username, doAction);
            if ((pwCb.getPassword() == null) && (pwCb.getKey() == null)) {
                throw new AxisFault("WSDoAllSender: password callback class provided null or empty password");
            }
        } else if (
                (cbHandler = (CallbackHandler) reqData.msgContext.getProperty(refProp))
                != null) {
            pwCb = performCallback(cbHandler, username, doAction);
            if ((pwCb.getPassword() == null) && (pwCb.getKey() == null)) {
                throw new AxisFault("WSDoAllSender: password callback provided null or empty password");
            }
        } else if ((password = reqData.msgContext.getPassword()) == null) {
            throw new AxisFault("WSDoAllSender: application provided null or empty password");
        } else {
        	reqData.msgContext.setPassword(null);
            pwCb = new WSPasswordCallback("", WSPasswordCallback.UNKNOWN);
            pwCb.setPassword(password);
        }
        return pwCb;
    }

    private WSPasswordCallback readPwViaCallbackClass(String callback,
                                                      String username,
                                                      int doAction)
            throws AxisFault {

        Class cbClass = null;
        CallbackHandler cbHandler = null;
        try {
            cbClass = java.lang.Class.forName(callback);
        } catch (ClassNotFoundException e) {
            throw new AxisFault("WSDoAllSender: cannot load password callback class: "
                    + callback,
                    e);
        }
        try {
            cbHandler = (CallbackHandler) cbClass.newInstance();
        } catch (java.lang.Exception e) {
            throw new AxisFault("WSDoAllSender: cannot create instance of password callback: "
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
            throws AxisFault {

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
            throw new AxisFault("WSDoAllSender: password callback failed", e);
        }
        return pwCb;
    }

    private void splitEncParts(String tmpS, Vector parts, RequestData reqData)
            throws AxisFault {
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
                        		reqData.soapConstants.getEnvelopeURI(),
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
                    nmSpace = reqData.soapConstants.getEnvelopeURI();
                } else {
                    nmSpace = nmSpace.substring(1);
                    if (nmSpace.equals(WSConstants.NULL_NS)) {
                    	nmSpace = null;
                    }
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
                throw new AxisFault("WSDoAllSender: wrong part definition: " + tmpS);
            }
            parts.add(encPart);
        }
    }

    private void handleSpecialUser(RequestData reqData) {
        if (!WSHandlerConstants.USE_REQ_SIG_CERT.equals(reqData.encUser)) {
            return;
        }
        Vector results = null;
        if ((results =
                (Vector) reqData.msgContext.getProperty(WSHandlerConstants.RECV_RESULTS))
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
            if (!WSSecurityUtil.isActorEqual(reqData.actor, hActor)) {
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
                	reqData.encCert = wser.getCertificate();
                    return;
                }
            }
        }
    }
}
