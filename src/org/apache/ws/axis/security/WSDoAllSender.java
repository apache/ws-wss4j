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
import org.apache.ws.axis.security.util.AxisUtil;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSEncryptBody;
import org.apache.ws.security.message.WSSAddUsernameToken;
import org.apache.ws.security.message.WSSignEnvelope;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.util.StringUtil;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;

import java.security.cert.X509Certificate;

import java.io.ByteArrayOutputStream;
import java.util.Hashtable;
import java.util.Vector;

/**
 *
 * @author Werner Dittmann (Werner.Dittmann@siemens.com)
 */
public class WSDoAllSender extends BasicHandler {

	static Log log = LogFactory.getLog(WSDoAllSender.class.getName());
	static final WSSecurityEngine secEngine = new WSSecurityEngine();

	private boolean doDebug = true;

	private static Hashtable cryptos = new Hashtable(5);

	private MessageContext msgContext = null;

	private int securityAction = WSConstants.NO_SECURITY;

	private boolean noSerialization = false;
	
	private SOAPConstants soapConstants = null;
	
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

	/**
	 * Axis calls invoke to handle a message.
	 * <p/>
	 * 
	 * @param msgContext message context.
	 * @throws AxisFault 
	 */
	public void invoke(MessageContext mc) throws AxisFault {

		doDebug = log.isDebugEnabled();
		if (doDebug) {
			log.debug(
				"WSDoAllSender: enter invoke() with msg type: "
					+ mc.getCurrentMessage().getMessageType());
		}
		noSerialization = false;
		msgContext = mc;
		/*
		 * Get the action first.
		 */
		Vector actions = new Vector();
		String action = null;
		if ((action = (String) getOption(WSDoAllConstants.ACTION)) == null) {
			action = (String) msgContext.getProperty(WSDoAllConstants.ACTION);
		}
		if (action == null) {
			throw new AxisFault("WSDoAllReceiver: No action defined");
		}
		int doAction = AxisUtil.decodeAction(action, actions);
		if (doAction == WSConstants.NO_SECURITY) {
			return;
		}

		boolean mu = decodeMustUnderstand();

		if ((actor = (String) getOption(WSDoAllConstants.ACTOR)) == null) {
			actor = (String) msgContext.getProperty(WSDoAllConstants.ACTOR);
		}
		/*
		 * For every action we need a username, so get this now.
		 * The username defined in the deployment descriptor takes
		 * precedence.
		 */
		username = (String) getOption(WSDoAllConstants.USER);
		if (username == null || username.equals("")) {
			username = msgContext.getUsername();
			msgContext.setUsername(null);
		}
		/*
		 * Now we perform some set-up for UsernameToken and Signature 
		 * functions. No need to do it for encryption only.
		 * Check if username is available and then get a passowrd.
		 */
		if ((doAction & (WSConstants.SIGN | WSConstants.UT)) != 0) {
			/*
			 * We need a username - if none throw an AxisFault. For
			 * encryption there is a specific parameter to get a username.
			 */
			if (username == null || username.equals("")) {
				throw new AxisFault("WSDoAllSender: Empty username for specified action");
			}
		}
		if (doDebug) {
			log.debug("Action: " + doAction);
			log.debug("Actor: " + actor + ", mu: " + mu);
		}
		/*
		 * Now get the SOAP part from the request message and convert it into
		 * a Document.
		 * 
		 * This forces Axis to serialize the SOAP request into FORM_STRING. 
		 * This string is converted into a document.
		 * 
		 * During the FORM_STRING serialization Axis performs multi-ref of 
		 * complex data types (if requested), generates and inserts references
		 * for attachements and so on. The resulting Document MUST be
		 * the complete and final SOAP request as Axis would send it over 
		 * the wire. Therefore this must shall be the last (or only) handler
		 * in a chain.
		 * 
		 * Now we can perform our security operations on this request. 
		 */
		Document doc = null;
		Message message = msgContext.getCurrentMessage();

		/*
		 * If the message context property conatins a document then this
		 * is a chained handler. 
		 */
		SOAPPart sPart = (org.apache.axis.SOAPPart) message.getSOAPPart();
		if ((doc =
			(Document) msgContext.getProperty(WSDoAllConstants.SND_SECURITY))
			== null) {
			try {
				doc =
					((org.apache.axis.message.SOAPEnvelope) sPart
						.getEnvelope())
						.getAsDocument();
			} catch (Exception e) {
				throw new AxisFault(
					"WSDoAllSender: cannot get SOAP envlope from message" + e);
			}
		}
		soapConstants = WSSecurityUtil.getSOAPConstants(doc.getDocumentElement());
		/*
		 * Here we have action, username, password, and actor, mustUnderstand.
		 * Now get the action specific parameters. 
		 */
		if ((doAction & WSConstants.UT) == WSConstants.UT) {
			decodeUTParameter();
		}
		/*
		 * Get and check the Signature specific parameters first because they 
		 * may be used for encryption too.
		 */
		if ((doAction & WSConstants.SIGN) == WSConstants.SIGN) {
			decodeSignatureParameter();
		}
		/*
		 * Set and check the encryption specific parameters, if necessary
		 * take over signature parameters username and crypto instance.
		 */
		if ((doAction & WSConstants.ENCR) == WSConstants.ENCR) {
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

			String password = null;
			switch (actionToDo) {
				case WSConstants.UT :
					password =
						getPassword(
							username,
							actionToDo,
							WSDoAllConstants.PW_CALLBACK_CLASS,
							WSDoAllConstants.PW_CALLBACK_REF)
							.getPassword();

					WSSAddUsernameToken builder =
						new WSSAddUsernameToken(actor, mu);
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
					break;

				case WSConstants.ENCR :
					WSEncryptBody wsEncrypt = new WSEncryptBody(actor, mu);
					if (encKeyId != 0) {
						wsEncrypt.setKeyIdentifierType(encKeyId);
					}
					if (encKeyId == WSConstants.EMBEDDED_KEYNAME) {
                        String encKeyName = null;
						if ((encKeyName =
							(String) getOption(WSDoAllConstants.ENC_KEY_NAME))
							== null) {
							encKeyName =
								(String) msgContext.getProperty(
									WSDoAllConstants.ENC_KEY_NAME);
						}
                        wsEncrypt.setEmbeddedKeyName(encKeyName);
						byte[] embeddedKey =
							getPassword(
								encUser,
								actionToDo,
								WSDoAllConstants.ENC_CALLBACK_CLASS,
								WSDoAllConstants.ENC_CALLBACK_REF)
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
						throw new AxisFault(
							"WSDoAllSender: Encryption: error during message processing"
								+ e);
					}
					break;

				case WSConstants.SIGN :
					password =
						getPassword(
							username,
							actionToDo,
							WSDoAllConstants.PW_CALLBACK_CLASS,
							WSDoAllConstants.PW_CALLBACK_REF)
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
						throw new AxisFault(
							"WSDoAllSender: Signature: error during message procesing"
								+ e);
					}
					break;

				case WSConstants.NO_SERIALIZE :
					noSerialization = true;
					break;
			}
		}
      
		/*
		 * If required convert the resulting document into a message first. 
		 * The outputDOM() method performs the necessary c14n call. After 
		 * that we extract it as a string for further processing.
		 * 
		 * Set the resulting string as the new SOAP message.
		 * 
		 * NOTE: must be set as FORM_STRING, otherwise Axis will serialize
		 * the message again. That could change the content of the message
		 * and therefore invalidates a signature. It would also not work
		 * if the SOAP request contains attachements because Axis couldn't
		 * find the references and so on...
		 * 
		 * If noSerialization is false, this handler shall be the last 
		 * (or only) one in a handler chain. 
		 * If noSerialization is true, just set the processed Document in
		 * the transfer property. The next Axis WSS4J handler takes it
		 * and performs additional security processing steps.  
		 * 
		 */
		if (noSerialization) {
			msgContext.setProperty(WSDoAllConstants.SND_SECURITY, doc);
		} else {
			ByteArrayOutputStream os = new ByteArrayOutputStream();
			XMLUtils.outputDOM(doc, os, true);
			String osStr = os.toString();
			if (doDebug) {
				log.debug("Send request:");
				log.debug(osStr);
			}
			sPart.setCurrentMessage(osStr, SOAPPart.FORM_STRING);
			msgContext.setProperty(WSDoAllConstants.SND_SECURITY, null);
		}
		if (doDebug) {
			log.debug("WSDoAllSender: exit invoke()");
		}
	}
	
	/**
	 * Hook to allow subclasses to load their Signature Crypto however they see fit.
	 */
	protected Crypto loadSignatureCrypto() throws AxisFault {
		Crypto crypto = null;
		/*
		 * Get crypto property file for signature. If none specified
		 * throw fault, otherwise get a crypto instance.
		 */
		String sigPropFile = null;
		if ((sigPropFile = (String) getOption(WSDoAllConstants.SIG_PROP_FILE))
		== null) {
			sigPropFile =
				(String) msgContext.getProperty(WSDoAllConstants.SIG_PROP_FILE);
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
	 * Hook to allow subclasses to load their Encryption Crypto however they see fit.
	 */
	protected Crypto loadEncryptionCrypto() throws AxisFault {
		Crypto crypto = null;
		/*
		 * Get encryption crypto property file. If non specified
		 * take crypto instance from signature, if that fails: throw fault
		 */
		String encPropFile = null;
		if ((encPropFile = (String) getOption(WSDoAllConstants.ENC_PROP_FILE))
		== null) {
			encPropFile =
				(String) msgContext.getProperty(WSDoAllConstants.ENC_PROP_FILE);
		}
		if (encPropFile != null) {
			if ((crypto = (Crypto) cryptos.get(encPropFile)) == null) {
				crypto = CryptoFactory.getInstance(encPropFile);
				cryptos.put(encPropFile, crypto);
			}
		} else if ((crypto = sigCrypto) == null) {
			throw new AxisFault("WSDoAllSender: Encryption: no crypto property file");
		}
		return crypto;
	}
	
	private void decodeUTParameter() throws AxisFault {
		if ((pwType = (String) getOption(WSDoAllConstants.PASSWORD_TYPE))
			== null) {
			pwType =
				(String) msgContext.getProperty(WSDoAllConstants.PASSWORD_TYPE);
		}
		if (pwType != null) {
			pwType =
				pwType.equals(WSConstants.PW_TEXT)
					? WSConstants.PASSWORD_TEXT
					: WSConstants.PASSWORD_DIGEST;
		}
		String tmpS = null;
		if ((tmpS = (String) getOption(WSDoAllConstants.ADD_UT_ELEMENTS))
			== null) {
			tmpS =
				(String) msgContext.getProperty(WSDoAllConstants.ADD_UT_ELEMENTS);
		}
		if (tmpS != null) {
			utElements = StringUtil.split(tmpS,' ');
		}
	}

	private void decodeSignatureParameter() throws AxisFault {

		sigCrypto = loadSignatureCrypto();
		String tmpS = null;
		if ((tmpS = (String) getOption(WSDoAllConstants.SIG_KEY_ID)) == null) {
			tmpS = (String) msgContext.getProperty(WSDoAllConstants.SIG_KEY_ID);
		}
		if (tmpS != null) {
			Integer I = (Integer) WSDoAllConstants.keyIdentifier.get(tmpS);
			if (I == null) {
				throw new AxisFault("WSDoAllSender: Signature: unknown key identification");
			}
			sigKeyId = I.intValue();
			if (!(sigKeyId == WSConstants.ISSUER_SERIAL
				|| sigKeyId == WSConstants.BST_DIRECT_REFERENCE
				|| sigKeyId == WSConstants.X509_KEY_IDENTIFIER
				|| sigKeyId == WSConstants.SKI_KEY_IDENTIFIER)) {
				throw new AxisFault("WSDoAllSender: Signature: illegal key identification");
			}
		}
		if ((sigAlgorithm = (String) getOption(WSDoAllConstants.SIG_ALGO))
			== null) {
			tmpS = (String) msgContext.getProperty(WSDoAllConstants.SIG_ALGO);
		}
		if ((tmpS = (String) getOption(WSDoAllConstants.SIGNATURE_PARTS))
			== null) {
			tmpS =
				(String) msgContext.getProperty(
					WSDoAllConstants.SIGNATURE_PARTS);
		}
		if (tmpS != null) {
			splitEncParts(tmpS, signatureParts);
		}
	}
	
	private void decodeEncryptionParameter() throws AxisFault {
		encCrypto = loadEncryptionCrypto();
		if ((encUser = (String) getOption(WSDoAllConstants.ENCRYPTION_USER))
			== null) {
			encUser =
				(String) msgContext.getProperty(
					WSDoAllConstants.ENCRYPTION_USER);
		}

		if (encUser == null && (encUser = username) == null) {
			throw new AxisFault("WSDoAllSender: Encryption: no username");
		}
		/*
		String msgType = msgContext.getCurrentMessage().getMessageType();
		if (msgType != null && msgType.equals(Message.RESPONSE)) {
			handleSpecialUser(encUser);
		}
		*/
		handleSpecialUser(encUser);		

		/*
		 * If the following parameters are no used (they return null)
		 * then the default values of WSS4J are used.
		 */
		String tmpS = null;
		if ((tmpS = (String) getOption(WSDoAllConstants.ENC_KEY_ID)) == null) {
			tmpS = (String) msgContext.getProperty(WSDoAllConstants.ENC_KEY_ID);
		}
		if (tmpS != null) {
			Integer I = (Integer) WSDoAllConstants.keyIdentifier.get(tmpS);
			if (I == null) {
				throw new AxisFault("WSDoAllSender: Encryption: unknown key identification");
			}
			encKeyId = I.intValue();
			if (!(encKeyId == WSConstants.ISSUER_SERIAL
				|| encKeyId == WSConstants.X509_KEY_IDENTIFIER
				|| encKeyId == WSConstants.SKI_KEY_IDENTIFIER
				|| encKeyId == WSConstants.BST_DIRECT_REFERENCE
				|| encKeyId == WSConstants.EMBEDDED_KEYNAME)) {
				throw new AxisFault("WSDoAllSender: Encryption: illegal key identification");
			}
		}
		if ((encSymmAlgo = (String) getOption(WSDoAllConstants.ENC_SYM_ALGO))
			== null) {
			encSymmAlgo =
				(String) msgContext.getProperty(WSDoAllConstants.ENC_SYM_ALGO);
		}
		if ((encKeyTransport =
			(String) getOption(WSDoAllConstants.ENC_KEY_TRANSPORT))
			== null) {
			encKeyTransport =
				(String) msgContext.getProperty(
					WSDoAllConstants.ENC_KEY_TRANSPORT);
		}
		if ((tmpS = (String) getOption(WSDoAllConstants.ENCRYPTION_PARTS))
			== null) {
			tmpS =
				(String) msgContext.getProperty(
					WSDoAllConstants.ENCRYPTION_PARTS);
		}
		if (tmpS != null) {
			splitEncParts(tmpS, encryptParts);
		}
	}
	
	private boolean decodeMustUnderstand() throws AxisFault {
		boolean mu = true;
		String mustUnderstand = null;
		if ((mustUnderstand =
			(String) getOption(WSDoAllConstants.MUST_UNDERSTAND))
			== null) {
			mustUnderstand =
				(String) msgContext.getProperty(
					WSDoAllConstants.MUST_UNDERSTAND);
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
	/**
	 * Get a password to construct a UsernameToken or sign a message.
	 * <p/>
	 * Try all possible sources to get a password. 
	 */
	private WSPasswordCallback getPassword(
		String username,
		int doAction,
		String clsProp,
		String refProp)
		throws AxisFault {
		WSPasswordCallback pwCb = null;
		String password = null;
		String callback = null;
		CallbackHandler cbHandler = null;

		if ((callback = (String) getOption(clsProp)) == null) {
			callback = (String) msgContext.getProperty(clsProp);
		}
		if (callback != null) { // we have a password callback class
			pwCb = readPwViaCallbackClass(callback, username, doAction);
			if ((pwCb.getPassword() == null) && (pwCb.getKey() == null)) {
				throw new AxisFault("WSDoAllSender: password callback class provided null or empty password");
			}
		} else if (
			(cbHandler = (CallbackHandler) msgContext.getProperty(refProp))
				!= null) {
			pwCb = performCallback(cbHandler, username, doAction);
			if ((pwCb.getPassword() == null) && (pwCb.getKey() == null)) {
				throw new AxisFault("WSDoAllSender: password callback provided null or empty password");
			}
		} else if ((password = msgContext.getPassword()) == null) {
			throw new AxisFault("WSDoAllSender: application provided null or empty password");
		} else {
			msgContext.setPassword(null);
			pwCb = new WSPasswordCallback("", WSPasswordCallback.UNKNOWN);
			pwCb.setPassword(password);
		}
		return pwCb;
	}

	private WSPasswordCallback readPwViaCallbackClass(
		String callback,
		String username,
		int doAction)
		throws AxisFault {

		Class cbClass = null;
		CallbackHandler cbHandler = null;
		try {
			cbClass = java.lang.Class.forName(callback);
		} catch (ClassNotFoundException e) {
			throw new AxisFault(
				"WSDoAllSender: cannot load password callback class: "
					+ callback,
				e);
		}
		try {
			cbHandler = (CallbackHandler) cbClass.newInstance();
		} catch (java.lang.Exception e) {
			throw new AxisFault(
				"WSDoAllSender: cannot create instance of password callback: "
					+ callback,
				e);
		}
		return (performCallback(cbHandler, username, doAction));
	}

	/**
	 * Perform a callback to get a password. 
	 * 
	 * The called back function gets an indication why to provide
	 * a password: to produce a UsernameToken, Signature, or a password
	 * (key) for a given name.
	 */
	private WSPasswordCallback performCallback(
		CallbackHandler cbHandler,
		String username,
		int doAction)
		throws AxisFault {

		WSPasswordCallback pwCb = null;
		int reason = 0;

		switch (doAction) {
			case WSConstants.UT :
				reason = WSPasswordCallback.USERNAME_TOKEN;
				break;
			case WSConstants.SIGN :
				reason = WSPasswordCallback.SIGNATURE;
				break;
			case WSConstants.ENCR :
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

	private void splitEncParts(String tmpS, Vector encryptParts)
		throws AxisFault {
		WSEncryptionPart encPart = null;
		String[] rawParts = StringUtil.split(tmpS,';');

		for (int i = 0; i < rawParts.length; i++) {
			String[] partDef = StringUtil.split(rawParts[i],'}');

			if (partDef.length == 1) {
				if (doDebug) {
					log.debug("single partDef: '" + partDef[0] + "'");
				}
				encPart =
					new WSEncryptionPart(
						partDef[0].trim(),
						soapConstants.getEnvelopeURI(),
						"Content");
			} else if (partDef.length == 3) {
				String mode = partDef[0].trim();
				if (mode.length() <= 1) {
					mode = "Content";
				}
				else {
					mode = mode.substring(1);
				}
				String nmSpace = partDef[1].trim();
				if (nmSpace.length() <= 1) {
					nmSpace = soapConstants.getEnvelopeURI();
				}
				else {
					nmSpace = nmSpace.substring(1);
				}
				String element = partDef[2].trim();
				if (doDebug) {
					log.debug(
						"partDefs: '"
							+ mode
							+ "' ,'"
							+ nmSpace
							+ "' ,'"
							+ element
							+ "'");
				}
				encPart = new WSEncryptionPart(element, nmSpace, mode);
			} else {
				throw new AxisFault(
					"WSDoAllSender: wrong part definition: " + tmpS);
			}
			encryptParts.add(encPart);
		}
	}

	private void handleSpecialUser(String encUser) {
		if (!WSDoAllConstants.USE_REQ_SIG_CERT.equals(encUser)) {
			return;
		}
		Vector results = null;
		if ((results =
			(Vector) msgContext.getProperty(WSDoAllConstants.RECV_RESULTS))
			== null) {
			return;
		}
		/*
		 * Scan the results for a matching actor. Use results only
		 * if the receiving Actor and the sending Actor match.
		 */
		for (int i = 0; i < results.size(); i++) {
			WSDoAllReceiverResult rResult =
				(WSDoAllReceiverResult) results.get(i);
			String hActor = rResult.getActor();
			if (!WSSecurityUtil.isActorEqual(actor, hActor)) {
				continue;
			}			
			Vector wsSecEngineResults = rResult.getResults();
			/*
			 * Scan the results for the first Signature action. Use
			 * the certificate of this Signature to set the certificate
			 * for the encryption action :-).
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
}
