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
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.xml.security.utils.XMLUtils;
import org.w3c.dom.Document;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import java.io.ByteArrayOutputStream;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.Vector;

public class WSDoAllReceiver extends BasicHandler {
	static Log log = LogFactory.getLog(WSDoAllReceiver.class.getName());
	static final WSSecurityEngine secEngine = new WSSecurityEngine();

	private boolean doDebug = true;

	private static Hashtable cryptos = new Hashtable(5);

	private MessageContext msgContext = null;

	Crypto sigCrypto = null;
	String sigPropFile = null;

	Crypto decCrypto = null;
	String decPropFile = null;

	/**
	 * Axis calls invoke to handle a message.
	 * <p/>
	 * 
	 * @param msgContext message context.
	 * @throws AxisFault 
	 */
	public void invoke(MessageContext mc) throws AxisFault {

		// doDebug = log.isDebugEnabled();
		if (doDebug) {
			log.debug("WSDoAllReceiver: enter invoke()");
		}
		msgContext = mc;

		Vector actions = new Vector();
		String action = null;
		if ((action = (String) getOption(WSDoAllConstants.ACTION)) == null) {
			action = (String) msgContext.getProperty(WSDoAllConstants.ACTION);
		}
		if (action == null) {
			throw new AxisFault("WSDoAllReceiver: No action defined");
		}
		int doAction = AxisUtil.decodeAction(action, actions);

		Message sm = msgContext.getCurrentMessage();
		SOAPHeader sHeader = null;
		try {
			sHeader = sm.getSOAPEnvelope().getHeader();
		} catch (Exception ex) {
			throw new AxisFault("WSDoAllReceiver: cannot get SOAP header", ex);
		}

		String actor = (String) getOption(WSDoAllConstants.ACTOR);
		Iterator headers = sHeader.examineHeaderElements(actor);

		SOAPHeaderElement headerElement = null;
		while (headers.hasNext()) {
			headerElement = (SOAPHeaderElement) headers.next();
			if (headerElement.getLocalName().equals(WSConstants.WSSE_LN)
				&& headerElement.getNamespaceURI().equals(WSConstants.WSSE_NS)) {
				break;
			}
		}

		if (doDebug && headerElement != null) {
			log.debug("Header found: " + headerElement.getLocalName());
		}

		/*
		 * If no security header found, then also action must be defined
		 * as NO_SECURITY, otherwise its a fault 
		 */
		if (headerElement == null) {
			// TODO: if no header - check if message is a response _and_ is a SOAP fault
			// in this case don't modify anything, just return for default processing
			if (doAction == WSConstants.NO_SECURITY) {
				return;
			} else {
				throw new AxisFault("WSDoAllReceiver: Request does not contain required Security header");
			}
		} else {
			((org.apache.axis.message.SOAPHeaderElement) headerElement)
						.setProcessed(true);
		}

		Document doc = null;
		try {
			doc = sm.getSOAPEnvelope().getAsDocument();
			if (doDebug) {
				log.debug(sm.getSOAPPartAsString());
			}
		} catch (Exception ex) {
			throw new AxisFault(
				"WSDoAllReceiver: cannot convert into document",
				ex);
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

		WSSecurityEngineResult wsResult = null;
		try {
			wsResult =
				secEngine.processSecurityHeader(
					doc,
					actor,
					cbHandler,
					sigCrypto,
					decCrypto);
		} catch (Exception ex) {
			throw new AxisFault(
				"WSDoAllReceiver: security processing failed",
				ex);
		}

		SOAPPart sPart = (org.apache.axis.SOAPPart) sm.getSOAPPart();
		
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		XMLUtils.outputDOM(doc, os, true);
		String osStr = os.toString();
		if (doDebug) {
			log.debug(osStr);
		}
		sPart.setCurrentMessage(osStr, SOAPPart.FORM_STRING);

		/*		
		try {
			AxisUtil.updateSOAPMessage(doc, sm);
			
		} catch (Exception ex) {
			throw new AxisFault(
				"WSDoAllReceiver: cannot update processed message",
				ex);
		}
		*/
		Vector resultActions = wsResult.getActions();
		int size = actions.size();
		if (size != resultActions.size()) {
			throw new AxisFault("WSDoAllReceiver: security processing failed (actions number mismatch)");
		}
		for (int i = 0; i < size; i++) {
			if (((Integer) actions.get(i)).intValue()
				!= ((Integer) resultActions.get(i)).intValue()) {
				throw new AxisFault("WSDoAllReceiver: security processing failed (actions mismatch)");
			}
		}
		Vector results = null;
		if ((results = (Vector) mc.getProperty(WSDoAllConstants.RECV_RESULTS))
			== null) {
			results = new Vector();
		}
		WSDoAllReceiverResult rResult =
			new WSDoAllReceiverResult(
				actor,
				resultActions,
				wsResult.getPrincipals());
		results.add(rResult);
		mc.setProperty(WSDoAllConstants.RECV_RESULTS, results);
		if (doDebug) {
			log.debug("WSDoAllReceiver: exit invoke()");
		}
	} 
	
	/**
	 * Hook to allow subclasses to load their Signature Crypto however they see fit.
	 */
	protected Crypto loadSignatureCrypto() throws AxisFault {
		Crypto crypto = null;
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
			throw new AxisFault("WSDoAllReceiver: Signature: no crypto property file");
		}
		return crypto;
	}
	
	/**
	 * Hook to allow subclasses to load their Decryption Crypto however they see fit.
	 */
	protected Crypto loadDecryptionCrypto() throws AxisFault {
		Crypto crypto = null;
		if ((decPropFile = (String) getOption(WSDoAllConstants.DEC_PROP_FILE))
			== null) {
			decPropFile =
				(String) msgContext.getProperty(WSDoAllConstants.DEC_PROP_FILE);
		}
		if (decPropFile != null) {
			if ((crypto = (Crypto) cryptos.get(decPropFile)) == null) {
				crypto = CryptoFactory.getInstance(decPropFile);
				cryptos.put(decPropFile, crypto);
			}
		} else if ((crypto = sigCrypto) == null) {
			throw new AxisFault("WSDoAllReceiver: Encryption: no crypto property file");
		}
		return crypto;
	}
	
	private void decodeSignatureParameter() throws AxisFault {
		sigCrypto = loadSignatureCrypto();
		/* There are currently no other signature parameters that need to be handled 
		 * here, but we call the load crypto hook rather than just changing the visibility
		 * of this method to maintain parity with WSDoAllSender.
		 */
	}
	
	/*
	 * Set and check the decryption specific parameters, if necessary
	 * take over signatur crypto instance.
	 */ 

	private void decodeDecryptionParameter() throws AxisFault {
		decCrypto = loadDecryptionCrypto();
		/* There are currently no other decryption parameters that need to be handled 
		 * here, but we call the load crypto hook rather than just changing the visibility
		 * of this method to maintain parity with WSDoAllSender.
		 */
	}

	/**
	 * Get the password callback class and get an instance
	 * <p/>
	 */
	private CallbackHandler getPasswordCB() throws AxisFault {

		String callback = null;
		CallbackHandler cbHandler = null;
		if ((callback = (String) getOption(WSDoAllConstants.PW_CALLBACK_CLASS))
			== null) {
			callback =
				(String) msgContext.getProperty(
					WSDoAllConstants.PW_CALLBACK_CLASS);
		}
		if (callback != null) {
			Class cbClass = null;
			try {
				cbClass = java.lang.Class.forName(callback);
			} catch (ClassNotFoundException e) {
				throw new AxisFault(
					"WSDoAllReceiver: cannot load password callback class: "
						+ callback,
					e);
			}
			try {
				cbHandler = (CallbackHandler) cbClass.newInstance();
			} catch (java.lang.Exception e) {
				throw new AxisFault(
					"WSDoAllReceiver: cannot create instance of password callback: "
						+ callback,
					e);
			}
		} else {
			cbHandler =
				(CallbackHandler) msgContext.getProperty(
					WSDoAllConstants.PW_CALLBACK_REF);
			if (cbHandler == null) {
				throw new AxisFault("WSDoAllReceiver: no reference in callback property");
			}
		}
		return cbHandler;
	}

}
