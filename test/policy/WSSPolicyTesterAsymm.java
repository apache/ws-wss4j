/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package policy;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Vector;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.client.AxisClient;
import org.apache.axis.configuration.NullProvider;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.axis.utils.XMLUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.SOAPConstants;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecTimestamp;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.policy.Constants;
import org.apache.ws.security.policy.WSS4JPolicyBuilder;
import org.apache.ws.security.policy.WSS4JPolicyData;
import org.apache.ws.security.policy.WSS4JPolicyToken;
import org.apache.ws.security.policy.WSSPolicyException;
import org.apache.ws.security.policy.model.RootPolicyEngineData;
import org.apache.ws.security.policy.parser.WSSPolicyProcessor;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import wssec.SOAPUtil;

public class WSSPolicyTesterAsymm extends TestCase implements CallbackHandler {
	private static Log log = LogFactory.getLog(WSSPolicyTesterAsymm.class);

	static final String soapMsg = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
			+ "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
			+ "   <soapenv:Body>"
			+ "      <ns1:testMethod xmlns:ns1=\"uri:LogTestService2\"></ns1:testMethod>"
			+ "   </soapenv:Body>" + "</soapenv:Envelope>";

	static final WSSecurityEngine secEngine = new WSSecurityEngine();

	static final Crypto crypto = CryptoFactory.getInstance();

	static final Crypto cryptoSKI = CryptoFactory
			.getInstance("cryptoSKI.properties");

	MessageContext msgContext;

	Message message;

	/**
	 * Policy Tester constructor.
	 * 
	 * @param name
	 *            name of the test
	 */
	public WSSPolicyTesterAsymm(String name) {
		super(name);
	}

	/**
	 * JUnit suite <p/>
	 * 
	 * @return a junit test suite
	 */
	public static Test suite() {
		return new TestSuite(WSSPolicyTesterAsymm.class);
	}

	/**
	 * Main method
	 * 
	 * @param args
	 *            command line args
	 */
	public static void main(String[] args) {
		junit.textui.TestRunner.run(suite());
	}

	/**
	 * Setup method.
	 * 
	 * Initializes an Axis 1 environment to process SOAP messages
	 * 
	 * @throws Exception
	 *             Thrown when there is a problem in setup
	 */
	protected void setUp() throws Exception {
		AxisClient tmpEngine = new AxisClient(new NullProvider());
		msgContext = new MessageContext(tmpEngine);
		message = getSOAPMessage();
	}

	/**
	 * Constructs a soap envelope.
	 * 
	 * @return A SOAP envelope
	 * @throws Exception
	 *             if there is any problem constructing the soap envelope
	 */
	protected Message getSOAPMessage() throws Exception {
		InputStream in = new ByteArrayInputStream(soapMsg.getBytes());
		Message msg = new Message(in);
		msg.setMessageContext(msgContext);
		return msg;
	}

	public void testerAsymm() {
		try {
			WSSPolicyProcessor processor = new WSSPolicyProcessor();
			if (!processor.setup()) {
				return;
			}
			String[] files = new String[2];
			files[0] = "test/policy/SecurityPolicyBindingsAsymmTest.xml";
			files[1] = "test/policy/SecurityPolicyMsgTest.xml";
			processor.go(files);

			RootPolicyEngineData rootPolicyEngineData = (RootPolicyEngineData) processor.secProcessorContext
					.popPolicyEngineData();
			assertNotNull("RootPolicyEngineData missing", rootPolicyEngineData);

			ArrayList peds = rootPolicyEngineData.getTopLevelPEDs();
			log.debug("Number of top level PolicyEngineData: " + peds.size());
			WSS4JPolicyData wpd = WSS4JPolicyBuilder.build(peds);
			createMessageAsymm(wpd);

		} catch (NoSuchMethodException e) {
			e.printStackTrace();
			fail(e.getMessage());
		} catch (WSSPolicyException e) {
			e.printStackTrace();
			fail(e.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			fail(e.getMessage());
		}
	}

	private void createMessageAsymm(WSS4JPolicyData wpd) throws Exception {
		log.info("Before create Message assym....");

		SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();

		/*
		 * First get the SOAP envelope as document, then create a security
		 * header and insert into the document (Envelope)
		 */
		Document doc = unsignedEnvelope.getAsDocument();
		SOAPConstants soapConstants = WSSecurityUtil.getSOAPConstants(doc
				.getDocumentElement());

		WSSecHeader secHeader = new WSSecHeader();
		secHeader.insertSecurityHeader(doc);

		Vector sigParts = new Vector();
		Vector encPartsInternal = new Vector();
		Vector encPartsExternal = new Vector();

		/*
		 * Check is a timestamp is required. If yes create one and add its Id to
		 * signed parts. According to WSP a timestamp must be signed
		 */
		WSSecTimestamp timestamp = null;
		if (wpd.isIncludeTimestamp()) {
			timestamp = new WSSecTimestamp();
			timestamp.prepare(doc);
			sigParts.add(new WSEncryptionPart(timestamp.getId()));
		}

		/*
		 * Check for a recipient token. If one is avaliable use it as token to
		 * encrypt data to the recipient. This is according to WSP
		 * specification. Most of the data is extracted from the
		 * WSS4JPolicyData, only the user info (name/alias of the certificate in
		 * the keystore) must be provided by some other means.
		 */
		WSSecEncrypt recEncrypt = null;
		WSS4JPolicyToken recToken = null;
		if ((recToken = wpd.getRecipientToken()) != null) {
			recEncrypt = new WSSecEncrypt();
			recEncrypt.setUserInfo("wss4jcert");
			recEncrypt.setKeyIdentifierType(recToken.getKeyIdentifier());
			recEncrypt.setSymmetricEncAlgorithm(recToken.getEncAlgorithm());
			recEncrypt.setKeyEnc(recToken.getEncTransportAlgorithm());
			recEncrypt.prepare(doc, cryptoSKI);
		}

		/*
		 * Check for an initiator token. If one is avaliable use it as token to
		 * sign data. This is according to WSP specification. Most of the data
		 * is extracted from the WSS4JPolicyData, only the user info (name/alias
		 * of the certificate in the keystore) must be provided by some other
		 * means.
		 * 
		 * If SignatureProtection is enabled add the signature to the encrypted
		 * parts vector. In any case the signature must be in the internal
		 * ReferenceList (this list is a child of the EncryptedKey element).
		 * 
		 * If TokenProtection is enabled add an appropriate signature reference.
		 * 
		 * TODO Check / enable for STRTransform
		 */
		WSSecSignature iniSignature = null;
		WSS4JPolicyToken iniToken = null;
		if ((iniToken = wpd.getInitiatorToken()) != null) {
			iniSignature = new WSSecSignature();
			iniSignature.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e",
					"security");
			iniSignature.setKeyIdentifierType(iniToken.getKeyIdentifier());
			iniSignature.setSignatureAlgorithm(iniToken.getSigAlgorithm());
			iniSignature.prepare(doc, crypto, secHeader);
			if (wpd.isSignatureProtection()) {
				encPartsInternal.add(new WSEncryptionPart(iniSignature.getId(),
						"Element"));
			}
			if (wpd.isTokenProtection()) {
				sigParts.add(new WSEncryptionPart("Token", null, null));
			}
		}

		Element body = WSSecurityUtil.findBodyElement(doc, soapConstants);
		if (body == null) {
			System.out
					.println("No SOAP Body found - illegal message structure. Processing terminated");
			return;
		}
		WSEncryptionPart bodyPart = new WSEncryptionPart("Body", soapConstants
				.getEnvelopeURI(), "Content");

		/*
		 * Check the protection order. If Encrypt before signing then first take
		 * all parts and elements to encrypt and encrypt them. Take their ids
		 * after encryption and put them to the parts to be signed.
		 * 
		 */
		Element externRefList = null;
		if (Constants.ENCRYPT_BEFORE_SIGNING.equals(wpd.getProtectionOrder())) {
			/*
			 * Process Body: it sign and encrypt: first encrypt the body, insert
			 * the body to the parts to be signed.
			 * 
			 * If just to be signed: add the plain Body to the parts to be
			 * signed
			 */
			if (wpd.isSignBody()) {
				if (wpd.isEncryptBody()) {
					Vector parts = new Vector();
					parts.add(bodyPart);
					externRefList = recEncrypt.encryptForExternalRef(
							externRefList, parts);
					sigParts.add(bodyPart);
				} else {
					sigParts.add(bodyPart);
				}
			}
			/*
			 * Here we need to handle signed/encrypted parts:
			 * 
			 * Get all parts that need to be encrypted _and_ signed, encrypt
			 * them, get ids of thier encrypted data elements and add these ids
			 * to the parts to be signed
			 * 
			 * Then encrypt the remaining parts that don't need to be signed.
			 * 
			 * Then add the remaining parts that don't nedd to be encrypted to
			 * the parts to be signed.
			 * 
			 * Similar handling for signed/encrypted elements (compare XPath
			 * strings?)
			 * 
			 * After all elements are encrypted put the external refernce list
			 * to the security header. is at the bottom of the security header)
			 */

			recEncrypt.addExternalRefElement(externRefList, secHeader);

			/*
			 * Now handle the supporting tokens - according to OASIS WSP
			 * supporting tokens are not part of a Binding assertion but a top
			 * level assertion similar to Wss11 or SignedParts. If supporting
			 * tokens are available their BST elements have to be added later
			 * (probably prepended to the initiator token - see below)
			 */

			/*
			 * Now add the various elements to the header. We do a strict layout
			 * here.
			 * 
			 */
			/*
			 * Prepend Signature to the supporting tokens that sign the primary
			 * signature
			 */
			iniSignature.prependToHeader(secHeader);
			/*
			 * This prepends a possible initiator token to the security header
			 */
			iniSignature.prependBSTElementToHeader(secHeader);
			/*
			 * Here prepend BST elements of supporting tokens
			 * (EndorsingSupportTokens), then prepend supporting token that do
			 * not sign the primary signature but are signed by the primary
			 * signature. Take care of the TokenProtection protery!?
			 */

			/*
			 * Add the encrypted key element and then the associated BST element
			 * recipient token)
			 */
			recEncrypt.prependToHeader(secHeader);
			recEncrypt.prependBSTElementToHeader(secHeader);

			/*
			 * Now we are ready to per Signature processing.
			 * 
			 * First the primary Signature then supporting tokens (Signatures)
			 * that sign the primary Signature.
			 */
			timestamp.prependToHeader(secHeader);

			iniSignature.addReferencesToSign(sigParts, secHeader);
			iniSignature.computeSignature();
			Element internRef = recEncrypt.encryptForInternalRef(null,
					encPartsInternal);
			recEncrypt.addInternalRefElement(internRef);
		} else {
			System.out.println("SignBeforeEncrypt needs to be implemented");
		}

		log.info("After creating Message asymm....");

		/*
		 * convert the resulting document into a message first. The
		 * toSOAPMessage() method performs the necessary c14n call to properly
		 * set up the signed document and convert it into a SOAP message. Check
		 * that the contents can't be read (cheching if we can find a specific
		 * substring). After that we extract it as a document again for further
		 * processing.
		 */

		Message encryptedMsg = (Message) SOAPUtil.toSOAPMessage(doc);
		if (log.isDebugEnabled()) {
			log.debug("Processed message");
			XMLUtils.PrettyElementToWriter(encryptedMsg.getSOAPEnvelope()
					.getAsDOM(), new PrintWriter(System.out));
		}
		String encryptedString = encryptedMsg.getSOAPPartAsString();
		assertTrue(encryptedString.indexOf("LogTestService2") == -1 ? true
		: false);
		// encryptedDoc = encryptedMsg.getSOAPEnvelope().getAsDocument();
		verify(doc);
	}

	/**
	 * Verifies the soap envelope <p/>
	 * 
	 * @param envelope
	 * @throws Exception
	 *             Thrown when there is a problem in verification
	 */
	private void verify(Document doc) throws Exception {
		secEngine.processSecurityHeader(doc, null, this, crypto, cryptoSKI);
		SOAPUtil.updateSOAPMessage(doc, message);
		String decryptedString = message.getSOAPPartAsString();
		assertTrue(decryptedString.indexOf("LogTestService2") > 0 ? true
				: false);
	}

	public void handle(Callback[] callbacks) throws IOException,
			UnsupportedCallbackException {
		for (int i = 0; i < callbacks.length; i++) {
			if (callbacks[i] instanceof WSPasswordCallback) {
				WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
				/*
				 * here call a function/method to lookup the password for the
				 * given identifier (e.g. a user name or keystore alias) e.g.:
				 * pc.setPassword(passStore.getPassword(pc.getIdentfifier)) for
				 * Testing we supply a fixed name here.
				 */
				pc.setPassword("security");
			} else {
				throw new UnsupportedCallbackException(callbacks[i],
						"Unrecognized Callback");
			}
		}
	}

}
