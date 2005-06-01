
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
package secconv.components;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Vector;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.parsers.DocumentBuilderFactory;

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
import org.apache.ws.axis.security.conversation.ConvHandlerConstants;
import org.apache.ws.axis.security.util.AxisUtil;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.conversation.ConversationEngine;
import org.apache.ws.security.conversation.DerivedKeyCallbackHandler;
import org.apache.ws.security.conversation.message.info.SecurityContextInfo;
import org.apache.ws.security.conversation.message.token.SecurityContextToken;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.trust.message.token.RequestSecurityTokenResponse;
import org.apache.ws.security.trust.message.token.RequestedProofToken;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author Dimuthu Leelarathne. (muthulee@yahoo.com)
 *
 */
public class TestRSTR extends TestCase implements CallbackHandler{
	/*TODO:: Fix the bug and remove the dktoken from DkTokenInfo
	 * Effectng changes : ConversationManger, ConversationClientHandler, ConversationServerHandler.
	 * 
	 */

	private static Log log = LogFactory.getLog(TestRSTR.class);

	static final String soapMsg =
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
			+ "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
			+ "   <soapenv:Body>"
			+ "      <ns1:testMethod xmlns:ns1=\"http://axis/service/security/test10/LogTestService10\"></ns1:testMethod>"
			+ "   </soapenv:Body>"
			+ "</soapenv:Envelope>";

	MessageContext msgContext;
	Message message;
	String uuid;
	DerivedKeyCallbackHandler dkcbHandler;
	HashMap config;
	Crypto crypto = CryptoFactory.getInstance();
	
	static{
	org.apache.xml.security.Init.init();
	}
	//sharedSecret = "SriLankaSriLankaSriLanka".getBytes();

	/**
	 * TestWSSecurity constructor
	 * <p/>
	 * 
	 * @param name name of the test
	 */
	public TestRSTR(String name) {
		super(name);
	}

	/**
	 * JUnit suite
	 * <p/>
	 * 
	 * @return a junit test suite
	 */
	public static Test suite() {
		return new TestSuite(TestRSTR.class);
	}

	/**
	 * Main method
	 * <p/>
	 * 
	 * @param args command line args
	 */
	//	 public static void main(String[] args) {
	//		 junit.textui.TestRunner.run(suite());
	//	 }

	/**
	 * Setup method
	 * <p/>
	 * 
	 * @throws Exception Thrown when there is a problem in setup
	 */
	protected void setUp() throws Exception {
		AxisClient tmpEngine = new AxisClient(new NullProvider());
		msgContext = new MessageContext(tmpEngine);
		message = getSOAPMessage();

		//Now we have to set up the dkcbHandler
		dkcbHandler = new DerivedKeyCallbackHandler();
		SecurityContextToken secConTok = this.getSCT();
		uuid = secConTok.getIdentifier();
		SecurityContextInfo info = new SecurityContextInfo(secConTok,"DumbShredSecret".getBytes(),1);
		dkcbHandler.addSecurtiyContext(uuid, info);
		dkcbHandler.setDerivedKeyLength(uuid, 24);
		dkcbHandler.setLabelForSession(
			uuid,
			"WSSecureConversationWSSecureConversation");
        
		//setting up the configurator.
		config = new HashMap();
		config.put(ConvHandlerConstants.KEY_FREQ,
					   new Integer(1));
					   
		this.config.put(ConvHandlerConstants.USE_FIXED_KEYLEN, new Boolean(true));
		this.config.put(ConvHandlerConstants.KEY_LEGNTH, new Long(24));		
		this.config.put(WSHandlerConstants.DEC_PROP_FILE,"crypto.properties");
        
	}

	/**
	 * Constructs a soap envelope
	 * <p/>
	 * 
	 * @return soap envelope
	 * @throws Exception if there is any problem constructing the soap envelope
	 */
	protected Message getSOAPMessage() throws Exception {
		InputStream in = new ByteArrayInputStream(soapMsg.getBytes());
		Message msg = new Message(in);
		msg.setMessageContext(msgContext);
		return msg;
	}

	protected SecurityContextToken getSCT() throws Exception {
		DocumentBuilderFactory buidler = DocumentBuilderFactory.newInstance();
		Document nulldoc = buidler.newDocumentBuilder().newDocument();
		SecurityContextToken sctTok = new SecurityContextToken(nulldoc);
		return sctTok;
	}

	/**
	 * Test that encrypts and signs a WS-Security envelope, then performs
	 * verification and decryption.
	 * <p/>
	 * 
	 * @throws Exception Thrown when there is any problem in signing, encryption,
	 *                   decryption, or verification
	 */
	public void testPerformRSTR() throws Exception {

		SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();
		SOAPEnvelope envelope = null;

		//Get the message as document
		log.info("Before RequestedSecurityTokenResponse....");
		Document doc = unsignedEnvelope.getAsDocument();

		/* Step 1 :: Create Security Header.
		 * Step 2 :: Add RSTR - a RequestedSecurityTokenRespose to it.
		 * Step 3 :: Create a RequestedProofToken, and encrypt the soap message with it.
		 */
		Element securityHeader =
			WSSecurityUtil.findWsseSecurityHeaderBlock(
				WSSConfig.getDefaultWSConfig(),
				doc,
				doc.getDocumentElement(),
				true);
	
	
		RequestSecurityTokenResponse stRes = new RequestSecurityTokenResponse(doc, true);
  	    uuid = stRes.getRequestedSecurityToken().getSct().getIdentifier();
   	    stRes.build(doc);
		
		//Now encrypting with the base token
		RequestedProofToken reqProof = stRes.getRequestedProofToken();
        
	    reqProof.doEncryptProof(doc, this.crypto, "16c73ab6-b892-458f-abf5-2f875f74882e");
			    
		/*
		 * convert the resulting document into a message first. The toSOAPMessage()
		 * mehtod performs the necessary c14n call to properly set up the signed
		 * document and convert it into a SOAP message. After that we extract it
		 * as a document again for further processing.
		 */

		Message rstrMsg = (Message) AxisUtil.toSOAPMessage(doc);

		XMLUtils.PrettyElementToWriter(
			rstrMsg.getSOAPEnvelope().getAsDOM(),
			new PrintWriter(System.out));
		verifyRSTR(doc);
	}

	/**
	 * Verifies the soap envelope
	 * <p/>
	 * 
	 * @param doc 
	 * @throws Exception Thrown when there is a problem in verification
	 */
	private void verifyRSTR(Document doc)
		throws Exception {
	   log.info("Before verifying RSTR............");
	   ConversationEngine engine = new ConversationEngine(config);
	   Vector results = engine.processSecConvHeader(doc, "", dkcbHandler, "secconv.components.PWCallback");
	}
	
	public void handle(Callback[] callbacks)
				   throws IOException, UnsupportedCallbackException {
			   for (int i = 0; i < callbacks.length; i++) {
				   if (callbacks[i] instanceof WSPasswordCallback) {
					   WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
					   /*
						* here call a function/method to lookup the password for
						* the given identifier (e.g. a user name or keystore alias)
						* e.g.: pc.setPassword(passStore.getPassword(pc.getIdentfifier))
						* for Testing we supply a fixed name here.
						*/
					   pc.setPassword("secret");
				   } else {
					   throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
				   }
			   }
   }




}
