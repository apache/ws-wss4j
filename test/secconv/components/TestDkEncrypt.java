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
//import org.apache.axis.encoding.Callback;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.axis.utils.XMLUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.axis.security.conversation.ConvHandlerConstants;
import org.apache.ws.axis.security.util.AxisUtil;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.conversation.ConvEngineResult;
import org.apache.ws.security.conversation.ConversationEngine;
import org.apache.ws.security.conversation.ConversationManager;
import org.apache.ws.security.conversation.ConversationUtil;
import org.apache.ws.security.conversation.DerivedKeyCallbackHandler;
import org.apache.ws.security.conversation.DerivedKeyTokenAdder;
import org.apache.ws.security.conversation.message.info.DerivedKeyInfo;
import org.apache.ws.security.conversation.message.info.SecurityContextInfo;
import org.apache.ws.security.conversation.message.token.SecurityContextToken;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * @author Dimuthu Leelarathne. (muthulee@yahoo.com)
 *
 */
public class TestDkEncrypt extends TestCase{
	/*TODO:: Fix the bug and remove the dktoken from DkTokenInfo
	 * Effectng changes : ConversationManger, ConversationClientHandler, ConversationServerHandler.
	 * 
	 */

    private static Log log = LogFactory.getLog(TestDkEncrypt.class);

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
    public TestDkEncrypt(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestDkEncrypt.class);
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
    public void testPerformDkEncrypt() throws Exception {

        SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();
        SOAPEnvelope envelope = null;

        //Get the message as document
        log.info("Before Derived Key Encryption");
        Document doc = unsignedEnvelope.getAsDocument();

        /* Step 1 :: Create Security Header.
         * Step 2 :: Add SCT to it.
         * Step 3 :: Add DerivedKeyToken to the security header.
         * Step 4 :: Create an instance of the ConversationManager.
         * Step 5 :: Perform encryption using the DerivedKeys
         */
        Element securityHeader =
            WSSecurityUtil.findWsseSecurityHeaderBlock(
                WSSConfig.getDefaultWSConfig(),
                doc,
                doc.getDocumentElement(),
                true);
        WSSecurityUtil.appendChildElement(
            doc,
            securityHeader,
            (new SecurityContextToken(doc, uuid)).getElement());

        ConversationManager manager = new ConversationManager();

		DerivedKeyInfo dkInfo =
					manager.createDerivedKeyToken(doc, uuid, dkcbHandler, null, 24);
		
		
		SecurityTokenReference secTokRef = dkInfo.getSecTokRef2DkToken();
		
		//manager.performDK_ENCR(ConversationUtil.generateIdentifier(uuid, dkInfo.getId()), "", true, doc, secTokRef, dkcbHandler);
	    manager.performDK_ENCR(ConversationUtil.generateIdentifier(uuid, dkInfo.getId()), "", true, doc, secTokRef, dkcbHandler, null, "http://www.w3.org/2001/04/xmlenc#tripledes-cbc");
	    
	    manager.addDkToken(doc, dkInfo);
	    
        /*
         * convert the resulting document into a message first. The toSOAPMessage()
         * mehtod performs the necessary c14n call to properly set up the signed
         * document and convert it into a SOAP message. After that we extract it
         * as a document again for further processing.
         */

        Message signedMsg = (Message) AxisUtil.toSOAPMessage(doc);

        XMLUtils.PrettyElementToWriter(
            signedMsg.getSOAPEnvelope().getAsDOM(),
            new PrintWriter(System.out));
        verifyDkSign(doc);
    }

    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param doc 
     * @throws Exception Thrown when there is a problem in verification
     */
    private void verifyDkSign(Document doc)
        throws Exception {
       log.info("Before verifying the derived key signature");
	   ConversationEngine engine = new ConversationEngine(config);
	   Vector results = engine.processSecConvHeader(doc, "", dkcbHandler,null);
	
    }

}
