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

package wssec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.utils.XMLUtils;
import org.apache.axis.client.AxisClient;
import org.apache.axis.configuration.NullProvider;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.axis.security.util.AxisUtil;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.message.WSSAddUsernameToken;
import org.apache.ws.security.message.WSSignEnvelope;

import org.apache.xml.security.signature.XMLSignature;

import org.w3c.dom.Document;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;


/**
 * WS-Security Test Case
 * <p/>
 * 
 * @author Werner Dittmann (Wern.erDittmann@siemens.com)
 */
public class TestWSSecurity13 extends TestCase implements CallbackHandler {
    private static Log log = LogFactory.getLog(TestWSSecurity13.class);
    static final String NS = "http://www.w3.org/2000/09/xmldsig#";
    static final String soapMsg = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" + "<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" + "<SOAP-ENV:Body>" + "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" + "<value xmlns=\"\">15</value>" + "</add>" + "</SOAP-ENV:Body>\r\n       \r\n" + "</SOAP-ENV:Envelope>";
    static final WSSecurityEngine secEngine = new WSSecurityEngine();
    MessageContext msgContext;
    SOAPEnvelope unsignedEnvelope;

    /**
     * TestWSSecurity constructor
     * <p/>
     * 
     * @param name name of the test
     */
    public TestWSSecurity13(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurity13.class);
    }

    /**
     * Main method
     * <p/>
     * 
     * @param args command line args
     */
    public static void main(String[] args) {
        junit.textui.TestRunner.run(suite());
    }

    /**
     * Setup method
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is a problem in setup
     */
    protected void setUp() throws Exception {
        AxisClient tmpEngine = new AxisClient(new NullProvider());
        msgContext = new MessageContext(tmpEngine);
        unsignedEnvelope = getSOAPEnvelope();
    }

    /**
     * Constructs a soap envelope
     * <p/>
     * 
     * @return soap envelope
     * @throws java.lang.Exception if there is any problem constructing the soap envelope
     */
    protected SOAPEnvelope getSOAPEnvelope() throws Exception {
        InputStream in = new ByteArrayInputStream(soapMsg.getBytes());
        Message msg = new Message(in);
        msg.setMessageContext(msgContext);
        return msg.getSOAPEnvelope();
    }

 
    /**
     * Test the specific signing mehtod that use UsernameToken values
     * <p/>
     * 
     * @throws java.lang.Exception Thrown when there is any problem in signing or verification
     */
    public void testUsernameTokenSigning() throws Exception {
        SOAPEnvelope envelope = null;
        Document doc = unsignedEnvelope.getAsDocument();

        WSSAddUsernameToken builder = new WSSAddUsernameToken();
        builder.setPasswordType(WSConstants.PASSWORD_TEXT);
        builder.preSetUsernameToken(doc, "wernerd", "verySecret");
        builder.addCreated(doc);
        builder.addNonce(doc);
        
        WSSignEnvelope sign = new WSSignEnvelope(null, true);
        sign.setUsernameToken(builder);
        sign.setKeyIdentifierType(WSConstants.UT_SIGNING);
        sign.setSignatureAlgorithm(XMLSignature.ALGO_ID_MAC_HMAC_SHA1);
        log.info("Before signing....");
        sign.build(doc, null);
        log.info("Before adding UsernameToken PW Text....");
        Document signedDoc = builder.build(doc, "wernerd", "verySecret");
        Message signedMsg = (Message) AxisUtil.toSOAPMessage(signedDoc);
        if (log.isDebugEnabled()) {
            log.debug("Message with UserNameToken PW Text:");
            XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        }
        signedDoc = signedMsg.getSOAPEnvelope().getAsDocument();
        log.info("After adding UsernameToken PW Text....");
        verify(signedDoc);
    }
    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param env soap envelope
     * @throws java.lang.Exception Thrown when there is a problem in verification
     */
    private void verify(Document doc) throws Exception {
        log.info("Before verifying UsernameToken....");
        secEngine.processSecurityHeader(doc, null, this, null);
        log.info("After verifying UsernameToken....");
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
                pc.setPassword("verySecret");
            } else {
                throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
            }
        }
    }
}
