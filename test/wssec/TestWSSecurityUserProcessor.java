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
import org.apache.axis.client.AxisClient;
import org.apache.axis.utils.XMLUtils;
import org.apache.axis.configuration.NullProvider;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.handler.WSHandler;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecHeader;
import org.w3c.dom.Document;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.PrintWriter;


/**
 * WS-Security Test Case
 * <p/>
 */
public class TestWSSecurityUserProcessor extends TestCase {
    private static Log log = LogFactory.getLog(TestWSSecurityUserProcessor.class);
    static final String NS = "http://www.w3.org/2000/09/xmldsig#";
    static final String soapMsg = 
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" 
        + "<SOAP-ENV:Envelope "
        +   "xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\" "
        +   "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" "
        +   "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" 
        +   "<SOAP-ENV:Body>" 
        +       "<add xmlns=\"http://ws.apache.org/counter/counter_port_type\">" 
        +           "<value xmlns=\"\">15</value>" 
        +       "</add>" 
        +   "</SOAP-ENV:Body>" 
        + "</SOAP-ENV:Envelope>";

    static final Crypto crypto = CryptoFactory.getInstance();

    MessageContext msgContext;
    SOAPEnvelope unsignedEnvelope;

    /**
     * TestWSSecurity constructor
     * <p/>
     * 
     * @param name name of the test
     */
    public TestWSSecurityUserProcessor(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurityUserProcessor.class);
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
     * Test to see that a custom processor configured through a
     * WSSConfig instance is called
     */
    public void 
    testCustomUserProcessor() throws Exception {
        WSSecSignature builder = new WSSecSignature();
        builder.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        builder.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
        log.info("Before Signing IS....");
        Document doc = unsignedEnvelope.getAsDocument();
        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);
        Document signedDoc = builder.build(doc, crypto, secHeader);

        /*
         * convert the resulting document into a message first. The toSOAPMessage()
         * mehtod performs the necessary c14n call to properly set up the signed
         * document and convert it into a SOAP message. After that we extract it
         * as a document again for further processing.
         */

        if (log.isDebugEnabled()) {
            log.debug("Signed message with IssuerSerial key identifier:");
            XMLUtils.PrettyElementToWriter(signedDoc.getDocumentElement(), new PrintWriter(System.out));
        }
        Message signedMsg = (Message) SOAPUtil.toSOAPMessage(signedDoc);
        if (log.isDebugEnabled()) {
            log.debug("Signed message with IssuerSerial key identifier(1):");
            XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        }
        signedDoc = signedMsg.getSOAPEnvelope().getAsDocument();
        log.info("After Signing IS....");
        //
        // Check to make sure we can install/replace and use our own processor
        //
        WSSConfig cfg = WSSConfig.getNewInstance();
        String p = "wssec.MyProcessor";
        cfg.setProcessor(
            WSSecurityEngine.SIGNATURE,
            p
        );
        final WSSecurityEngine engine = new WSSecurityEngine();
        engine.setWssConfig(cfg);
        final java.util.List results = 
            engine.processSecurityHeader(doc, null, null, crypto);
        boolean found = false;
        for (final java.util.Iterator pos = results.iterator();  pos.hasNext(); ) {
            final java.util.Map result = (java.util.Map) pos.next();
            Object obj = result.get("foo");
            if (obj != null) {
                if (obj.getClass().getName().equals(p)) {
                    found = true;
                }
            }
        }
        assertTrue("Unable to find result from MyProcessor", found);
    }
    
    /**
     * Test to see that a custom action configured through a
     * WSSConfig instance is called
     */
    public void
    testCustomAction() throws Exception {
        
        final WSSConfig cfg = WSSConfig.getNewInstance();
        final int action = 0xDEADF000;
        cfg.setAction(action, "wssec.MyAction");
        final RequestData reqData = new RequestData();
        reqData.setWssConfig(cfg);
        reqData.setMsgContext(new java.util.TreeMap());
        
        final java.util.Vector actions = new java.util.Vector();
        actions.add(new Integer(action));
        final Document doc = unsignedEnvelope.getAsDocument();
        MyHandler handler = new MyHandler();
        reqData.setMsgContext("bread");
        assertEquals(reqData.getMsgContext(), "bread");
        handler.doit(
            action, 
            doc, 
            reqData, 
            actions
        );
        assertEquals(reqData.getMsgContext(), "crumb");
    }
    
    /**
     * a trivial extension of the WSHandler type
     */
    public static class MyHandler extends WSHandler {
        
        public Object 
        getOption(String key) {
            return null;
        }
        
        public void 
        setProperty(
            Object msgContext, 
            String key, 
            Object value
        ) {
        }

        public Object 
        getProperty(Object ctx, String key) {
            return null;
        }
    
        public void 
        setPassword(Object msgContext, String password) {
        }
        
        public String 
        getPassword(Object msgContext) {
            return null;
        }

        void doit(
            int action, 
            Document doc,
            RequestData reqData, 
            java.util.Vector actions
        ) throws org.apache.ws.security.WSSecurityException {
            doSenderAction(
                action, 
                doc, 
                reqData, 
                actions,
                true
            );
        }
    }
}
