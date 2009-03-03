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
import org.apache.axis.configuration.NullProvider;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecSignature;
import org.apache.ws.security.message.WSSecHeader;
import org.w3c.dom.Document;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * WS-Security Test Case <p/>
 * 
 * @author Davanum Srinivas (dims@yahoo.com)
 */
public class TestWSSecurityNew6 extends TestCase implements CallbackHandler {
    private static final Log LOG = LogFactory.getLog(TestWSSecurityNew6.class);
    private static final String soapMsg = 
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

    private WSSecurityEngine secEngine = new WSSecurityEngine();
    private Crypto crypto = CryptoFactory.getInstance();
    private MessageContext msgContext;
    private Message message;

    /**
     * TestWSSecurity constructor <p/>
     * 
     * @param name
     *            name of the test
     */
    public TestWSSecurityNew6(String name) {
        super(name);
    }

    /**
     * JUnit suite <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurityNew6.class);
    }

    /**
     * Setup method <p/>
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
     * Constructs a soap envelope <p/>
     * 
     * @return soap envelope
     * @throws Exception
     *             if there is any problem constructing the soap envelope
     */
    protected Message getSOAPMessage() throws Exception {
        InputStream in = new ByteArrayInputStream(soapMsg.getBytes());
        Message msg = new Message(in);
        msg.setMessageContext(msgContext);
        return msg;
    }

    /**
     * Test that encrypts and signs a WS-Security envelope, then performs
     * verification and decryption <p/>
     * 
     * @throws Exception
     *             Thrown when there is any problem in signing, encryption,
     *             decryption, or verification
     */
    public void testEncryptionSigning() throws Exception {
        SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();
        WSSecEncrypt encrypt = new WSSecEncrypt();
        WSSecSignature sign = new WSSecSignature();
        encrypt.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e");
        sign.setUserInfo("16c73ab6-b892-458f-abf5-2f875f74882e", "security");
        LOG.info("Before Encryption....");
        Document doc = unsignedEnvelope.getAsDocument();

        WSSecHeader secHeader = new WSSecHeader();
        secHeader.insertSecurityHeader(doc);

        Document encryptedDoc = encrypt.build(doc, crypto, secHeader);
        Document encryptedSignedDoc = sign.build(encryptedDoc, crypto,
                secHeader);
        LOG.info("After Encryption....");
        verify(encryptedSignedDoc);
    }

    /**
     * Verifies the soap envelope <p/>
     * 
     * @param envelope
     * @throws Exception
     *             Thrown when there is a problem in verification
     */
    private void verify(Document doc) throws Exception {
        secEngine.processSecurityHeader(doc, null, this, crypto);
        if (LOG.isDebugEnabled()) {
            String outputString = 
                org.apache.ws.security.util.XMLUtils.PrettyDocumentToString(doc);
            LOG.debug(outputString);
        }
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
