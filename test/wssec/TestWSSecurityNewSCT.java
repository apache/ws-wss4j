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

package wssec;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Hashtable;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import junit.framework.TestCase;

import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.client.AxisClient;
import org.apache.axis.configuration.NullProvider;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.message.WSSecDKEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSecurityContextToken;
import org.w3c.dom.Document;

/**
 * Testcase to test WSSecSecurityContextToken
 * 
 * @see org.apache.ws.security.message.WSSecSecurityContextToken
 * 
 * @author Ruchith Fernando (ruchith.fernando@gmail.com)
 */
public class TestWSSecurityNewSCT extends TestCase implements CallbackHandler {

    static final String soapMsg = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
            + "   <soapenv:Body>"
            + "      <ns1:testMethod xmlns:ns1=\"uri:LogTestService2\"></ns1:testMethod>"
            + "   </soapenv:Body>" + "</soapenv:Envelope>";

    static final WSSecurityEngine secEngine = new WSSecurityEngine();

    static final Crypto crypto = CryptoFactory
            .getInstance("cryptoSKI.properties");

    MessageContext msgContext;

    Message message;

    /**
     * Table of secrets idexd by the sct identifiers
     */
    private Hashtable secrets = new Hashtable();

    /**
     * @param arg0
     */
    public TestWSSecurityNewSCT(String arg0) {
        super(arg0);
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

    public void testBuild() {
        try {
            SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();
            Document doc = unsignedEnvelope.getAsDocument();
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken();
            sctBuilder.build(doc, crypto, secHeader);
            sctBuilder.commit(doc, crypto, secHeader);

            String out = org.apache.ws.security.util.XMLUtils
                    .PrettyDocumentToString(doc);

            assertTrue(
                    "SecurityContextToken missing",
                    out
                            .indexOf(ConversationConstants.SECURITY_CONTEXT_TOKEN_LN) > 0);
            assertTrue("wsc:Identifier missing", out
                    .indexOf(ConversationConstants.IDENTIFIER_LN) > 0);

            // System.out.println(out);

        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    /**
     * Test encryption using a derived key which is based on a secret associated
     * with a security context token
     */
    public void testSCTDKEncryptDecrypt() {
        try {
            SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();
            Document doc = unsignedEnvelope.getAsDocument();
            WSSecHeader secHeader = new WSSecHeader();
            secHeader.insertSecurityHeader(doc);

            WSSecSecurityContextToken sctBuilder = new WSSecSecurityContextToken();
            sctBuilder.build(doc, crypto, secHeader);

            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte[] tempSecret = new byte[16];
            random.nextBytes(tempSecret);

            // Store the secret
            this.secrets.put(sctBuilder.getIdentifier(), tempSecret);

            String tokenId = sctBuilder.getSctId();

            // Derived key encryption
            WSSecDKEncrypt encrBuilder = new WSSecDKEncrypt();
            encrBuilder.setSymmetricEncAlgorithm(WSConstants.AES_128);
            encrBuilder.setExternalKey(tempSecret, tokenId);
            encrBuilder.build(doc, crypto, secHeader);

            sctBuilder.commit(doc, crypto, secHeader);

//            String out = org.apache.ws.security.util.XMLUtils
//                    .PrettyDocumentToString(doc);

//            System.out.println(out);
            
            verify(doc);
        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }
    
    /**
     * Verifies the soap envelope
     * <p/>
     * 
     * @param envelope 
     * @throws Exception Thrown when there is a problem in verification
     */
    private void verify(Document doc) throws Exception {
        secEngine.processSecurityHeader(doc, null, this, crypto);
        SOAPUtil.updateSOAPMessage(doc, message);
        String decryptedString = message.getSOAPPartAsString();
        assertTrue(decryptedString.indexOf("LogTestService2") > 0 ? true : false);
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

    public void handle(Callback[] callbacks) throws IOException,
            UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
                byte[] secret = (byte[]) this.secrets.get(pc.getIdentifer());
                pc.setKey(secret);
            } else {
                throw new UnsupportedCallbackException(callbacks[i],
                        "Unrecognized Callback");
            }
        }
    }

}
