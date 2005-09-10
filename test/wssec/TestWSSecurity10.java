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
import org.apache.axis.utils.XMLUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.message.WSEncryptBody;
import org.apache.ws.security.message.WSSAddUsernameToken;
import org.apache.ws.security.message.token.Reference;
import org.apache.ws.security.message.token.SecurityTokenReference;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;

/**
 * TestCase10 for testing HMAC_SHA1 in wss4j.
 * Based on TestCase9.
 *
 * The objective of this TestCase is to test the HMAC_SHA1 signature.
 *
 *  @author Dimuthu Leelarathne. (muthulee@yahoo.com)
 */
public class TestWSSecurity10 extends TestCase implements CallbackHandler {
    private static Log log = LogFactory.getLog(TestWSSecurity10.class);

    static final String soapMsg =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"
            + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
            + "   <soapenv:Body>"
            + "      <ns1:testMethod xmlns:ns1=\"http://axis/service/security/test10/LogTestService10\"></ns1:testMethod>"
            + "   </soapenv:Body>"
            + "</soapenv:Envelope>";

    static final WSSecurityEngine secEngine = new WSSecurityEngine();
    static final Crypto crypto = CryptoFactory.getInstance();
    MessageContext msgContext;
    Message message;

    private byte[] sharedSecret = "SriLankaSriLankaSriLanka".getBytes();

    /**
     * TestWSSecurity constructor
     * <p/>
     *
     * @param name name of the test
     */
    public TestWSSecurity10(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     *
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurity10.class);
    }

    /**
     * Main method
     * <p/>
     *
     * @param args command line args
     */
    //     public static void main(String[] args) {
    //         junit.textui.TestRunner.run(suite());
    //     }

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

    /**
     * Test that encrypts and signs a WS-Security envelope, then performs
     * verification and decryption.
     * <p/>
     *
     * @throws Exception Thrown when there is any problem in signing, encryption,
     *                   decryption, or verification
     */
    public void testEMBED_SECURITY_TOKEN_REF() throws Exception {

        SOAPEnvelope unsignedEnvelope = message.getSOAPEnvelope();
        SOAPEnvelope envelope = null;
        WSEncryptBody wsEncrypt = new WSEncryptBody();

        //Get the message as document
        log.info("Before Encryption....");
        Document doc = unsignedEnvelope.getAsDocument();

        /* Step 1 :: Add a UserNameToken.
         * Step 2 :: Add an Id to it.
         * Step 3 :: Create a Reference to the UserNameToken.
         * Step 4 :: Setting necessary parameters in WSEncryptBody.
         * Step 5 :: Encrypt using the using the password of UserNameToken.
         */

        //Step 1
        String username = "Dimthu";
        String password = "Sri Lanka Sri Lanka UOM ";
        byte[] key = password.getBytes();

        WSSAddUsernameToken builder = new WSSAddUsernameToken("", false);
        builder.setPasswordType(WSConstants.PASSWORD_TEXT);
        builder.build(doc, username, password);

        //Step 2
        // I should add wsu:Id here but I am not adding it since
        Element usrEle =
            (Element) (doc
                .getElementsByTagNameNS(WSConstants.WSSE_NS, "UsernameToken")
                .item(0));
        String idValue = "1234";
        usrEle.setAttribute("Id", idValue);

        //Step 3 ::
        Reference ref = new Reference(doc);
        ref.setURI("#" + idValue);
        ref.setValueType("UsernameToken");
        SecurityTokenReference secRef =
            new SecurityTokenReference(doc);
        secRef.setReference(ref);

        // adding the namespace
        WSSecurityUtil.setNamespace(
            secRef.getElement(),
            WSConstants.WSSE_NS,
            WSConstants.WSSE_PREFIX);

        //Step 4 ::
        wsEncrypt.setKeyIdentifierType(WSConstants.EMBED_SECURITY_TOKEN_REF);
        wsEncrypt.setSecurityTokenReference(secRef);
        wsEncrypt.setKey(key);

        //Step 4 :: Encrypting using the key.
        Document encDoc = wsEncrypt.build(doc, crypto);

        /*
         * convert the resulting document into a message first. The toSOAPMessage()
         * mehtod performs the necessary c14n call to properly set up the signed
         * document and convert it into a SOAP message. After that we extract it
         * as a document again for further processing.
         */

        Message signedMsg = (Message) SOAPUtil.toSOAPMessage(encDoc);

        XMLUtils.PrettyElementToWriter(signedMsg.getSOAPEnvelope().getAsDOM(), new PrintWriter(System.out));
        log.info("Encryption Done\n");
    //    verifyEMBED_SECURITY_TOKEN_REF(signedMsg.getSOAPEnvelope().getAsDocument());
    }

    /**
     * Verifies the soap envelope
     * <p/>
     *
     * @param doc
     * @throws Exception Thrown when there is a problem in verification
     */
    private void verifyEMBED_SECURITY_TOKEN_REF(Document doc)
        throws Exception {
        secEngine.processSecurityHeader(doc, "", this, null);
        log.info("Success ......");
    }

    /* (non-Javadoc)
     * @see javax.security.auth.callback.CallbackHandler#handle(javax.security.auth.callback.Callback[])
     */
    public void handle(Callback[] callbacks)
        throws IOException, UnsupportedCallbackException {
        for (int i = 0; i < callbacks.length; i++) {
            if (callbacks[i] instanceof WSPasswordCallback) {
                WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
                if (pc.getUsage() == WSPasswordCallback.USERNAME_TOKEN) {
                    pc.setPassword("Sri Lanka Sri Lanka UOM ");
                } else if (pc.getUsage() == WSPasswordCallback.DECRYPT) {
                    pc.setKey("Sri Lanka Sri Lanka UOM ".getBytes());

                }
            } else {
                throw new UnsupportedCallbackException(
                    callbacks[i],
                    "Unrecognized Callback");
            }
        }
    }

    public static void main(String[] args) throws Exception {
        TestWSSecurity10 tst10 = new TestWSSecurity10("TestWSSecurity10");
        tst10.setUp();
        tst10.testEMBED_SECURITY_TOKEN_REF();

    }

}
