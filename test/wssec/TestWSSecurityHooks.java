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
import org.apache.axis.AxisFault;
import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.client.AxisClient;
import org.apache.axis.configuration.NullProvider;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.axis.security.WSDoAllReceiver;
import org.apache.ws.axis.security.WSDoAllSender;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.components.crypto.BouncyCastle;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.handler.WSHandlerConstants;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;

/**
 * <dl>
 * <dt><b>Title: </b><dd>WS Security Hooks Test Case</dd>
 * <p>
 * <dt><b>Description: </b><dd>Test Case to verify the load...Crypto hooks work properly. 
 * Also tests the setKeyStore method of Merlin </dd>
 * </dl>
 * 
 * @see org.apache.ws.security.components.crypto.Merlin#setKeyStore
 * @see org.apache.ws.axis.security.WSDoAllReceiver#loadSignatureCrypto
 * @see org.apache.ws.axis.security.WSDoAllReceiver#loadDecryptionCrypto
 * @see org.apache.ws.axis.security.WSDoAllSender#loadSignatureCrypto
 * @see org.apache.ws.axis.security.WSDoAllSender#loadEncryptionCrypto
 * 
 * @author <a href="mailto:jasone@greenrivercomputing.com>Jason Essington</a>
 * @version $Revision$
 */
public class TestWSSecurityHooks extends TestCase implements CallbackHandler
{
   private static final String soapMessage = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+
         "<soapenv:Envelope " +
               "xmlns:soapenv=\"http://www.w3.org/2003/05/soap-envelope\" " +
               "xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" " +
               "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">" +
            "<soapenv:Header>" +
            "</soapenv:Header>" +
            "<soapenv:Body>" +
               "<ns1:echo " +
                     "xmlns:ns1=\"http://org.apache.wss4j.wssec/TESTCASE\" " +
                     "soapenv:encodingStyle=\"http://www.w3.org/2003/05/soap-encoding\">" +
                  "<inStr xsi:type=\"xsd:string\">ECHO ECHo ECho Echo echo echO ecHO eCHO ECHO</inStr>" +
               "</ns1:echo>" +
            "</soapenv:Body>" +
         "</soapenv:Envelope>";

   KeyStore keystore = null;
   MessageContext mc = null;
   
   public TestWSSecurityHooks(String name) {
      super(name);
   }
   
   protected void setUp() throws Exception {
      AxisClient tmpEngine = new AxisClient(new NullProvider());
      mc = new MessageContext(tmpEngine);
      mc.setCurrentMessage(getSOAPMessage(soapMessage));
      mc.setProperty(WSHandlerConstants.PW_CALLBACK_REF, this);
      keystore = loadKeyStore();
   }

   public static Test suite() {
      return new TestSuite(TestWSSecurityHooks.class);
   }

   public static void main(String[] args) {
      junit.textui.TestRunner.run(suite());
   }
   
   //
   //
   // Tests
   //
   //
   
   public void testCryptoHook() throws Exception {
      assertNotNull("", keystore);
      Crypto crypto = new TestCryptoImpl(keystore);
      assertNotNull(PrivilegedAccessor.getValue(crypto, "keystore"));
   }
   public void testSenderLoadSignatureHook() throws Exception {
      TestSenderImpl sender = new TestSenderImpl();
      // we have to coerce a value into this field or we'll get a bunch of NPEs when calling decodeSignatureParameter
      PrivilegedAccessor.setValue(sender, "msgContext", mc);
      PrivilegedAccessor.invokeMethod(sender, "decodeSignatureParameter", new Object[] {});
      assertNotNull(PrivilegedAccessor.getValue(sender, "sigCrypto"));
   }
   public void testSenderLoadEncryptionHook() throws Exception {
      TestSenderImpl sender = new TestSenderImpl();
      // decodeEcnryptionParameter() is rather insistant on having a user (anyUser)
      sender.setOption(WSHandlerConstants.ENCRYPTION_USER, "anyUserWillDo");
      // we have to coerce a value into this field or we'll get a bunch of NPEs when calling decodeSignatureParameter
      PrivilegedAccessor.setValue(sender, "msgContext", mc);
      PrivilegedAccessor.invokeMethod(sender, "decodeEncryptionParameter", new Object[] {});
      assertNotNull(PrivilegedAccessor.getValue(sender, "encCrypto"));
   }
   public void testReceiverLoadSignatureHook() throws Exception {
      TestReceiverImpl receiver = new TestReceiverImpl();
      PrivilegedAccessor.invokeMethod(receiver, "decodeSignatureParameter", new Object[] {});
      assertNotNull(PrivilegedAccessor.getValue(receiver, "sigCrypto"));
   }
   public void testReceiverLoadDecryptionHook() throws Exception {
      TestReceiverImpl receiver = new TestReceiverImpl();
      PrivilegedAccessor.invokeMethod(receiver, "decodeDecryptionParameter", new Object[] {});
      assertNotNull(PrivilegedAccessor.getValue(receiver, "decCrypto"));
   }
   
   public void testRoundTripWithHooks() throws Exception {
      // Setup our sender to Encrypt and Sign a soap message
      TestSenderImpl sender = new TestSenderImpl();
      sender.setOption(WSHandlerConstants.ACTOR, "test");
      sender.setOption(WSHandlerConstants.USER, "16c73ab6-b892-458f-abf5-2f875f74882e");
      sender.setOption(WSHandlerConstants.ACTION, "Encrypt Signature");
      sender.setOption(WSHandlerConstants.SIG_KEY_ID, "DirectReference");
      sender.setOption(WSHandlerConstants.ENC_KEY_ID, "X509KeyIdentifier");
      sender.invoke(mc);
      
      // Make sure that at least SOMETHING happened
      String soapPart = mc.getCurrentMessage().getSOAPPartAsString();
      assertNotSame("The message has not been Encrypted or Signed", soapPart, soapMessage);
      
      // Prepare the message context for the response
      Message message = getSOAPMessage(soapPart);
      mc.setPastPivot(true);
      mc.setCurrentMessage(message);
      
      // Setup our receiver for the decryption / signature validation
      TestReceiverImpl receiver = new TestReceiverImpl();
      receiver.setOption(WSHandlerConstants.ACTOR, "test");
      receiver.setOption(WSHandlerConstants.ACTION, "Encrypt Signature");
      receiver.invoke(mc);
   }
   
   //
   //
   // Test Utility Classes
   //
   //
      
   /**
    * This is a subclass of Merlin that uses the setKeyStore() method rather than the 
    * load(is) method to set the private keystore field.
    */
   public class TestCryptoImpl extends BouncyCastle {
      TestCryptoImpl(KeyStore ks) throws Exception {
         super(null);
         assertNotNull(ks);
         setKeyStore(ks);
      }
   }
   
   /**
    * Subclass of WSDoAllReceiver that creates the Crypto's directly
    */
   public class TestReceiverImpl extends WSDoAllReceiver
   {
      protected Crypto loadDecryptionCrypto() throws AxisFault {
         try {
            return new TestCryptoImpl(keystore);
         } catch(Exception e) {
            fail("Failed to create a Crypto instance.");
            throw new AxisFault("Failed to create a Crypto instance.", e);
         }
      }
      protected Crypto loadSignatureCrypto() throws AxisFault {
         try {
            return new TestCryptoImpl(keystore);
         } catch(Exception e) {
            fail("Failed to create a Crypto instance.");
            throw new AxisFault("Failed to create a Crypto instance.", e);
         }
      }
   }
   
   /**
    * Subclass of WSDoAllSender that creates the Crypto's directly
    */
   public class TestSenderImpl extends WSDoAllSender
   {
      protected Crypto loadEncryptionCrypto() throws AxisFault {
         try {
            return new TestCryptoImpl(keystore);
         } catch(Exception e) {
            fail("Failed to create a Crypto instance.");
            throw new AxisFault("Failed to create a Crypto instance.", e);
         }
      }
      protected Crypto loadSignatureCrypto() throws AxisFault {
         try {
            return new TestCryptoImpl(keystore);
         } catch(Exception e) {
            fail("Failed to create a Crypto instance.");
            throw new AxisFault("Failed to create a Crypto instance.", e);
         }
      }
   }
   
   
   //
   //
   // test utility methods
   //
   //
   
   protected Message getSOAPMessage(String message) throws Exception {
      InputStream in = new ByteArrayInputStream(message.getBytes());
      Message msg = new Message(in);
      msg.setMessageContext(mc);
      return msg;
   }
   
   protected KeyStore loadKeyStore() throws Exception {
      KeyStore ks = null;
      FileInputStream is = null;
      is = new FileInputStream("keys/x509.PFX.MSFT");
      ks = KeyStore.getInstance("pkcs12");
      String password = "security";
      ks.load(is, password.toCharArray());
      return ks;
   }
   
   public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
      for (int i = 0; i < callbacks.length; i++) {
         if (callbacks[i] instanceof WSPasswordCallback) {
            WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];
            pc.setPassword("security");
            
         } else {
            throw new UnsupportedCallbackException(callbacks[i], "Unrecognized Callback");
         }
      }
   }
   
}
