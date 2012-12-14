/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.swssf.cxfIntegration.test.integration;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.message.Message;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.hello_world_soap_http.Greeter;
import org.apache.hello_world_soap_http.SOAPService;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.xml.security.stax.impl.util.KeyValue;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.xml.stream.XMLInputFactory;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class CXFIntegrationTest {

    private Greeter greeterStream;
    private Greeter greeterDOM;

    static {
        try {
            Field xmlInputFactoryField = StaxUtils.class.getDeclaredField("SAFE_INPUT_FACTORY");
            xmlInputFactoryField.setAccessible(true);
            XMLInputFactory xmlInputFactory = (XMLInputFactory)xmlInputFactoryField.get(null);
            xmlInputFactory.setProperty(XMLInputFactory.IS_COALESCING, Boolean.FALSE);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @BeforeClass()
    public void setUp() {
        ClassPathXmlApplicationContext applicationContext = new ClassPathXmlApplicationContext("integration/test-application-context.xml");
        {
            SOAPService soapService = new SOAPService(this.getClass().getClassLoader().getResource("integration/helloWorld.wsdl"));
            greeterStream = soapService.getSoapPort();
            final Client client = ClientProxy.getClient(greeterStream);
            WSS4JOutInterceptor wss4JOutInterceptor = new WSS4JOutInterceptor();
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ACTION, "Timestamp Signature Encrypt");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.USER, "transmitter");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENCRYPTION_USER, "receiver");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.PW_CALLBACK_CLASS, WSS4JCallbackHandlerImpl.class.getName());
            wss4JOutInterceptor.setProperty(WSHandlerConstants.SIG_PROP_FILE, "transmitter-crypto.properties");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENC_PROP_FILE, "transmitter-crypto.properties");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2001/04/xmlenc#aes256-cbc");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENC_KEY_TRANSPORT, "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
            client.getOutInterceptors().add(wss4JOutInterceptor);

            WSS4JInInterceptor wss4JInInterceptor = new WSS4JInInterceptor();
            wss4JInInterceptor.setProperty(WSHandlerConstants.ACTION, "Timestamp Signature Encrypt");
            wss4JInInterceptor.setProperty(WSHandlerConstants.PW_CALLBACK_CLASS, WSS4JCallbackHandlerImpl.class.getName());
            wss4JInInterceptor.setProperty(WSHandlerConstants.SIG_PROP_FILE, "transmitter-crypto.properties");
            wss4JInInterceptor.setProperty(WSHandlerConstants.DEC_PROP_FILE, "transmitter-crypto.properties");
            client.getInInterceptors().add(wss4JInInterceptor);

            greeterStream.greetMe("Cold start");
        }

        {
            SOAPService soapService = new SOAPService(this.getClass().getClassLoader().getResource("integration/helloWorld.wsdl"));
            greeterDOM = soapService.getSoapPort();
            final Client client = ClientProxy.getClient(greeterDOM);
            WSS4JOutInterceptor wss4JOutInterceptor = new WSS4JOutInterceptor();
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ACTION, "Timestamp Signature Encrypt");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.USER, "transmitter");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENCRYPTION_USER, "receiver");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.PW_CALLBACK_CLASS, WSS4JCallbackHandlerImpl.class.getName());
            wss4JOutInterceptor.setProperty(WSHandlerConstants.SIG_PROP_FILE, "transmitter-crypto.properties");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENC_PROP_FILE, "transmitter-crypto.properties");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2001/04/xmlenc#aes256-cbc");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENC_KEY_TRANSPORT, "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p");
            client.getOutInterceptors().add(wss4JOutInterceptor);

            WSS4JInInterceptor wss4JInInterceptor = new WSS4JInInterceptor();
            wss4JInInterceptor.setProperty(WSHandlerConstants.ACTION, "Timestamp Signature Encrypt");
            wss4JInInterceptor.setProperty(WSHandlerConstants.PW_CALLBACK_CLASS, WSS4JCallbackHandlerImpl.class.getName());
            wss4JInInterceptor.setProperty(WSHandlerConstants.SIG_PROP_FILE, "transmitter-crypto.properties");
            wss4JInInterceptor.setProperty(WSHandlerConstants.DEC_PROP_FILE, "transmitter-crypto.properties");
            client.getInInterceptors().add(wss4JInInterceptor);

            client.getRequestContext().put(Message.ENDPOINT_ADDRESS, "http://localhost:9001/GreeterServiceWSS4J");

            greeterDOM.greetMe("Cold start");
        }
    }

    private static final int invocationCount = 100;
    private ExecutorService executorService = Executors.newFixedThreadPool(10);
    private ExecutorCompletionService executorCompletionService = new ExecutorCompletionService(executorService);
    private List<KeyValue<Integer, Long>> streamingTimes = new ArrayList<KeyValue<Integer, Long>>();
    private List<KeyValue<Integer, Long>> domTimes = new ArrayList<KeyValue<Integer, Long>>();

    @DataProvider
    public Object[][] payload() {
        Object[][] objects = new Object[10][1];
        for (int i = 0; i < objects.length; i++) {
            objects[i][0] = RandomStringUtils.randomAlphanumeric((int)Math.pow((i + 1), 6));
        }
        return objects;
    }

    @SuppressWarnings("unchecked")
    @Test(timeOut = 300000, dataProvider = "payload")
    public void testStreamingPerformance(String payload) throws Exception {

        long startTime = System.currentTimeMillis();

        for (int i = 0; i < invocationCount; i++) {
            executorCompletionService.submit(new Invoker(greeterStream, payload));
        }

        for (int i = 0; i < invocationCount; i++) {
            executorCompletionService.take().get();
        }

        streamingTimes.add(new KeyValue<Integer, Long>(payload.length(), System.currentTimeMillis() - startTime));
    }

    @SuppressWarnings("unchecked")
    @Test(timeOut = 300000, dataProvider = "payload")
    public void testDOMPerformance(String payload) throws Exception {

        long startTime = System.currentTimeMillis();

        for (int i = 0; i < invocationCount; i++) {
            executorCompletionService.submit(new Invoker(greeterDOM, payload));
        }

        for (int i = 0; i < invocationCount; i++) {
            executorCompletionService.take().get();
        }

        domTimes.add(new KeyValue<Integer, Long>(payload.length(), System.currentTimeMillis() - startTime));
    }

    @AfterClass
    public void tearDown() throws Exception {

        System.out.println("Payload size\tStreaming\tDOM");

        for (int i = 0; i < streamingTimes.size(); i++) {
            KeyValue<Integer, Long> streamingValues = streamingTimes.get(i);
            KeyValue<Integer, Long> domValues = domTimes.get(i);

            if (!streamingValues.getKey().equals(domValues.getKey())) {
                throw new Exception("Different payload sizes: Streaming has: " + streamingValues.getKey() + " but DOM has: " + domValues.getKey());
            }
            System.out.println(streamingValues.getKey() + "\t\t" + streamingValues.getValue() + "\t\t" + domValues.getValue());
        }
    }

    class Invoker implements Callable {

        private Greeter greeter;
        private String payload;

        Invoker(Greeter greeter, String payload) {
            this.greeter = greeter;
            this.payload = payload;
        }

        @Override
        public Object call() throws Exception {
            return greeter.greetMe(payload);
        }
    }
}
