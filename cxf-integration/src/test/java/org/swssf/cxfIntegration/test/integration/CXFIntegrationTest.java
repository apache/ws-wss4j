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

import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.message.Message;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.hello_world_soap_http.Greeter;
import org.apache.hello_world_soap_http.SOAPService;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.apache.ws.security.wss.test.WSS4JCallbackHandlerImpl;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class CXFIntegrationTest {

    private Greeter greeterStream;
    private Greeter greeterWSS4J;

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
            greeterWSS4J = soapService.getSoapPort();
            final Client client = ClientProxy.getClient(greeterWSS4J);
            WSS4JOutInterceptor wss4JOutInterceptor = new WSS4JOutInterceptor();
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ACTION, "Timestamp Signature Encrypt");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.USER, "transmitter");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENCRYPTION_USER, "receiver");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.PW_CALLBACK_CLASS, WSS4JCallbackHandlerImpl.class.getName());
            wss4JOutInterceptor.setProperty(WSHandlerConstants.SIG_PROP_FILE, "transmitter-crypto.properties");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENC_PROP_FILE, "transmitter-crypto.properties");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENC_SYM_ALGO, "http://www.w3.org/2001/04/xmlenc#aes256-cbc");
            client.getOutInterceptors().add(wss4JOutInterceptor);

            WSS4JInInterceptor wss4JInInterceptor = new WSS4JInInterceptor();
            wss4JInInterceptor.setProperty(WSHandlerConstants.ACTION, "Timestamp Signature Encrypt");
            wss4JInInterceptor.setProperty(WSHandlerConstants.PW_CALLBACK_CLASS, WSS4JCallbackHandlerImpl.class.getName());
            wss4JInInterceptor.setProperty(WSHandlerConstants.SIG_PROP_FILE, "transmitter-crypto.properties");
            wss4JInInterceptor.setProperty(WSHandlerConstants.DEC_PROP_FILE, "transmitter-crypto.properties");
            client.getInInterceptors().add(wss4JInInterceptor);

            client.getRequestContext().put(Message.ENDPOINT_ADDRESS, "http://localhost:9001/GreeterServiceWSS4J");
            greeterWSS4J.greetMe("Cold start");
        }
    }

    private long starttime;

    @Test(alwaysRun = true)
    public void startTiming() {
        System.gc();
        System.out.println("startTiming");
        starttime = System.currentTimeMillis();
    }

    @Test(dependsOnMethods = "testCXF", alwaysRun = true)
    public void stopTiming() {
        System.out.println("Streaming: 100 invocations took " + (System.currentTimeMillis() - starttime) + " milliseconds");
        System.out.flush();
        System.gc();
    }

    @Test(invocationCount = 100, threadPoolSize = 10, dependsOnMethods = {"startTiming"})
    public void testCXF() throws Exception {
        String resp = greeterStream.greetMe("Hey Service. It's me, the client. Nice to meet you...");
        //System.out.println(resp);
    }

    private long starttimeWSS4J;

    @Test(alwaysRun = true, dependsOnMethods = {"stopTiming"})
    public void startTimingWSS4J() {
        System.gc();
        System.out.println("startTiming");
        starttimeWSS4J = System.currentTimeMillis();
    }

    @Test(dependsOnMethods = "testCXFWSS4J", alwaysRun = true)
    public void stopTimingWSS4J() {
        System.out.println("DOM: 100 invocations took " + (System.currentTimeMillis() - starttimeWSS4J) + " milliseconds");
        System.out.flush();
        System.gc();
    }

    @Test(invocationCount = 100, threadPoolSize = 10, dependsOnMethods = "startTimingWSS4J")
    public void testCXFWSS4J() throws Exception {
        String resp = greeterWSS4J.greetMe("Hey Service. It's me, the client. Nice to meet you...");
        //System.out.println(resp);
    }
}
