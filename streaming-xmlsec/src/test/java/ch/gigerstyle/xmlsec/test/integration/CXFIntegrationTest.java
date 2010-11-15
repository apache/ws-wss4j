package ch.gigerstyle.xmlsec.test.integration;

import ch.gigerstyle.xmlsec.test.WSS4JCallbackHandlerImpl;
import org.apache.cxf.endpoint.Client;
import org.apache.cxf.frontend.ClientProxy;
import org.apache.cxf.message.Message;
import org.apache.cxf.ws.security.wss4j.WSS4JInInterceptor;
import org.apache.cxf.ws.security.wss4j.WSS4JOutInterceptor;
import org.apache.hello_world_soap_http.Greeter;
import org.apache.hello_world_soap_http.SOAPService;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * User: giger
 * Date: Oct 22, 2010
 * Time: 6:43:43 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
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
            //wss4JOutInterceptor.setProperty(WSHandlerConstants.ACTION, "Timestamp Signature Encrypt");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ACTION, "Encrypt");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.USER, "transmitter");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENCRYPTION_USER, "receiver");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.PW_CALLBACK_CLASS, WSS4JCallbackHandlerImpl.class.getName());
            wss4JOutInterceptor.setProperty(WSHandlerConstants.SIG_PROP_FILE, "integration/transmitter-crypto.properties");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENC_PROP_FILE, "integration/transmitter-crypto.properties");
            client.getOutInterceptors().add(wss4JOutInterceptor);

            WSS4JInInterceptor wss4JInInterceptor = new WSS4JInInterceptor();
            wss4JInInterceptor.setProperty(WSHandlerConstants.ACTION, "Encrypt");
            wss4JInInterceptor.setProperty(WSHandlerConstants.PW_CALLBACK_CLASS, WSS4JCallbackHandlerImpl.class.getName());
            wss4JInInterceptor.setProperty(WSHandlerConstants.SIG_PROP_FILE, "integration/transmitter-crypto.properties");
            wss4JInInterceptor.setProperty(WSHandlerConstants.DEC_PROP_FILE, "integration/transmitter-crypto.properties");
            client.getInInterceptors().add(wss4JInInterceptor);

            greeterStream.greetMe("Cold start");
        }

        {
            SOAPService soapService = new SOAPService(this.getClass().getClassLoader().getResource("integration/helloWorld.wsdl"));
            greeterWSS4J = soapService.getSoapPort();
            final Client client = ClientProxy.getClient(greeterWSS4J);
            WSS4JOutInterceptor wss4JOutInterceptor = new WSS4JOutInterceptor();
            //wss4JOutInterceptor.setProperty(WSHandlerConstants.ACTION, "Timestamp Signature Encrypt");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ACTION, "Encrypt");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.USER, "transmitter");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENCRYPTION_USER, "receiver");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.PW_CALLBACK_CLASS, WSS4JCallbackHandlerImpl.class.getName());
            wss4JOutInterceptor.setProperty(WSHandlerConstants.SIG_PROP_FILE, "integration/transmitter-crypto.properties");
            wss4JOutInterceptor.setProperty(WSHandlerConstants.ENC_PROP_FILE, "integration/transmitter-crypto.properties");
            client.getOutInterceptors().add(wss4JOutInterceptor);

            WSS4JInInterceptor wss4JInInterceptor = new WSS4JInInterceptor();
            wss4JInInterceptor.setProperty(WSHandlerConstants.ACTION, "Encrypt");
            wss4JInInterceptor.setProperty(WSHandlerConstants.PW_CALLBACK_CLASS, WSS4JCallbackHandlerImpl.class.getName());
            wss4JInInterceptor.setProperty(WSHandlerConstants.SIG_PROP_FILE, "integration/transmitter-crypto.properties");
            wss4JInInterceptor.setProperty(WSHandlerConstants.DEC_PROP_FILE, "integration/transmitter-crypto.properties");
            client.getInInterceptors().add(wss4JInInterceptor);

            client.getRequestContext().put(Message.ENDPOINT_ADDRESS, "http://localhost:9001/GreeterServiceWSS4J");
            greeterWSS4J.greetMe("Cold start");
        }
    }

    private long starttime;

    @Test(alwaysRun = true)
    public void startTiming() {
        System.out.println("startTiming");
        starttime = System.currentTimeMillis();
    }

    @Test(dependsOnMethods = "testCXF", alwaysRun = true)
    public void stopTiming() {
        System.out.println("Streaming: 100 invocations took " + (System.currentTimeMillis() - starttime) + " milliseconds");
        System.out.flush();
    }

    @Test(invocationCount = 100, threadPoolSize = 10, dependsOnMethods = {"startTiming", "testCXFWSS4J"})
    //@Test(invocationCount = 1, threadPoolSize = 10)
    public void testCXF() throws Exception {
        String resp = greeterStream.greetMe("Hey Stream Service. It's me, the client. Nice to meet you...");
        //System.out.println(resp);
    }

    private long starttimeWSS4J;

    @Test(alwaysRun = true)
    public void startTimingWSS4J() {
        System.out.println("startTiming");
        starttimeWSS4J = System.currentTimeMillis();
    }

    @Test(dependsOnMethods = "testCXFWSS4J", alwaysRun = true)
    public void stopTimingWSS4J() {
        System.out.println("DOM: 100 invocations took " + (System.currentTimeMillis() - starttimeWSS4J) + " milliseconds");
        System.out.flush();
    }

    @Test(invocationCount = 100, threadPoolSize = 10, dependsOnMethods = "startTimingWSS4J")
    public void testCXFWSS4J() throws Exception {
        String resp = greeterWSS4J.greetMe("Hey DOM Service. It's me, the client. Nice to meet you...");
        //System.out.println(resp);
    }
}
