package interop;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.ws.axis.oasis.ping.PingPort;
import org.apache.ws.axis.oasis.ping.PingServiceLocator;
import org.apache.ws.security.handler.WSS4JHandler;

import javax.xml.namespace.QName;
import javax.xml.rpc.handler.HandlerInfo;
import javax.xml.rpc.handler.HandlerRegistry;
import javax.xml.rpc.holders.StringHolder;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Created by IntelliJ IDEA.
 * User: srida01
 * Date: Aug 12, 2004
 * Time: 9:44:32 PM
 * To change this template use File | Settings | File Templates.
 */
public class TestJAXRPCHandler extends TestCase {
    /**
     * TestScenario1 constructor
     * <p/>
     *
     * @param name name of the test
     */
    public TestJAXRPCHandler(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     *
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestJAXRPCHandler.class);
    }

    public void testScenario3() throws Exception {
        PingServiceLocator service = new PingServiceLocator();

        List handlerChain = new ArrayList();
        Map config = new HashMap();
        config.put("deployment", "client");
        config.put("action", "Signature Encrypt Timestamp");
        config.put("user", "alice");
        config.put("passwordCallbackClass", "org.apache.ws.axis.oasis.PWCallback1");
        config.put("signatureKeyIdentifier", "DirectReference");
        config.put("signaturePropFile", "wsstest.properties");
        config.put("encryptionKeyIdentifier", "SKIKeyIdentifier");
        config.put("encryptionUser", "bob");
        handlerChain.add(new HandlerInfo(WSS4JHandler.class, config, null));

        HandlerRegistry registry = service.getHandlerRegistry();
        registry.setHandlerChain(new QName("Ping3"), handlerChain);

        service.getHandlerRegistry().getHandlerChain(new QName("http://xmlsoap.org/Ping", "ticketType"));

        PingPort port = (PingPort) service.getPing3(new URL("http://localhost:8080/axis/services/Ping3"));
        StringHolder text =
                new StringHolder("WSS4J - Scenario3 @ [" + new java.util.Date(System.currentTimeMillis()) + "]");
        port.ping(new org.apache.ws.axis.oasis.ping.TicketType("WSS4J3"), text);
        System.out.println(text.value);
    }
}
