package interop;

import junit.framework.TestCase;
import junit.framework.Test;
import junit.framework.TestSuite;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;

import java.security.cert.X509Certificate;
import java.security.PrivateKey;

/**
 * Created by IntelliJ IDEA.
 * User: srida01
 * Date: Mar 15, 2004
 * Time: 10:47:59 AM
 * To change this template use File | Settings | File Templates.
 */
public class TestInteropKeys extends TestCase {
    /**
     * TestScenario1 constructor
     * <p/>
     * 
     * @param name name of the test
     */
    public TestInteropKeys(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestInteropKeys.class);
    }

    public void testInteropKeys1() throws Exception {
        Crypto c = CryptoFactory.getInstance("wsstest.properties");
        X509Certificate[] certs = c.getCertificates("1fb7623be7b2f4831ffc3f3741fa09dd_1e149434-9d3a-4adc-9284-4cfdc595012f");
        assertTrue(certs != null);
        assertTrue(certs[0] != null);
        PrivateKey privKey = c.getPrivateKey("1fb7623be7b2f4831ffc3f3741fa09dd_1e149434-9d3a-4adc-9284-4cfdc595012f","interop");
        assertTrue(privKey != null);
    }

    public void testInteropKeys2() throws Exception {
        Crypto c = CryptoFactory.getInstance("wsstest.properties");
        X509Certificate[] certs = c.getCertificates("c82f74d031dabf9d7546f40ad07c32c0_1e149434-9d3a-4adc-9284-4cfdc595012f");
        assertTrue(certs != null);
        assertTrue(certs[0] != null);
        PrivateKey privKey = c.getPrivateKey("c82f74d031dabf9d7546f40ad07c32c0_1e149434-9d3a-4adc-9284-4cfdc595012f","interop");
        assertTrue(privKey != null);
    }
}
