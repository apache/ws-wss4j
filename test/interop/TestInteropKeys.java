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
        X509Certificate[] certs = c.getCertificates("alice");
        assertTrue(certs != null);
        assertTrue(certs[0] != null);
        PrivateKey privKey = c.getPrivateKey("alice","password");
        assertTrue(privKey != null);
    }

    public void testInteropKeys2() throws Exception {
        Crypto c = CryptoFactory.getInstance("wsstest.properties");
        X509Certificate[] certs = c.getCertificates("bob");
        assertTrue(certs != null);
        assertTrue(certs[0] != null);
        PrivateKey privKey = c.getPrivateKey("bob","password");
        assertTrue(privKey != null);
    }
}
