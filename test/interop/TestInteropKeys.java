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
        Crypto c = CryptoFactory.getInstance("wsstest1.properties");
        X509Certificate[] certs = c.getCertificates("7706c71b0628d6ecc85ea1e8ad62be60_a8272f6f-2c94-436e-aa71-d8d2be4647f6");
        assertTrue(certs != null);
        assertTrue(certs[0] != null);
        PrivateKey privKey = c.getPrivateKey("7706c71b0628d6ecc85ea1e8ad62be60_a8272f6f-2c94-436e-aa71-d8d2be4647f6","interop");
        assertTrue(privKey != null);
    }

    public void testInteropKeys2() throws Exception {
        Crypto c = CryptoFactory.getInstance("wsstest2.properties");
        X509Certificate[] certs = c.getCertificates("86ab6c4828bcde6983d81b2b59ff426c_a8272f6f-2c94-436e-aa71-d8d2be4647f6");
        assertTrue(certs != null);
        assertTrue(certs[0] != null);
        PrivateKey privKey = c.getPrivateKey("86ab6c4828bcde6983d81b2b59ff426c_a8272f6f-2c94-436e-aa71-d8d2be4647f6","interop");
        assertTrue(privKey != null);
    }
}
