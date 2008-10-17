package components;

import junit.framework.TestCase;
import junit.framework.Test;
import junit.framework.TestSuite;
import org.apache.ws.security.components.crypto.AbstractCrypto;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;

/**
 * Created by IntelliJ IDEA.
 * User: srida01
 * Date: Apr 12, 2004
 * Time: 10:50:05 AM
 * To change this template use File | Settings | File Templates.
 */
public class TestMerlin extends TestCase {
    /**
     * TestScenario1 constructor
     * <p/>
     * 
     * @param name name of the test
     */
    public TestMerlin(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestMerlin.class);
    }

    public void testCrypto() {
        Crypto crypto = CryptoFactory.getInstance();
        assertTrue(crypto != null);
    }

    public void testAbstractCryptoWithNullProperties() 
        throws Exception {
        Crypto crypto = new NullPropertiesCrypto();
        assertTrue(crypto != null);
    }
    
    /**
     * WSS-102 -- ensure AbstractCrypto will null properties
     * can be instantiated
     */
    private static class NullPropertiesCrypto extends AbstractCrypto {
    
        public NullPropertiesCrypto() 
            throws Exception {
            super((java.util.Properties) null);
        }
    }
}
