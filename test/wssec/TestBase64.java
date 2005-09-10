/*
 * Created on 09.09.2005
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package wssec;

import java.util.Arrays;
import junit.framework.TestCase;
import org.apache.ws.security.util.Base64;
import org.apache.ws.security.WSSecurityException;

public class TestBase64 extends TestCase {

    private byte[] dataBinary = null;
    
    /*
     * The following String is the value "This is a test\n" encoded
     * in Base64
     */
    private String thisIsATestEnc = "VGhpcyBpcyBhIHRlc3QK";
    private String thisIsATestClear = "This is a test\n";
    private String thisIsATestEnc4group = "VGhp\ncyBp\ncyBh\nIHRl\nc3QK";
    
    private String encodedBinary;
    
    public static void main(String[] args) {
        junit.textui.TestRunner.run(TestBase64.class);
    }

    public TestBase64(String arg0) {
        super(arg0);
    }

    protected void setUp() throws Exception {
        super.setUp();
        dataBinary = new byte[256];
        for (int i = 0; i < 256; i++) {
            dataBinary[i] = (byte)i;
        }
    }

    /*
     * Class under test for String encode(byte[])
     */
    public void testEncodebyteArray() {
        String isATestEnc = Base64.encode(thisIsATestClear.getBytes());
        assertEquals(isATestEnc, thisIsATestEnc);

        encodedBinary = Base64.encode(dataBinary);
        byte[] outBinary = null;
        try {
            outBinary = Base64.decode(encodedBinary);
        } catch (WSSecurityException ex) {

        }
        assertTrue(Arrays.equals(outBinary, dataBinary));
    }

    /*
     * Class under test for String encode(byte[], int, boolean)
     */
    public void testEncodebyteArrayintboolean() {
        String isATestEnc = Base64.encode(thisIsATestClear.getBytes(), 4, false);
        assertEquals(isATestEnc, thisIsATestEnc);

        isATestEnc = Base64.encode(thisIsATestClear.getBytes(), 76, false);
        assertEquals(isATestEnc, thisIsATestEnc);

        isATestEnc = Base64.encode(thisIsATestClear.getBytes(), 4, true);
        assertEquals(isATestEnc, thisIsATestEnc4group);

        isATestEnc = Base64.encode(thisIsATestClear.getBytes(), 76, true);
        assertEquals(isATestEnc, thisIsATestEnc);
        
        encodedBinary = Base64.encode(dataBinary, 4, false);
        byte[] outBinary = null;
        try {
            outBinary = Base64.decode(encodedBinary);
        } catch (WSSecurityException ex) {
        }
        assertTrue(Arrays.equals(outBinary, dataBinary));   
        
        encodedBinary = Base64.encode(dataBinary, 76, false);
        outBinary = null;
        try {
            outBinary = Base64.decode(encodedBinary);
        } catch (WSSecurityException ex) {
        }
        assertTrue(Arrays.equals(outBinary, dataBinary));        
        
        encodedBinary = Base64.encode(dataBinary, 4, true);
        outBinary = null;
        try {
            outBinary = Base64.decode(encodedBinary);
        } catch (WSSecurityException ex) {
        }
        assertTrue(Arrays.equals(outBinary, dataBinary));    
        
        encodedBinary = Base64.encode(dataBinary, 76, true);
        outBinary = null;
        try {
            outBinary = Base64.decode(encodedBinary);
        } catch (WSSecurityException ex) {
        }
        assertTrue(Arrays.equals(outBinary, dataBinary));        
    }

    public void testDecode() {
        byte[] out = null;
        byte[] outBinary = null;
        try {
            out = Base64.decode(thisIsATestEnc);
        } catch (WSSecurityException ex) {

        }
        assertEquals(new String(out), thisIsATestClear);
    }

}
