/*
 * Created on Aug 13, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package secconv.scenarios;


import secconv.scenarios.ping.WSConvScenario1;
import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Test package for WS-Security tests
 */
public class TestSecConvScen1 extends TestCase {
	/**
		 * TestScenario1 constructor
		 * <p/>
		 * 
		 * @param name name of the test
		 */
		public TestSecConvScen1(String name) {
			super(name);
		}

		/**
		 * JUnit suite
		 * <p/>
		 * 
		 * @return a junit test suite
		 */
		public static Test suite() {
			return new TestSuite(TestSecConvScen1.class);
		}

		/**
		 * Main method
		 * <p/>
		 * 
		 * @param args command line args
		 */
		public static void main(String[] args) throws Exception {
			WSConvScenario1.main(args);
		}

		public void testWSSecConvScen1() throws Exception {
			WSConvScenario1.main(new String[]{"-lhttp://localhost:8080/axis/services/WSConvScenario1"});
		}
	
	
}
