/*
 * Created on Aug 13, 2004
 *
 * To change the template for this generated file go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
package secconv.scenarios;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * @author Dimuthu
 *
 * To change the template for this generated type comment go to
 * Window&gt;Preferences&gt;Java&gt;Code Generation&gt;Code and Comments
 */
public class PackageTests extends TestCase{
	
	public PackageTests(String name) {
			super(name);
		}

		public static Test suite() {
			TestSuite suite = new TestSuite();
		  	suite.addTestSuite(TestSecConvScen1.class);
			return suite;
		}

		/**
		 * Main method
		 * <p/>
		 * 
		 * @param args command line args
		 */
		public static void main(String[] args) {
			junit.textui.TestRunner.run(suite());
		}

}
