/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package wssec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;

/**
 * Test package for WS-Security tests
 */
public class PackageTests extends TestCase {

    public PackageTests(String name) {
        super(name);
    }

    public static Test suite() {
        TestSuite suite = new TestSuite();
        suite.addTestSuite(TestWSSecurityNew.class);
        suite.addTestSuite(TestWSSecurityNew2.class);
        suite.addTestSuite(TestWSSecurityNew3.class);
//        suite.addTestSuite(TestWSSecurity4.class);
        suite.addTestSuite(TestWSSecurityNew5.class);
        suite.addTestSuite(TestWSSecurityNew6.class);
        suite.addTestSuite(TestWSSecurityNew7.class);
        suite.addTestSuite(TestWSSecurityNew8.class);
        suite.addTestSuite(TestWSSecurityNew9.class);
        suite.addTestSuite(TestWSSecurityNew10.class);
        suite.addTestSuite(TestWSSecurityNew11.class);
        suite.addTestSuite(TestWSSecurityNew12.class);
        suite.addTestSuite(TestWSSecurityNew13.class);
        suite.addTestSuite(TestWSSecurityNew14.class);
        suite.addTestSuite(TestWSSecurityNewSOAP12.class);
        // suite.addTestSuite(TestWSSecurityHooks.class);
        suite.addTestSuite(TestWSSecurityNewST1.class);
        suite.addTestSuite(TestWSSecurityNewST2.class);
        suite.addTestSuite(TestWSSecurityNewST3.class);
        suite.addTestSuite(TestWSSecurityNewDK.class);
        suite.addTestSuite(TestWSSecurityNewSCT.class);
        suite.addTestSuite(TestWSSecurityX509v1.class);
        suite.addTestSuite(TestWSSecurityUserProcessor.class);
        suite.addTestSuite(TestWSSecurityFaultCodes.class);
        suite.addTestSuite(TestWSSecurityUTDK.class);
        suite.addTestSuite(TestWSSecurityDataRef.class);
        suite.addTestSuite(TestWSSecurityDataRef1.class);
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
