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
        suite.addTestSuite(TestWSSecurity.class);
        suite.addTestSuite(TestWSSecurity2.class);
        suite.addTestSuite(TestWSSecurity3.class);
//        suite.addTestSuite(TestWSSecurity4.class);
        suite.addTestSuite(TestWSSecurity5.class);
        suite.addTestSuite(TestWSSecurity6.class);
        suite.addTestSuite(TestWSSecurity7.class);
        suite.addTestSuite(TestWSSecurity8.class);
        suite.addTestSuite(TestWSSecurity9.class);
        suite.addTestSuite(TestWSSecurity11.class);
        suite.addTestSuite(TestWSSecurity12.class);
        suite.addTestSuite(TestWSSecurity13.class);
        suite.addTestSuite(TestWSSecuritySOAP12.class);
        // suite.addTestSuite(TestWSSecurityHooks.class);
        suite.addTestSuite(TestWSSecurityST1.class);
        suite.addTestSuite(TestWSSecurityST2.class);
        suite.addTestSuite(TestWSSecurityST3.class);
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
