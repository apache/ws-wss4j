/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package wssec;

import junit.framework.Test;
import junit.framework.TestCase;
import junit.framework.TestSuite;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;


/**
 * This is a test for WSS-147. A "checkReceiverResultsAnyOrder" method is added to WSHandler
 * which applications can use if they want.
 */
public class TestWSSecurityResultsOrder extends TestCase {

    /**
     * TestWSSecurity constructor
     * <p/>
     * 
     * @param name name of the test
     */
    public TestWSSecurityResultsOrder(String name) {
        super(name);
    }

    /**
     * JUnit suite
     * <p/>
     * 
     * @return a junit test suite
     */
    public static Test suite() {
        return new TestSuite(TestWSSecurityResultsOrder.class);
    }
    
    /**
     */
    public void 
    testOrder() throws Exception {
        MyHandler handler = new MyHandler();
        
        java.util.List<WSSecurityEngineResult> results = new java.util.Vector<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.UT, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.TS, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN, (Object)null)
        );
        
        java.util.List<Integer> actions = new java.util.Vector<Integer>();
        actions.add(new Integer(WSConstants.UT));
        actions.add(new Integer(WSConstants.TS));
        actions.add(new Integer(WSConstants.SIGN));
        
        assertTrue (handler.checkResults(results, actions));
        assertTrue (handler.checkResultsAnyOrder(results, actions));
    }

    /**
     */
    public void 
    testReverseOrder() throws Exception {
        MyHandler handler = new MyHandler();
        
        java.util.List<WSSecurityEngineResult> results = new java.util.Vector<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.TS, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.UT, (Object)null)
        );
        
        java.util.List<Integer> actions = new java.util.Vector<Integer>();
        actions.add(new Integer(WSConstants.UT));
        actions.add(new Integer(WSConstants.TS));
        actions.add(new Integer(WSConstants.SIGN));
        
        assertFalse (handler.checkResults(results, actions));
        assertTrue (handler.checkResultsAnyOrder(results, actions));
        assertTrue (results.size() == 4 && actions.size() == 3);
    }
    
    /**
     */
    public void 
    testMixedOrder() throws Exception {
        MyHandler handler = new MyHandler();
        
        java.util.List<WSSecurityEngineResult> results = 
            new java.util.Vector<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.TS, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.UT, (Object)null)
        );
        
        java.util.List<Integer> actions = new java.util.Vector<Integer>();
        actions.add(new Integer(WSConstants.UT));
        actions.add(new Integer(WSConstants.TS));
        actions.add(new Integer(WSConstants.SIGN));
        
        assertFalse (handler.checkResults(results, actions));
        assertTrue (handler.checkResultsAnyOrder(results, actions));
        assertFalse (actions.isEmpty());
    }
    
    /**
     */
    public void 
    testMixedOrder2() throws Exception {
        MyHandler handler = new MyHandler();
        
        java.util.List<WSSecurityEngineResult> results = 
            new java.util.Vector<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.TS, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.UT, (Object)null)
        );
        
        java.util.List<Integer> actions = new java.util.Vector<Integer>();
        actions.add(new Integer(WSConstants.SIGN));
        actions.add(new Integer(WSConstants.UT));
        actions.add(new Integer(WSConstants.TS));
        
        assertFalse (handler.checkResults(results, actions));
        assertTrue (handler.checkResultsAnyOrder(results, actions));
    }
    
    /**
     */
    public void 
    testMissingResult() throws Exception {
        MyHandler handler = new MyHandler();
        
        java.util.List<WSSecurityEngineResult> results = 
            new java.util.Vector<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.UT, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.TS, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC, (Object)null)
        );
        
        java.util.List<Integer> actions = new java.util.Vector<Integer>();
        actions.add(new Integer(WSConstants.TS));
        actions.add(new Integer(WSConstants.UT));
        actions.add(new Integer(WSConstants.SIGN));
        
        assertFalse (handler.checkResults(results, actions));
        assertFalse (handler.checkResultsAnyOrder(results, actions));
    }
    
    /**
     */
    public void 
    testMissingAction() throws Exception {
        MyHandler handler = new MyHandler();
        
        java.util.List<WSSecurityEngineResult> results = 
            new java.util.Vector<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.UT, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.TS, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC, (Object)null)
        );
        
        java.util.List<Integer> actions = new java.util.Vector<Integer>();
        actions.add(new Integer(WSConstants.TS));
        actions.add(new Integer(WSConstants.UT));
        
        assertFalse (handler.checkResults(results, actions));
        assertFalse (handler.checkResultsAnyOrder(results, actions));
    }
    
    /**
     */
    public void 
    testNoResult() throws Exception {
        MyHandler handler = new MyHandler();
        
        java.util.List<WSSecurityEngineResult> results = 
            new java.util.Vector<WSSecurityEngineResult>();
        
        java.util.List<Integer> actions = new java.util.Vector<Integer>();
        actions.add(new Integer(WSConstants.TS));
        
        assertFalse (handler.checkResults(results, actions));
        assertFalse (handler.checkResultsAnyOrder(results, actions));
    }
    
    /**
     */
    public void 
    testNoAction() throws Exception {
        MyHandler handler = new MyHandler();
        
        java.util.List<WSSecurityEngineResult> results = 
            new java.util.Vector<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.TS, (Object)null)
        );
        
        java.util.List<Integer> actions = new java.util.Vector<Integer>();
        
        assertFalse (handler.checkResults(results, actions));
        assertFalse (handler.checkResultsAnyOrder(results, actions));
    }
    
    /**
     */
    public void 
    testMultipleIdenticalResults() throws Exception {
        MyHandler handler = new MyHandler();
        
        java.util.List<WSSecurityEngineResult> results = 
            new java.util.Vector<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.ENCR, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.UT, (Object)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.ENCR, (Object)null)
        );
        
        java.util.List<Integer> actions = new java.util.Vector<Integer>();
        actions.add(new Integer(WSConstants.ENCR));
        actions.add(new Integer(WSConstants.UT));
        actions.add(new Integer(WSConstants.UT));
        
        assertFalse (handler.checkResults(results, actions));
        assertFalse (handler.checkResultsAnyOrder(results, actions));
    }
    
}
