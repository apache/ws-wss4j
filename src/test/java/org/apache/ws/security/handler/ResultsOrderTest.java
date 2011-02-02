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

package org.apache.ws.security.handler;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;

import org.apache.ws.security.common.CustomHandler;
import org.apache.ws.security.message.token.Timestamp;


/**
 * This is a test for WSS-147. A "checkReceiverResultsAnyOrder" method is added to WSHandler
 * which applications can use if they want.
 */
public class ResultsOrderTest extends org.junit.Assert {

    /**
     */
    @org.junit.Test
    public void 
    testOrder() throws Exception {
        CustomHandler handler = new CustomHandler();
        
        java.util.List<WSSecurityEngineResult> results = new java.util.ArrayList<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.UT, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.TS, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN, (Timestamp)null)
        );
        
        java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(new Integer(WSConstants.UT));
        actions.add(new Integer(WSConstants.TS));
        actions.add(new Integer(WSConstants.SIGN));
        
        assertTrue (handler.checkResults(results, actions));
        assertTrue (handler.checkResultsAnyOrder(results, actions));
    }

    /**
     */
    @org.junit.Test
    public void 
    testReverseOrder() throws Exception {
        CustomHandler handler = new CustomHandler();
        
        java.util.List<WSSecurityEngineResult> results = new java.util.ArrayList<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.TS, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.UT, (Timestamp)null)
        );
        
        java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(new Integer(WSConstants.UT));
        actions.add(new Integer(WSConstants.TS));
        actions.add(new Integer(WSConstants.SIGN));
        
        assertFalse (handler.checkResults(results, actions));
        assertTrue (handler.checkResultsAnyOrder(results, actions));
        assertTrue (results.size() == 4 && actions.size() == 3);
    }
    
    /**
     */
    @org.junit.Test
    public void 
    testMixedOrder() throws Exception {
        CustomHandler handler = new CustomHandler();
        
        java.util.List<WSSecurityEngineResult> results = 
            new java.util.ArrayList<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.TS, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.UT, (Timestamp)null)
        );
        
        java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(new Integer(WSConstants.UT));
        actions.add(new Integer(WSConstants.TS));
        actions.add(new Integer(WSConstants.SIGN));
        
        assertFalse (handler.checkResults(results, actions));
        assertTrue (handler.checkResultsAnyOrder(results, actions));
        assertFalse (actions.isEmpty());
    }
    
    /**
     */
    @org.junit.Test
    public void 
    testMixedOrder2() throws Exception {
        CustomHandler handler = new CustomHandler();
        
        java.util.List<WSSecurityEngineResult> results = 
            new java.util.ArrayList<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.TS, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.UT, (Timestamp)null)
        );
        
        java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(new Integer(WSConstants.SIGN));
        actions.add(new Integer(WSConstants.UT));
        actions.add(new Integer(WSConstants.TS));
        
        assertFalse (handler.checkResults(results, actions));
        assertTrue (handler.checkResultsAnyOrder(results, actions));
    }
    
    /**
     */
    @org.junit.Test
    public void 
    testMissingResult() throws Exception {
        CustomHandler handler = new CustomHandler();
        
        java.util.List<WSSecurityEngineResult> results = 
            new java.util.ArrayList<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.UT, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.TS, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC, (Timestamp)null)
        );
        
        java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(new Integer(WSConstants.TS));
        actions.add(new Integer(WSConstants.UT));
        actions.add(new Integer(WSConstants.SIGN));
        
        assertFalse (handler.checkResults(results, actions));
        assertFalse (handler.checkResultsAnyOrder(results, actions));
    }
    
    /**
     */
    @org.junit.Test
    public void 
    testMissingAction() throws Exception {
        CustomHandler handler = new CustomHandler();
        
        java.util.List<WSSecurityEngineResult> results = 
            new java.util.ArrayList<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.UT, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.TS, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC, (Timestamp)null)
        );
        
        java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(new Integer(WSConstants.TS));
        actions.add(new Integer(WSConstants.UT));
        
        assertFalse (handler.checkResults(results, actions));
        assertFalse (handler.checkResultsAnyOrder(results, actions));
    }
    
    /**
     */
    @org.junit.Test
    public void 
    testNoResult() throws Exception {
        CustomHandler handler = new CustomHandler();
        
        java.util.List<WSSecurityEngineResult> results = 
            new java.util.ArrayList<WSSecurityEngineResult>();
        
        java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(new Integer(WSConstants.TS));
        
        assertFalse (handler.checkResults(results, actions));
        assertFalse (handler.checkResultsAnyOrder(results, actions));
    }
    
    /**
     */
    @org.junit.Test
    public void 
    testNoAction() throws Exception {
        CustomHandler handler = new CustomHandler();
        
        java.util.List<WSSecurityEngineResult> results = 
            new java.util.ArrayList<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.TS, (Timestamp)null)
        );
        
        java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        
        assertFalse (handler.checkResults(results, actions));
        assertFalse (handler.checkResultsAnyOrder(results, actions));
    }
    
    /**
     */
    @org.junit.Test
    public void 
    testMultipleIdenticalResults() throws Exception {
        CustomHandler handler = new CustomHandler();
        
        java.util.List<WSSecurityEngineResult> results = 
            new java.util.ArrayList<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.ENCR, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.UT, (Timestamp)null)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.ENCR, (Timestamp)null)
        );
        
        java.util.List<Integer> actions = new java.util.ArrayList<Integer>();
        actions.add(new Integer(WSConstants.ENCR));
        actions.add(new Integer(WSConstants.UT));
        actions.add(new Integer(WSConstants.UT));
        
        assertFalse (handler.checkResults(results, actions));
        assertFalse (handler.checkResultsAnyOrder(results, actions));
    }
    
}
