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

package org.apache.wss4j.dom.handler;

import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.common.CustomHandler;
import org.apache.wss4j.dom.common.SecurityTestUtil;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.junit.Test;


/**
 * This is a test for WSS-147. A "checkReceiverResultsAnyOrder" method is added to WSHandler
 * which applications can use if they want.
 */
public class ResultsOrderTest extends org.junit.Assert {

    @org.junit.AfterClass
    public static void cleanup() throws Exception {
        SecurityTestUtil.cleanup();
    }

    /**
     */
    @Test
    public void
    testOrder() throws Exception {
        CustomHandler handler = new CustomHandler();

        java.util.List<WSSecurityEngineResult> results = new java.util.ArrayList<>();
        results.add(
            new WSSecurityEngineResult(WSConstants.UT)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.TS)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN)
        );

        java.util.List<Integer> actions = new java.util.ArrayList<>();
        actions.add(WSConstants.UT);
        actions.add(WSConstants.TS);
        actions.add(WSConstants.SIGN);

        assertTrue(handler.checkResults(results, actions));
        assertTrue(handler.checkResultsAnyOrder(results, actions));
    }

    /**
     */
    @Test
    public void
    testReverseOrder() throws Exception {
        CustomHandler handler = new CustomHandler();

        java.util.List<WSSecurityEngineResult> results = new java.util.ArrayList<>();
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.TS)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.UT)
        );

        java.util.List<Integer> actions = new java.util.ArrayList<>();
        actions.add(WSConstants.UT);
        actions.add(WSConstants.TS);
        actions.add(WSConstants.SIGN);

        assertFalse(handler.checkResults(results, actions));
        assertTrue(handler.checkResultsAnyOrder(results, actions));
        assertTrue(results.size() == 4 && actions.size() == 3);
    }

    /**
     */
    @Test
    public void
    testMixedOrder() throws Exception {
        CustomHandler handler = new CustomHandler();

        java.util.List<WSSecurityEngineResult> results =
            new java.util.ArrayList<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.TS)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.UT)
        );

        java.util.List<Integer> actions = new java.util.ArrayList<>();
        actions.add(WSConstants.UT);
        actions.add(WSConstants.TS);
        actions.add(WSConstants.SIGN);

        assertFalse(handler.checkResults(results, actions));
        assertTrue(handler.checkResultsAnyOrder(results, actions));
        assertFalse(actions.isEmpty());
    }

    /**
     */
    @Test
    public void
    testMixedOrder2() throws Exception {
        CustomHandler handler = new CustomHandler();

        java.util.List<WSSecurityEngineResult> results =
            new java.util.ArrayList<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.TS)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.UT)
        );

        java.util.List<Integer> actions = new java.util.ArrayList<>();
        actions.add(WSConstants.SIGN);
        actions.add(WSConstants.UT);
        actions.add(WSConstants.TS);

        assertFalse(handler.checkResults(results, actions));
        assertTrue(handler.checkResultsAnyOrder(results, actions));
    }

    /**
     */
    @Test
    public void
    testMissingResult() throws Exception {
        CustomHandler handler = new CustomHandler();

        java.util.List<WSSecurityEngineResult> results =
            new java.util.ArrayList<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.UT)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.TS)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC)
        );

        java.util.List<Integer> actions = new java.util.ArrayList<>();
        actions.add(WSConstants.TS);
        actions.add(WSConstants.UT);
        actions.add(WSConstants.SIGN);

        assertFalse(handler.checkResults(results, actions));
        assertFalse(handler.checkResultsAnyOrder(results, actions));
    }

    /**
     */
    @Test
    public void
    testMissingAction() throws Exception {
        CustomHandler handler = new CustomHandler();

        java.util.List<WSSecurityEngineResult> results =
            new java.util.ArrayList<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.UT)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.TS)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SIGN)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.SC)
        );

        java.util.List<Integer> actions = new java.util.ArrayList<>();
        actions.add(WSConstants.TS);
        actions.add(WSConstants.UT);

        assertFalse(handler.checkResults(results, actions));
        assertFalse(handler.checkResultsAnyOrder(results, actions));
    }

    /**
     */
    @Test
    public void
    testNoResult() throws Exception {
        CustomHandler handler = new CustomHandler();

        java.util.List<WSSecurityEngineResult> results =
            new java.util.ArrayList<WSSecurityEngineResult>();

        java.util.List<Integer> actions = new java.util.ArrayList<>();
        actions.add(WSConstants.TS);

        assertFalse(handler.checkResults(results, actions));
        assertFalse(handler.checkResultsAnyOrder(results, actions));
    }

    /**
     */
    @Test
    public void
    testNoAction() throws Exception {
        CustomHandler handler = new CustomHandler();

        java.util.List<WSSecurityEngineResult> results =
            new java.util.ArrayList<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.TS)
        );

        java.util.List<Integer> actions = new java.util.ArrayList<>();

        assertFalse(handler.checkResults(results, actions));
        assertFalse(handler.checkResultsAnyOrder(results, actions));
    }

    /**
     */
    @Test
    public void
    testMultipleIdenticalResults() throws Exception {
        CustomHandler handler = new CustomHandler();

        java.util.List<WSSecurityEngineResult> results =
            new java.util.ArrayList<WSSecurityEngineResult>();
        results.add(
            new WSSecurityEngineResult(WSConstants.ENCR)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.UT)
        );
        results.add(
            new WSSecurityEngineResult(WSConstants.ENCR)
        );

        java.util.List<Integer> actions = new java.util.ArrayList<>();
        actions.add(WSConstants.ENCR);
        actions.add(WSConstants.UT);
        actions.add(WSConstants.UT);

        assertFalse(handler.checkResults(results, actions));
        assertFalse(handler.checkResultsAnyOrder(results, actions));
    }

}
