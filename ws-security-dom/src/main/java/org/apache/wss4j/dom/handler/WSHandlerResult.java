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

import java.util.List;
import java.util.Map;

import org.apache.wss4j.dom.WSSecurityEngineResult;

public class WSHandlerResult {
    private final String actor;
    private final List<WSSecurityEngineResult> wsSecurityResults;
    private final Map<Integer, List<WSSecurityEngineResult>> actionResults;

    /**
     * constructor
     * @param actor
     * @param results
     */ 
    public WSHandlerResult(String actor, List<WSSecurityEngineResult> results,
                           Map<Integer, List<WSSecurityEngineResult>> actionResults) {
        this.actor = actor;
        this.wsSecurityResults = results;
        this.actionResults = actionResults;
    }

    /**
     * gets the actor
     * @return actor
     */
    public String getActor() {
        return actor;
    }

    /**
     * gets the the security results
     * @return the the security results
     */
    public List<WSSecurityEngineResult> getResults() {
        return wsSecurityResults;
    }
    
    public Map<Integer, List<WSSecurityEngineResult>> getActionResults() {
        return actionResults;
    }
}
