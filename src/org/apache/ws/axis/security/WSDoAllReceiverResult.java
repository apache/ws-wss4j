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

package org.apache.ws.axis.security;

import java.util.Vector;

/**
 * @author Werner Dittmann (Werner.Dittmann@Siemens.com)
 */
public class WSDoAllReceiverResult {
    private String actor;
    private Vector wsSecurityResults;

    WSDoAllReceiverResult(String actor, Vector wsResults) {
        this.actor = actor;
        this.wsSecurityResults = wsResults;
    }

    /**
     * @return
     */
    public String getActor() {
        return actor;
    }

    /**
     * @return
     */
    public Vector getResults() {
        return wsSecurityResults;
    }

}
