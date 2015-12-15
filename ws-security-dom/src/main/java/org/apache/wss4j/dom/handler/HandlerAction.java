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

import org.apache.wss4j.common.SecurityActionToken;


/**
 * This class associates an "Action" Integer with a (optional) SecurityActionToken
 */
public class HandlerAction {

    private Integer action;
    private SecurityActionToken actionToken;

    public HandlerAction() {

    }

    public HandlerAction(Integer action) {
        this(action, null);
    }

    public HandlerAction(Integer action, SecurityActionToken actionToken) {
        this.action = action;
        this.actionToken = actionToken;
    }

    public Integer getAction() {
        return action;
    }
    public void setAction(Integer action) {
        this.action = action;
    }
    public SecurityActionToken getActionToken() {
        return actionToken;
    }
    public void setActionToken(SecurityActionToken actionToken) {
        this.actionToken = actionToken;
    }
}