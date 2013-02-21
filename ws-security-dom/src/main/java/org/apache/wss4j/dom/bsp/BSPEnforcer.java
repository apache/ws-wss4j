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
package org.apache.wss4j.dom.bsp;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.wss4j.common.bsp.BSPRule;
import org.apache.wss4j.common.ext.WSSecurityException;

/**
 * An class that enforces Basic Security Profile Rules
 */
public class BSPEnforcer {
    
    private static final Log LOG = LogFactory.getLog(BSPEnforcer.class);
    
    private List<BSPRule> ignoredBSPRules = Collections.emptyList();
    
    private boolean disableBSPRules;
    
    public BSPEnforcer() {
        // Complete
    }
    
    public BSPEnforcer(List<BSPRule> bspRules) {
        ignoredBSPRules = new ArrayList<BSPRule>(bspRules);
    }
    
    public BSPEnforcer(boolean disableBSPRules) {
        this.disableBSPRules = disableBSPRules;
    }
    
    public void handleBSPRule(BSPRule bspRule) throws WSSecurityException {
        if (disableBSPRules) {
            return;
        }
        
        if (!ignoredBSPRules.contains(bspRule)) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.INVALID_SECURITY, "empty",
                "BSP:" + bspRule.name() + ": " + bspRule.getMsg()
            );
        } else {
            LOG.debug("BSP:" + bspRule.name() + ": " + bspRule.getMsg());
        }
    }

    public void setIgnoredBSPRules(List<BSPRule> bspRules) {
        ignoredBSPRules = new ArrayList<BSPRule>(bspRules);
    }
    
    public void setDisableBSPRules(boolean disableBSPRules) {
        this.disableBSPRules = disableBSPRules;
    }
    
}
