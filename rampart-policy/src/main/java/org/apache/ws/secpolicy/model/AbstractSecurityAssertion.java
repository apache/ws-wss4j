/*
 * Copyright 2001-2004 The Apache Software Foundation.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.ws.secpolicy.model;

import org.apache.neethi.Assertion;
import org.apache.neethi.PolicyComponent;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.SP12Constants;

public abstract class AbstractSecurityAssertion implements Assertion {

    private boolean isOptional;
    private boolean isIgnorable;
    
    private boolean normalized = true; 
    
    protected int version;

    public boolean isOptional() {
        return isOptional;
    }
    
    public void setOptional(boolean isOptional) {
        this.isOptional = isOptional;
    }
    public boolean isIgnorable() {
        return isIgnorable;
    }
    
    public void setIgnorable(boolean isIgnorable) {
        this.isIgnorable = isIgnorable;
    }

    public short getType() {
        return org.apache.neethi.Constants.TYPE_ASSERTION;
    }    
    
    public boolean equal(PolicyComponent policyComponent) {
        throw new UnsupportedOperationException();
    }
    
    public void setNormalized(boolean normalized) {
        this.normalized = normalized;
    }
    
    public boolean isNormalized() {
        return this.normalized;
    }

    public PolicyComponent normalize() {
        
        /*
         * TODO: Handling the isOptional:TRUE case
         */
        return this;
    }  
    
    public void setVersion(int version) {
        this.version = version;
    }
    
    public int getVersion() {
        return version;
    }
    
    
}
