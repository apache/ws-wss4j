/*
 * Copyright 2004,2005 The Apache Software Foundation.
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

import org.apache.ws.secpolicy.SPConstants;

public abstract class Token extends AbstractSecurityAssertion {

    /**
     * Inclusion property of a TokenAssertion
     */
    private int inclusion = SPConstants.INCLUDE_TOEKN_ALWAYS;
    
    /**
     * Whether to derive keys or not
     */
    private boolean derivedKeys;
    
    private boolean impliedDerivedKeys;
    
    private boolean explicitDerivedKeys;
    
    /**
     * @return Returns the inclusion.
     */
    public int getInclusion() {
        return inclusion;
    }

    /**
     * @param inclusion The inclusion to set.
     */
    public void setInclusion(int inclusion)  {
        if(SPConstants.INCLUDE_TOEKN_ALWAYS == inclusion || 
           SPConstants.INCLUDE_TOEKN_ALWAYS_TO_RECIPIENT == inclusion ||
           SPConstants.INCLUDE_TOEKN_ALWAYS_TO_INITIATOR == inclusion ||
           SPConstants.INCLUDE_TOKEN_NEVER == inclusion ||
           SPConstants.INCLUDE_TOKEN_ONCE == inclusion ) {
            this.inclusion = inclusion;
        } else {
            //TODO replace this with a proper (WSSPolicyException) exception
            throw new RuntimeException("Incorrect inclusion value: " + inclusion);
        }
    }
    
    /**
     * @return Returns the derivedKeys.
     */
    public boolean isDerivedKeys() {
        return derivedKeys;
    }

    /**
     * @param derivedKeys The derivedKeys to set.
     */
    public void setDerivedKeys(boolean derivedKeys) {
        this.derivedKeys = derivedKeys;
    } 
    
    
    public boolean isExplicitDerivedKeys() {
        return explicitDerivedKeys;
    }
    
    public void setExplicitDerivedKeys(boolean explicitDerivedKeys) {
        this.explicitDerivedKeys = explicitDerivedKeys;
    }
    
    public boolean isImpliedDerivedKeys() {
        return impliedDerivedKeys;
    }
    
    public void setImpliedDerivedKeys(boolean impliedDerivedKeys) {
        this.impliedDerivedKeys = impliedDerivedKeys;
    }
    
}