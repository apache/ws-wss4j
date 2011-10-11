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

package org.swssf.policy.secpolicy.model;

import org.apache.neethi.Assertion;
import org.swssf.policy.assertionStates.AssertionState;
import org.swssf.policy.secpolicy.SPConstants;
import org.swssf.wss.securityEvent.SecurityEvent;

import javax.xml.namespace.QName;
import java.util.List;
import java.util.Map;

/**
 * class lent from apache rampart
 */
public abstract class Token extends AbstractSecurityAssertion {

    /**
     * Inclusion property of a TokenAssertion
     */
    private SPConstants.IncludeTokenType inclusion = SPConstants.IncludeTokenType.INCLUDE_TOKEN_ALWAYS;

    private String issuer;

    private String issuerName;

    /**
     * Whether to derive keys or not
     */
    private boolean derivedKeys;

    private boolean impliedDerivedKeys;

    private boolean explicitDerivedKeys;

    /**
     * @return Returns the inclusion.
     */
    public SPConstants.IncludeTokenType getInclusion() {
        return inclusion;
    }

    /**
     * @param inclusion The inclusion to set.
     */
    public void setInclusion(SPConstants.IncludeTokenType inclusion) {
        if (SPConstants.IncludeTokenType.INCLUDE_TOKEN_ALWAYS == inclusion ||
                SPConstants.IncludeTokenType.INCLUDE_TOKEN_ALWAYS_TO_RECIPIENT == inclusion ||
                SPConstants.IncludeTokenType.INCLUDE_TOKEN_ALWAYS_TO_INITIATOR == inclusion ||
                SPConstants.IncludeTokenType.INCLUDE_TOKEN_NEVER == inclusion ||
                SPConstants.IncludeTokenType.INCLUDE_TOKEN_ONCE == inclusion) {
            this.inclusion = inclusion;
        } else {
            //TODO replace this with a proper (WSSPolicyException) exception
            throw new RuntimeException("Incorrect inclusion value: " + inclusion);
        }
    }

    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public String getIssuerName() {
        return issuerName;
    }

    public void setIssuerName(String issuerName) {
        this.issuerName = issuerName;
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

    public abstract QName getXmlName();

    private SecurityEvent.Event[] securityEvents;

    public void setResponsibleAssertionEvents(SecurityEvent.Event[] securityEvents) {
        this.securityEvents = securityEvents;
    }

    @Override
    public SecurityEvent.Event[] getResponsibleAssertionEvents() {
        return this.securityEvents;
    }

    @Override
    public boolean isAsserted(Map<SecurityEvent.Event, Map<Assertion, List<AssertionState>>> assertionStateMap) {
        return super.isAsserted(assertionStateMap);
    }
}
