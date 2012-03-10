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
package org.swssf.policy.assertionStates;

import org.apache.ws.secpolicy.AssertionState;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.ws.secpolicy.model.*;
import org.swssf.policy.Assertable;
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.wss.securityEvent.TokenSecurityEvent;
import org.swssf.xmlsec.ext.SecurityToken;
import org.swssf.xmlsec.ext.XMLSecurityException;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */

public abstract class TokenAssertionState extends AssertionState implements Assertable {

    //todo how to verify the issuer of the UsernameToken??
    //todo <sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>
    //todo issuerName
    //todo claims
    //todo derived keys?

    public TokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException, XMLSecurityException {

        TokenSecurityEvent tokenSecurityEvent = (TokenSecurityEvent) securityEvent;
        AbstractToken abstractToken = (AbstractToken) getAssertion();

        final AbstractSecurityAssertion parentAssertion = abstractToken.getParentAssertion();
        //todo what todo with the other usages if there are any? What when a sig and enc derives from the same source token?
        SecurityToken.TokenUsage tokenUsage = tokenSecurityEvent.getSecurityToken().getTokenUsages().get(0);
        switch (tokenUsage) {
            case MainSignature:
                if (!(parentAssertion instanceof InitiatorToken)
                        && !(parentAssertion instanceof InitiatorSignatureToken)
                        && !(parentAssertion instanceof SignatureToken)
                        && !(parentAssertion instanceof ProtectionToken)
                        && !(parentAssertion instanceof TransportToken)) {
                    return true;
                }
                break;
            case Signature:
                throw new WSSPolicyException("Illegal token usage!");
            case MainEncryption:
                if (!(parentAssertion instanceof RecipientToken)
                        && !(parentAssertion instanceof RecipientEncryptionToken)
                        && !(parentAssertion instanceof EncryptionToken)
                        && !(parentAssertion instanceof ProtectionToken)
                        && !(parentAssertion instanceof TransportToken)) {
                    return true;
                }
                break;
            case Encryption:
                throw new WSSPolicyException("Illegal token usage!");
            case SupportingTokens:
            case SignedSupportingTokens:
            case EndorsingSupportingTokens:
            case SignedEndorsingSupportingTokens:
            case SignedEncryptedSupportingTokens:
            case EncryptedSupportingTokens:
            case EndorsingEncryptedSupportingTokens:
            case SignedEndorsingEncryptedSupportingTokens:
                if (!(parentAssertion instanceof SupportingTokens)) {
                    return true;
                }

                SupportingTokens supportingTokens = (SupportingTokens) parentAssertion;
                SecurityToken.TokenUsage expectedTokenUsage = SecurityToken.TokenUsage.valueOf(supportingTokens.getName().getLocalPart());
                if (expectedTokenUsage != tokenUsage) {
                    return true;
                }
                break;
        }

        SPConstants.IncludeTokenType includeTokenType = abstractToken.getIncludeTokenType();
        if (includeTokenType == SPConstants.IncludeTokenType.INCLUDE_TOKEN_NEVER) {
            setAsserted(false);
            setErrorMessage("Token must not be included");
            return false;
        }

        boolean hasDerivedKeys = false;
        hasDerivedKeys = hasDerivedKeys(tokenSecurityEvent.getSecurityToken());
        if (abstractToken.getDerivedKeys() != null) {
            AbstractToken.DerivedKeys derivedKeys = abstractToken.getDerivedKeys();
            switch (derivedKeys) {
                case RequireDerivedKeys:
                case RequireExplicitDerivedKeys:
                case RequireImpliedDerivedKeys:
                    if (!hasDerivedKeys) {
                        setAsserted(false);
                        setErrorMessage("Derived key must be used");
                    }
            }
        } else {
            if (hasDerivedKeys) {
                setAsserted(false);
                setErrorMessage("Derived key must not be used");
            }
        }

        return assertToken(tokenSecurityEvent, abstractToken);
    }

    public abstract boolean assertToken(TokenSecurityEvent tokenSecurityEvent, AbstractToken abstractToken) throws WSSPolicyException, XMLSecurityException;

    protected boolean hasDerivedKeys(SecurityToken securityToken) throws XMLSecurityException {
        if (securityToken == null) {
            return false;
        } else if (securityToken.getTokenType() == WSSConstants.DerivedKeyToken) {
            return true;
        }

        if (securityToken.getWrappedTokens().size() == 0) {
            return false;
        }

        //all wrapped tokens must be derived!:
        boolean hasDerivedKeys = true;
        for (int i = 0; i < securityToken.getWrappedTokens().size(); i++) {
            SecurityToken wrappedSecurityToken = securityToken.getWrappedTokens().get(i);
            hasDerivedKeys &= hasDerivedKeys(wrappedSecurityToken);
        }
        return hasDerivedKeys;
    }
}
