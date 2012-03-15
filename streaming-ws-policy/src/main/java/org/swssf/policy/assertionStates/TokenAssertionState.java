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

import java.util.Iterator;

/**
 * WSP1.3, 5 Token Assertions
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public abstract class TokenAssertionState extends AssertionState implements Assertable {

    //todo WSP1.3, 5.2.1 Token Issuer: <sp:Issuer>wsa:EndpointReferenceType</sp:Issuer>
    //todo? WSP1.3 5.2.3 Required Claims
    //todo derived keys?

    public TokenAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException, XMLSecurityException {

        TokenSecurityEvent tokenSecurityEvent = (TokenSecurityEvent) securityEvent;
        AbstractToken abstractToken = (AbstractToken) getAssertion();
        final AbstractSecurityAssertion parentAssertion = abstractToken.getParentAssertion();

        int ignoreToken = 0;
        Iterator<SecurityToken.TokenUsage> tokenUsageIterator = tokenSecurityEvent.getSecurityToken().getTokenUsages().iterator();
        while (tokenUsageIterator.hasNext()) {
            SecurityToken.TokenUsage tokenUsage = tokenUsageIterator.next();
            switch (tokenUsage) {
                case MainSignature:
                    if (!(parentAssertion instanceof InitiatorToken)
                            && !(parentAssertion instanceof InitiatorSignatureToken)
                            && !(parentAssertion instanceof SignatureToken)
                            && !(parentAssertion instanceof ProtectionToken)
                            && !(parentAssertion instanceof TransportToken)) {
                        ignoreToken++;
                        break;
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
                        ignoreToken++;
                        break;
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
                        ignoreToken++;
                        break;
                    }

                    SupportingTokens supportingTokens = (SupportingTokens) parentAssertion;
                    SecurityToken.TokenUsage expectedTokenUsage = SecurityToken.TokenUsage.valueOf(supportingTokens.getName().getLocalPart());
                    if (expectedTokenUsage != tokenUsage) {
                        ignoreToken++;
                        break;
                    }
                    break;
            }
        }
        if (ignoreToken >= tokenSecurityEvent.getSecurityToken().getTokenUsages().size()) {
            //token is not for us, so return true to prevent false alarm
            return true;
        }

        //WSP1.3, 5.1 Token Inclusion
        //todo do we need a global token cache to fullfill ".../IncludeToken/Once" ?
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
