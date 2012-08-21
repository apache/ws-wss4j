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
package org.apache.ws.security.policy.stax.assertionStates;

import org.apache.ws.security.policy.AssertionState;
import org.apache.ws.security.policy.SPConstants;
import org.apache.ws.security.policy.WSSPolicyException;
import org.apache.ws.security.policy.model.*;
import org.apache.ws.security.policy.stax.Assertable;
import org.apache.ws.security.stax.ext.WSSConstants;
import org.apache.xml.security.stax.ext.SecurityToken;
import org.apache.xml.security.stax.ext.XMLSecurityException;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.TokenSecurityEvent;

import java.util.Iterator;
import java.util.List;

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

        if (isAsserted()) {
            //just return true when this token assertion is already fulfilled.
            return true;
        }

        TokenSecurityEvent tokenSecurityEvent = (TokenSecurityEvent) securityEvent;
        AbstractToken abstractToken = (AbstractToken) getAssertion();
        final AbstractSecurityAssertion parentAssertion = abstractToken.getParentAssertion();

        int ignoreToken = 0;
        final List<SecurityToken.TokenUsage> tokenUsages = tokenSecurityEvent.getSecurityToken().getTokenUsages();
        Iterator<SecurityToken.TokenUsage> tokenUsageIterator = tokenUsages.iterator();
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
        if (ignoreToken >= tokenUsages.size()) {
            //token is not for us, so return true to prevent false alarm
            return true;
        }

        boolean asserted = true;

        //WSP1.3, 5.1 Token Inclusion
        //todo do we need a global token cache to fullfill ".../IncludeToken/Once" ?
        SPConstants.IncludeTokenType includeTokenType = abstractToken.getIncludeTokenType();
        if (includeTokenType == SPConstants.IncludeTokenType.INCLUDE_TOKEN_NEVER) {
            setErrorMessage("Token must not be included");
            asserted = false;
        }

        //WSP1.3, 5.3 Token Properties
        boolean hasDerivedKeys = false;
        hasDerivedKeys = hasDerivedKeys(tokenSecurityEvent.getSecurityToken());
        if (abstractToken.getDerivedKeys() != null) {
            AbstractToken.DerivedKeys derivedKeys = abstractToken.getDerivedKeys();
            switch (derivedKeys) {
                case RequireDerivedKeys:
                case RequireExplicitDerivedKeys:
                case RequireImpliedDerivedKeys:
                    if (!hasDerivedKeys) {
                        setErrorMessage("Derived key must be used");
                        asserted = false;
                    }
            }
        } else {
            if (hasDerivedKeys) {
                setErrorMessage("Derived key must not be used");
                asserted = false;
            }
        }

        asserted &= assertToken(tokenSecurityEvent, abstractToken);
        if (asserted) {
            setAsserted(true);
        }
        if (!asserted && (tokenUsages.contains(SecurityToken.TokenUsage.MainSignature)
                || tokenUsages.contains(SecurityToken.TokenUsage.MainEncryption))) {
            //return false if not asserted for the main signature and encryption tokens
            return false;
        } else {
            //always return true for supporting tokens.
            return true;
        }
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
