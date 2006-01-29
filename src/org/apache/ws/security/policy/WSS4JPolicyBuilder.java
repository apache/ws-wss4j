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
package org.apache.ws.security.policy;

import java.util.ArrayList;
import java.util.Iterator;

import org.apache.ws.security.policy.model.AlgorithmSuite;
import org.apache.ws.security.policy.model.AsymmetricBinding;
import org.apache.ws.security.policy.model.Binding;
import org.apache.ws.security.policy.model.ProtectionToken;
import org.apache.ws.security.policy.model.EncryptionToken;
import org.apache.ws.security.policy.model.SignatureToken;
import org.apache.ws.security.policy.model.PolicyEngineData;
import org.apache.ws.security.policy.model.SymmetricBinding;
import org.apache.ws.security.policy.model.AsymmetricBinding;
import org.apache.ws.security.policy.model.SymmetricAsymmetricBindingBase;
import org.apache.ws.security.policy.model.SignedEncryptedElements;
import org.apache.ws.security.policy.model.SignedEncryptedParts;
import org.apache.ws.security.policy.model.Wss10;
import org.apache.ws.security.policy.model.Wss11;

public class WSS4JPolicyBuilder {

    /**
     * Compile the parsed security data into one Policy data block.
     * 
     * This methods loops over all top level Policy Engine data, extracts the
     * parsed parameters and sets them into a single data block. The WSS4J
     * policy enabled handler takes this data block to control the setup of the
     * security header.
     * 
     * @param topLevelPeds
     *            The list of the top level Policy Engine data
     * @return The compile Poilcy data block.
     * @throws WSSPolicyException
     */
    public static WSS4JPolicyData build(ArrayList topLevelPeds)
            throws WSSPolicyException {
        Iterator topLevelPEDIterator = topLevelPeds.iterator();
        WSS4JPolicyData wpd = new WSS4JPolicyData();
        while (topLevelPEDIterator.hasNext()) {
            PolicyEngineData ped = (PolicyEngineData) topLevelPEDIterator
                    .next();
            if (ped instanceof Binding) {
                if (ped instanceof SymmetricBinding) {
                    processSymmetricPolicyBinding((SymmetricBinding) ped, wpd);
                } else {
                    processAsymmetricPolicyBinding((AsymmetricBinding) ped, wpd);
                }
            } else if (ped instanceof Wss10) {
                processWSS10((Wss10) ped, wpd);
            } else if (ped instanceof Wss11) {
                processWSS11((Wss11) ped, wpd);
            } else if (ped instanceof SignedEncryptedElements) {
                processSignedEncryptedElements((SignedEncryptedElements) ped,
                        wpd);
            } else if (ped instanceof SignedEncryptedParts) {
                processSignedEncryptedParts((SignedEncryptedParts) ped, wpd);
            }
        }
        return wpd;
    }

    private static void processSymmetricPolicyBinding(
            SymmetricBinding symmBinding, WSS4JPolicyData wpd) {
        binding(symmBinding, wpd);
        symmAsymmBinding(symmBinding, wpd);
        symmetricBinding(symmBinding, wpd);
    }

    private static void processWSS10(Wss10 wss10, WSS4JPolicyData wpd) {
        // TODO
        throw new UnsupportedOperationException("TODO");
    }

    private static void processAsymmetricPolicyBinding(
            AsymmetricBinding binding, WSS4JPolicyData wpd) {
        binding(binding, wpd);
        symmAsymmBinding(binding, wpd);
        asymmetricBinding(binding, wpd);
    }

    private static void processWSS11(Wss11 wss11, WSS4JPolicyData wpd) {
        if (wss11.isRequireSignatureConfirmation()) {
        }
    }

    private static void processSignedEncryptedElements(
            SignedEncryptedElements see, WSS4JPolicyData wpd) {
        // TODO
        throw new UnsupportedOperationException("TODO");
    }

    private static void processSignedEncryptedParts(SignedEncryptedParts sep,
            WSS4JPolicyData wpd) {
        // TODO
        throw new UnsupportedOperationException("TODO");
    }

    private static void binding(Binding binding, WSS4JPolicyData wpd) {
        algorithmSuite(binding.getAlgorithmSuite(), wpd);
        binding.getLayout();
        binding.isIncludeTimestamp();
    }

    private static void symmAsymmBinding(
            SymmetricAsymmetricBindingBase binding, WSS4JPolicyData wpd) {
        binding.isEntireHeaderAndBodySignatures();
        binding.getProtectionOrder();
        binding.isSignatureProtection();
        binding.isTokenProtection();
    }

    private static void symmetricBinding(SymmetricBinding binding,
            WSS4JPolicyData wpd) {
        PolicyEngineData ped = binding.getProtectionToken();
        if (ped != null) {
            wpd
                    .setProtectionToken(((ProtectionToken) ped)
                            .getProtectionToken());
        } else {
            ped = binding.getEncryptionToken();
            PolicyEngineData ped1 = binding.getSignatureToken();
            if (ped == null && ped1 == null) {
                // this is an error - throw something
            }
            wpd
                    .setEncryptionToken(((EncryptionToken) ped)
                            .getEncryptionToken());
            wpd.setSignatureToken(((SignatureToken) ped).getSignatureToken());
        }
    }

    private static void asymmetricBinding(AsymmetricBinding binding,
            WSS4JPolicyData wpd) {
        PolicyEngineData ped = binding.getRecipientToken();
        PolicyEngineData ped1 = binding.getInitiatorToken();
        if (ped == null && ped1 == null) {
            // this is an error - throw something
        }
        wpd.setRecipientToken(((EncryptionToken) ped).getEncryptionToken());
        wpd.setInitiatorToken(((SignatureToken) ped).getSignatureToken());
    }

    private static void algorithmSuite(AlgorithmSuite suite, WSS4JPolicyData wpd) {
    }

}
