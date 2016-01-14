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
package org.apache.wss4j.policy.stax.assertionStates;

import javax.xml.namespace.QName;

import org.apache.wss4j.policy.AssertionState;
import org.apache.wss4j.common.WSSPolicyException;
import org.apache.wss4j.policy.model.AbstractSecurityAssertion;
import org.apache.wss4j.policy.model.AlgorithmSuite;
import org.apache.wss4j.policy.stax.Assertable;
import org.apache.wss4j.policy.stax.DummyPolicyAsserter;
import org.apache.wss4j.policy.stax.PolicyAsserter;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.apache.xml.security.stax.ext.XMLSecurityConstants;
import org.apache.xml.security.stax.securityEvent.AlgorithmSuiteSecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEvent;
import org.apache.xml.security.stax.securityEvent.SecurityEventConstants;

/**
 * WSP1.3, 6.1 Algorithm Suite Property
 */
public class AlgorithmSuiteAssertionState extends AssertionState implements Assertable {

    private PolicyAsserter policyAsserter;

    public AlgorithmSuiteAssertionState(AbstractSecurityAssertion assertion,
                                        PolicyAsserter policyAsserter,
                                        boolean asserted) {
        super(assertion, asserted);

        this.policyAsserter = policyAsserter;
        if (this.policyAsserter == null) {
            this.policyAsserter = new DummyPolicyAsserter();
        }

        if (asserted) {
            AlgorithmSuite algorithmSuite = (AlgorithmSuite) getAssertion();
            policyAsserter.assertPolicy(getAssertion());
            String namespace = algorithmSuite.getAlgorithmSuiteType().getNamespace();
            String name = algorithmSuite.getAlgorithmSuiteType().getName();
            policyAsserter.assertPolicy(new QName(namespace, name));
        }
    }

    @Override
    public SecurityEventConstants.Event[] getSecurityEventType() {
        return new SecurityEventConstants.Event[]{
                SecurityEventConstants.AlgorithmSuite
        };
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) throws WSSPolicyException {
        AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = (AlgorithmSuiteSecurityEvent) securityEvent;
        AlgorithmSuite algorithmSuite = (AlgorithmSuite) getAssertion();

        XMLSecurityConstants.AlgorithmUsage keyUsage = algorithmSuiteSecurityEvent.getAlgorithmUsage();
        int keyLength = algorithmSuiteSecurityEvent.getKeyLength();
        String algorithmURI = algorithmSuiteSecurityEvent.getAlgorithmURI();
        if (WSSConstants.Sym_Sig.equals(keyUsage)) {
            if (algorithmSuite.getSymmetricSignature() != null
                && !algorithmSuite.getSymmetricSignature().equals(algorithmURI)) {
                setAsserted(false);
                setErrorMessage("Symmetric signature algorithm " + algorithmURI + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
            if (algorithmSuite.getAlgorithmSuiteType() != null) {
                if (!algorithmSuiteSecurityEvent.isDerivedKey()
                    && (algorithmSuite.getAlgorithmSuiteType().getMinimumSymmetricKeyLength() > keyLength
                    || algorithmSuite.getAlgorithmSuiteType().getMaximumSymmetricKeyLength() < keyLength)) {
                    setAsserted(false);
                    setErrorMessage("Symmetric signature algorithm key length " + keyLength  + " does not meet policy");
                    policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
                } else if (algorithmSuiteSecurityEvent.isDerivedKey()
                        && algorithmSuite.getAlgorithmSuiteType().getSignatureDerivedKeyLength() != keyLength) {
                    setAsserted(false);
                    setErrorMessage("Symmetric signature algorithm derived key length " + keyLength + " does not meet policy");
                    policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
                }
            }
        } else if (WSSConstants.Asym_Sig.equals(keyUsage)) {
            if (algorithmSuite.getAsymmetricSignature() != null
                    && !algorithmSuite.getAsymmetricSignature().equals(algorithmURI)) {
                setAsserted(false);
                setErrorMessage("Asymmetric algorithm " + algorithmURI + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
            if (algorithmSuite.getAlgorithmSuiteType() != null
                    && (algorithmSuite.getAlgorithmSuiteType().getMinimumAsymmetricKeyLength() > keyLength
                    || algorithmSuite.getAlgorithmSuiteType().getMaximumAsymmetricKeyLength() < keyLength)) {
                setAsserted(false);
                setErrorMessage("Asymmetric signature algorithm key length " + keyLength + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
        } else if (WSSConstants.SigDig.equals(keyUsage)) {
            if (algorithmSuite.getAlgorithmSuiteType() != null
                    && !algorithmSuite.getAlgorithmSuiteType().getDigest().equals(algorithmURI)) {
                setAsserted(false);
                setErrorMessage("Digest algorithm " + algorithmURI + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
        } else if (WSSConstants.Enc.equals(keyUsage)) {
            if (algorithmSuite.getAlgorithmSuiteType() != null
                    && !algorithmSuite.getAlgorithmSuiteType().getEncryption().equals(algorithmURI)) {
                setAsserted(false);
                setErrorMessage("Encryption algorithm " + algorithmURI + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
            if (algorithmSuite.getAlgorithmSuiteType() != null) {
                if (!algorithmSuiteSecurityEvent.isDerivedKey()
                    && (algorithmSuite.getAlgorithmSuiteType().getMinimumSymmetricKeyLength() > keyLength
                    || algorithmSuite.getAlgorithmSuiteType().getMaximumSymmetricKeyLength() < keyLength)) {
                    setAsserted(false);
                    setErrorMessage("Symmetric encryption algorithm key length " + keyLength  + " does not meet policy");
                    policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
                } else if (algorithmSuiteSecurityEvent.isDerivedKey()
                        && algorithmSuite.getAlgorithmSuiteType().getEncryptionDerivedKeyLength() != keyLength) {
                    setAsserted(false);
                    setErrorMessage("Symmetric encryption algorithm derived key length " + keyLength  + " does not meet policy");
                    policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
                }
            }
        } else if (WSSConstants.Sym_Key_Wrap.equals(keyUsage)) {
            if (algorithmSuite.getAlgorithmSuiteType() != null
                    && !algorithmSuite.getAlgorithmSuiteType().getSymmetricKeyWrap().equals(algorithmURI)) {
                setAsserted(false);
                setErrorMessage("Symmetric key wrap algorithm " + algorithmURI + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
            if (algorithmSuite.getAlgorithmSuiteType() != null
                    && (algorithmSuite.getAlgorithmSuiteType().getMinimumSymmetricKeyLength() > keyLength
                    || algorithmSuite.getAlgorithmSuiteType().getMaximumSymmetricKeyLength() < keyLength)) {
                setAsserted(false);
                setErrorMessage("Symmetric key wrap algorithm key length " + keyLength  + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
        } else if (WSSConstants.Asym_Key_Wrap.equals(keyUsage)) {
            if (algorithmSuite.getAlgorithmSuiteType() != null
                    && !algorithmSuite.getAlgorithmSuiteType().getAsymmetricKeyWrap().equals(algorithmURI)) {
                setAsserted(false);
                setErrorMessage("Asymmetric key wrap algorithm " + algorithmURI + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
            if (algorithmSuite.getAlgorithmSuiteType() != null
                    && (algorithmSuite.getAlgorithmSuiteType().getMinimumAsymmetricKeyLength() > keyLength
                    || algorithmSuite.getAlgorithmSuiteType().getMaximumAsymmetricKeyLength() < keyLength)) {
                setAsserted(false);
                setErrorMessage("Asymmetric key wrap algorithm key length " + keyLength + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
        } else if (WSSConstants.COMP_KEY.equals(keyUsage)) {
            if (algorithmSuite.getComputedKey() != null
                    && !algorithmSuite.getComputedKey().equals(algorithmURI)) {
                setAsserted(false);
                setErrorMessage("Computed key algorithm " + algorithmURI + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
        } else if (WSSConstants.ENC_KD.equals(keyUsage)) {
            if (algorithmSuite.getAlgorithmSuiteType() != null
                    && !algorithmSuite.getAlgorithmSuiteType().getEncryptionKeyDerivation().equals(algorithmURI)) {
                setAsserted(false);
                setErrorMessage("Encryption key derivation algorithm " + algorithmURI + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
        } else if (WSSConstants.SIG_KD.equals(keyUsage)) {
            if (algorithmSuite.getAlgorithmSuiteType() != null
                    && !algorithmSuite.getAlgorithmSuiteType().getSignatureKeyDerivation().equals(algorithmURI)) {
                setAsserted(false);
                setErrorMessage("Signature key derivation algorithm " + algorithmURI + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
        } else if (WSSConstants.SigC14n.equals(keyUsage)) {
            if (algorithmSuite.getC14n() != null
                    && !algorithmSuite.getC14n().getValue().equals(algorithmURI)) {
                setAsserted(false);
                setErrorMessage("C14N algorithm " + algorithmURI + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
        } else if (WSSConstants.SigTransform.equals(keyUsage)) {
            if (algorithmSuite.getC14n() != null
                && !algorithmSuite.getC14n().getValue().equals(algorithmURI)
                && !WSSConstants.NS_C14N_EXCL.equals(algorithmURI)
                && !WSSConstants.SOAPMESSAGE_NS10_STR_TRANSFORM.equals(algorithmURI)
                && !WSSConstants.SWA_ATTACHMENT_CONTENT_SIG_TRANS.equals(algorithmURI)
                && !WSSConstants.SWA_ATTACHMENT_COMPLETE_SIG_TRANS.equals(algorithmURI)) {
                setAsserted(false);
                setErrorMessage("Transform C14N algorithm " + algorithmURI + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
        } else if (WSSConstants.SOAP_NORM.equals(keyUsage)) {
            if (algorithmSuite.getSoapNormType() != null
                    && !algorithmSuite.getSoapNormType().getValue().equals(algorithmURI)) {
                setAsserted(false);
                setErrorMessage("Soap normalization algorithm " + algorithmURI + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
        } else if (WSSConstants.STR_TRANS.equals(keyUsage)) {
            if (algorithmSuite.getStrType() != null
                    && !algorithmSuite.getStrType().getValue().equals(algorithmURI)) {
                setAsserted(false);
                setErrorMessage("STR transformation algorithm " + algorithmURI  + " does not meet policy");
                policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
            }
        } else if (WSSConstants.XPATH.equals(keyUsage) && algorithmSuite.getXPathType() != null 
            && !algorithmSuite.getXPathType().getValue().equals(algorithmURI)) {
            setAsserted(false);
            setErrorMessage("XPATH algorithm " + algorithmURI + " does not meet policy");
            policyAsserter.unassertPolicy(getAssertion(), getErrorMessage());
        }

        if (isAsserted()) {
            policyAsserter.assertPolicy(getAssertion());
            String namespace = algorithmSuite.getAlgorithmSuiteType().getNamespace();
            String name = algorithmSuite.getAlgorithmSuiteType().getName();
            policyAsserter.assertPolicy(new QName(namespace, name));
            if (algorithmSuite.getC14n() != null) {
                policyAsserter.assertPolicy(new QName(namespace, algorithmSuite.getC14n().name()));
            }
        }

        return isAsserted();
    }
}
