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

import org.swssf.policy.secpolicy.model.AbstractSecurityAssertion;
import org.swssf.policy.secpolicy.model.AlgorithmSuite;
import org.swssf.securityEvent.AlgorithmSuiteSecurityEvent;
import org.swssf.securityEvent.SecurityEvent;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class AlgorithmSuiteAssertionState extends AssertionState {

    public AlgorithmSuiteAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) {
        AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = (AlgorithmSuiteSecurityEvent) securityEvent;
        AlgorithmSuite algorithmSuite = (AlgorithmSuite) getAssertion();

        switch (algorithmSuiteSecurityEvent.getKeyUsage()) {
            case Sym_Sig:
                if (!algorithmSuite.getSymmetricSignature().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                    setAsserted(false);
                    setErrorMessage("Symmetric signature algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
                }
                break;
            case Asym_Sig:
                if (!algorithmSuite.getAsymmetricSignature().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                    setAsserted(false);
                    setErrorMessage("Asymmetric signature algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
                }
                break;
            case Dig:
                if (!algorithmSuite.getDigest().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                    setAsserted(false);
                    setErrorMessage("Digest algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
                }
                break;
            case Enc:
                if (!algorithmSuite.getEncryption().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                    setAsserted(false);
                    setErrorMessage("Encryption algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
                }
                break;
            case Sym_Key_Wrap:
                if (!algorithmSuite.getSymmetricKeyWrap().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                    setAsserted(false);
                    setErrorMessage("Symmetric key wrap algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
                }
                break;
            case Asym_Key_Wrap:
                if (!algorithmSuite.getAsymmetricKeyWrap().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                    setAsserted(false);
                    setErrorMessage("Asymmetric key wrap algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
                }
                break;
            case Comp_Key:
                if (!algorithmSuite.getComputedKey().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                    setAsserted(false);
                    setErrorMessage("Computed key algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
                }
                break;
            case Enc_KD:
                if (!algorithmSuite.getEncryptionKeyDerivation().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                    setAsserted(false);
                    setErrorMessage("Encryption key derivation algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
                }
                break;
            case Sig_KD:
                if (!algorithmSuite.getSignatureKeyDerivation().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                    setAsserted(false);
                    setErrorMessage("Signature key derivation algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
                }
                break;
            case C14n:
                if (!algorithmSuite.getC14n().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                    setAsserted(false);
                    setErrorMessage("C14N algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
                }
                break;
            case Soap_Norm:
                if (!algorithmSuite.getSoapNormalization().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                    setAsserted(false);
                    setErrorMessage("Soap normalization algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
                }
                break;
            case STR_Trans:
                if (!algorithmSuite.getStrTransform().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                    setAsserted(false);
                    setErrorMessage("STR transformation algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
                }
                break;
            case XPath:
                if (!algorithmSuite.getXPath().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                    setAsserted(false);
                    setErrorMessage("XPath algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
                }
                break;

        }
        return isAsserted();
    }
}
