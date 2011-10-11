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
import org.swssf.wss.ext.WSSConstants;
import org.swssf.wss.securityEvent.AlgorithmSuiteSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.swssf.xmlsec.ext.XMLSecurityConstants;

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

        XMLSecurityConstants.KeyUsage keyUsage = algorithmSuiteSecurityEvent.getKeyUsage();
        if (WSSConstants.Sym_Sig.equals(keyUsage)) {
            if (!algorithmSuite.getSymmetricSignature().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                setAsserted(false);
                setErrorMessage("Symmetric signature algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
            }
        } else if (WSSConstants.Asym_Sig.equals(keyUsage)) {
            if (!algorithmSuite.getAsymmetricSignature().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                setAsserted(false);
                setErrorMessage("Asymmetric signature algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
            }
        } else if (WSSConstants.Dig.equals(keyUsage)) {
            if (!algorithmSuite.getDigest().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                setAsserted(false);
                setErrorMessage("Digest algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
            }
        } else if (WSSConstants.Enc.equals(keyUsage)) {
            if (!algorithmSuite.getEncryption().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                setAsserted(false);
                setErrorMessage("Encryption algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
            }
        } else if (WSSConstants.Sym_Key_Wrap.equals(keyUsage)) {
            if (!algorithmSuite.getSymmetricKeyWrap().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                setAsserted(false);
                setErrorMessage("Symmetric key wrap algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
            }
        } else if (WSSConstants.Asym_Key_Wrap.equals(keyUsage)) {
            if (!algorithmSuite.getAsymmetricKeyWrap().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                setAsserted(false);
                setErrorMessage("Asymmetric key wrap algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
            }
        } else if (WSSConstants.Comp_Key.equals(keyUsage)) {
            if (!algorithmSuite.getComputedKey().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                setAsserted(false);
                setErrorMessage("Computed key algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
            }
        } else if (WSSConstants.Enc_KD.equals(keyUsage)) {
            if (!algorithmSuite.getEncryptionKeyDerivation().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                setAsserted(false);
                setErrorMessage("Encryption key derivation algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
            }
        } else if (WSSConstants.Sig_KD.equals(keyUsage)) {
            if (!algorithmSuite.getSignatureKeyDerivation().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                setAsserted(false);
                setErrorMessage("Signature key derivation algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
            }
        } else if (WSSConstants.C14n.equals(keyUsage)) {
            if (!algorithmSuite.getC14n().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                setAsserted(false);
                setErrorMessage("C14N algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
            }
        } else if (WSSConstants.Soap_Norm.equals(keyUsage)) {
            if (!algorithmSuite.getSoapNormalization().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                setAsserted(false);
                setErrorMessage("Soap normalization algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
            }
        } else if (WSSConstants.STR_Trans.equals(keyUsage)) {
            if (!algorithmSuite.getStrTransform().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                setAsserted(false);
                setErrorMessage("STR transformation algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
            }
        } else if (WSSConstants.XPath.equals(keyUsage)) {
            if (!algorithmSuite.getXPath().equals(algorithmSuiteSecurityEvent.getAlgorithmURI())) {
                setAsserted(false);
                setErrorMessage("XPath algorithm " + algorithmSuiteSecurityEvent.getAlgorithmURI() + " does not meet policy");
            }
        }
        return isAsserted();
    }
}
