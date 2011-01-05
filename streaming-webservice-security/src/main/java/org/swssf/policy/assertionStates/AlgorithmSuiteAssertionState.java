/**
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.policy.assertionStates;

import org.swssf.policy.secpolicy.model.AbstractSecurityAssertion;
import org.swssf.policy.secpolicy.model.AlgorithmSuite;
import org.swssf.securityEvent.AlgorithmSuiteSecurityEvent;
import org.swssf.securityEvent.SecurityEvent;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class AlgorithmSuiteAssertionState extends AssertionState {

    public AlgorithmSuiteAssertionState(AbstractSecurityAssertion assertion, boolean asserted) {
        super(assertion, asserted);
    }

    @Override
    public boolean assertEvent(SecurityEvent securityEvent) {
        AlgorithmSuiteSecurityEvent algorithmSuiteSecurityEvent = (AlgorithmSuiteSecurityEvent) securityEvent;
        AlgorithmSuite algorithmSuite = (AlgorithmSuite) getAssertion();

        switch (algorithmSuiteSecurityEvent.getUsage()) {
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
