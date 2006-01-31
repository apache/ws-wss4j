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

/**
 * @author Werner Dittmann (werner@apache.org)
 */
import java.util.ArrayList;
import java.util.Iterator;

import org.apache.ws.security.policy.model.AlgorithmSuite;
import org.apache.ws.security.policy.model.AsymmetricBinding;
import org.apache.ws.security.policy.model.Binding;
import org.apache.ws.security.policy.model.Header;
import org.apache.ws.security.policy.model.ProtectionToken;
import org.apache.ws.security.policy.model.RecipientToken;
import org.apache.ws.security.policy.model.InitiatorToken;
import org.apache.ws.security.policy.model.EncryptionToken;
import org.apache.ws.security.policy.model.SignatureToken;
import org.apache.ws.security.policy.model.PolicyEngineData;
import org.apache.ws.security.policy.model.SymmetricBinding;
import org.apache.ws.security.policy.model.SymmetricAsymmetricBindingBase;
import org.apache.ws.security.policy.model.SignedEncryptedElements;
import org.apache.ws.security.policy.model.SignedEncryptedParts;
import org.apache.ws.security.policy.model.Wss10;
import org.apache.ws.security.policy.model.Wss11;

public class WSS4JPolicyBuilder {

	/**
	 * Compile the parsed security data into one Policy data block.
	 * 
	 * This methods loops over all top level Policy Engine data elements,
	 * extracts the parsed parameters and sets them into a single data block.
	 * During this processing the method prepares the parameters in a format
	 * that is ready for processing by the WSS4J functions.
	 * 
	 * <p/>
	 * 
	 * The WSS4J policy enabled handler takes this data block to control the
	 * setup of the security header.
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
			/*
			 * Don't change the order of Wss11 / Wss10 instance checks because
			 * Wss11 extends Wss10 - thus first check Wss11.
			 */
			} else if (ped instanceof Wss11) {
				processWSS11((Wss11) ped, wpd);
			} else if (ped instanceof Wss10) {
				processWSS10((Wss10) ped, wpd);
			} else if (ped instanceof SignedEncryptedElements) {
				processSignedEncryptedElements((SignedEncryptedElements) ped,
						wpd);
			} else if (ped instanceof SignedEncryptedParts) {
				processSignedEncryptedParts((SignedEncryptedParts) ped, wpd);
			}
			else {
				System.out.println("Unknown top level PED found: " + ped.getClass().getName());
			}
		}
		return wpd;
	}

	/**
	 * Evaluate the symmetric policy binding data.
	 * 
	 * @param binding
	 *            The binding data
	 * @param wpd
	 *            The WSS4J data to initialize
	 * @throws WSSPolicyException
	 */
	private static void processSymmetricPolicyBinding(
			SymmetricBinding symmBinding, WSS4JPolicyData wpd)
			throws WSSPolicyException {
		wpd.setSymmetricBinding(true);
		binding(symmBinding, wpd);
		symmAsymmBinding(symmBinding, wpd);
		symmetricBinding(symmBinding, wpd);
	}

	private static void processWSS10(Wss10 wss10, WSS4JPolicyData wpd) {
		System.out.println("Top level PED found: " + wss10.getClass().getName());
		// TODO
		// throw new UnsupportedOperationException("TODO");
	}

	/**
	 * Evaluate the asymmetric policy binding data.
	 * 
	 * @param binding
	 *            The binding data
	 * @param wpd
	 *            The WSS4J data to initialize
	 * @throws WSSPolicyException
	 */
	private static void processAsymmetricPolicyBinding(
			AsymmetricBinding binding, WSS4JPolicyData wpd)
			throws WSSPolicyException {
		wpd.setSymmetricBinding(false);
		binding(binding, wpd);
		symmAsymmBinding(binding, wpd);
		asymmetricBinding(binding, wpd);
	}

	private static void processWSS11(Wss11 wss11, WSS4JPolicyData wpd) {
			wpd.setSignatureConfirmation(wss11.isRequireSignatureConfirmation());
	}

	/**
	 * Populate elements to sign and/or encrypt with the message tokens.
	 * 
	 * @param sep
	 *            The data describing the elements (XPath)
	 * @param wpd
	 *            The WSS4J data to initialize
	 */
	private static void processSignedEncryptedElements(
			SignedEncryptedElements see, WSS4JPolicyData wpd) {
		Iterator it = see.getXPathExpressions().iterator();
		if (see.isSignedElements()) {
			while (it.hasNext()) {
				wpd.setSignedElements((String) it.next());
			}
		} else {
			while (it.hasNext()) {
				wpd.setEncryptedElements((String) it.next());
			}
		}
	}

	/**
	 * Populate parts to sign and/or encrypt with the message tokens.
	 * 
	 * @param sep
	 *            The data describing the parts
	 * @param wpd
	 *            The WSS4J data to initialize
	 */
	private static void processSignedEncryptedParts(SignedEncryptedParts sep,
			WSS4JPolicyData wpd) {
		Iterator it = sep.getHeaders().iterator();
		if (sep.isSignedParts()) {
			wpd.setSignBody(sep.isBody());
			while (it.hasNext()) {
				Header header = (Header) it.next();
				wpd.setSignedParts(header.getNamespace(), header.getName());
			}
		} else {
			wpd.setEncryptBody(sep.isBody());
			while (it.hasNext()) {
				Header header = (Header) it.next();
				wpd.setEncryptedParts(header.getNamespace(), header.getName());
			}
		}
	}

	/**
	 * Evaluate policy data that is common to all bindings.
	 * 
	 * @param binding
	 *            The common binding data
	 * @param wpd
	 *            The WSS4J data to initialize
	 */
	private static void binding(Binding binding, WSS4JPolicyData wpd) {
		wpd.setLayout(binding.getLayout().getValue());
		wpd.setIncludeTimestamp(binding.isIncludeTimestamp());
	}

	/**
	 * Evaluate policy data that is common to symmetric and asymmetric bindings.
	 * 
	 * @param binding
	 *            The symmetric/asymmetric binding data
	 * @param wpd
	 *            The WSS4J data to initialize
	 */
	private static void symmAsymmBinding(
			SymmetricAsymmetricBindingBase binding, WSS4JPolicyData wpd) {
		wpd.setEntireHeaderAndBodySignatures(binding
				.isEntireHeaderAndBodySignatures());
		wpd.setProtectionOrder(binding.getProtectionOrder());
		wpd.setSignatureProtection(binding.isSignatureProtection());
		wpd.setTokenProtection(binding.isTokenProtection());
	}

	/**
	 * Evaluate policy data that is specific to symmetric binding.
	 * 
	 * @param binding
	 *            The symmetric binding data
	 * @param wpd
	 *            The WSS4J data to initialize
	 */
	private static void symmetricBinding(SymmetricBinding binding,
			WSS4JPolicyData wpd) throws WSSPolicyException {
		PolicyEngineData ped = binding.getProtectionToken();
		AlgorithmSuite suite = binding.getAlgorithmSuite();
		if (ped != null) {
			wpd.setProtectionToken(
					((ProtectionToken) ped).getProtectionToken(), suite);
		} else {
			ped = binding.getEncryptionToken();
			PolicyEngineData ped1 = binding.getSignatureToken();
			if (ped == null && ped1 == null) {
				// this is an error - throw something
			}
			wpd.setEncryptionToken(
					((EncryptionToken) ped).getEncryptionToken(), suite);
			wpd.setSignatureToken(((SignatureToken) ped).getSignatureToken(),
					suite);
		}
	}

	/**
	 * Evaluate policy data that is specific to asymmetric binding.
	 * 
	 * @param binding
	 *            The asymmetric binding data
	 * @param wpd
	 *            The WSS4J data to initialize
	 */
	private static void asymmetricBinding(AsymmetricBinding binding,
			WSS4JPolicyData wpd) throws WSSPolicyException {
		PolicyEngineData ped = binding.getRecipientToken();
		PolicyEngineData ped1 = binding.getInitiatorToken();
		if (ped == null && ped1 == null) {
			// this is an error - throw something
		}
		AlgorithmSuite suite = binding.getAlgorithmSuite();
		wpd.setRecipientToken(((RecipientToken) ped).getRecipientToken(),
				suite);
		wpd
				.setInitiatorToken(((InitiatorToken) ped1).getInitiatorToken(),
						suite);
	}
}
