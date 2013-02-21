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
package org.apache.wss4j.policy.stax;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyBuilder;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.wss4j.policy.WSSPolicyException;
import org.apache.wss4j.policy.builders.*;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.wsdl.*;
import javax.wsdl.extensions.ExtensibilityElement;
import javax.wsdl.extensions.UnknownExtensibilityElement;
import javax.wsdl.extensions.soap.SOAPOperation;
import javax.wsdl.extensions.soap12.SOAP12Operation;
import javax.wsdl.factory.WSDLFactory;
import javax.wsdl.xml.WSDLReader;
import javax.xml.namespace.QName;
import java.net.URL;
import java.util.*;

/**
 * PolicyEnforcerFactory builds a map of all the possible effective Policies
 * and caches them for reuse
 *
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class PolicyEnforcerFactory {

    protected static final transient Log log = LogFactory.getLog(PolicyEnforcerFactory.class);

    private final List<AssertionBuilder> assertionBuilders;

    private Definition wsdlDefinition;
    private List<OperationPolicy> operationPolicies;
    private final Map<Element, Policy> elementPolicyCache;

    private PolicyEnforcerFactory(List<AssertionBuilder> customAssertionBuilders) {
        elementPolicyCache = new HashMap<Element, Policy>();

        assertionBuilders = new ArrayList<AssertionBuilder>();
        assertionBuilders.add(new AlgorithmSuiteBuilder());
        assertionBuilders.add(new AsymmetricBindingBuilder());
        assertionBuilders.add(new ContentEncryptedElementsBuilder());
        assertionBuilders.add(new EncryptedElementsBuilder());
        assertionBuilders.add(new EncryptedPartsBuilder());
        assertionBuilders.add(new EncryptionTokenBuilder());
        assertionBuilders.add(new HttpsTokenBuilder());
        assertionBuilders.add(new InitiatorEncryptionTokenBuilder());
        assertionBuilders.add(new InitiatorSignatureTokenBuilder());
        assertionBuilders.add(new InitiatorTokenBuilder());
        assertionBuilders.add(new IssuedTokenBuilder());
        assertionBuilders.add(new KerberosTokenBuilder());
        assertionBuilders.add(new KeyValueTokenBuilder());
        assertionBuilders.add(new LayoutBuilder());
        assertionBuilders.add(new ProtectionTokenBuilder());
        assertionBuilders.add(new RecipientEncryptionTokenBuilder());
        assertionBuilders.add(new RecipientSignatureTokenBuilder());
        assertionBuilders.add(new RecipientTokenBuilder());
        assertionBuilders.add(new RelTokenBuilder());
        assertionBuilders.add(new RequiredElementsBuilder());
        assertionBuilders.add(new RequiredPartsBuilder());
        assertionBuilders.add(new SamlTokenBuilder());
        assertionBuilders.add(new SecureConversationTokenBuilder());
        assertionBuilders.add(new SecurityContextTokenBuilder());
        assertionBuilders.add(new SignatureTokenBuilder());
        assertionBuilders.add(new SignedElementsBuilder());
        assertionBuilders.add(new SignedPartsBuilder());
        assertionBuilders.add(new SpnegoContextTokenBuilder());
        assertionBuilders.add(new SupportingTokensBuilder());
        assertionBuilders.add(new SymmetricBindingBuilder());
        assertionBuilders.add(new TransportBindingBuilder());
        assertionBuilders.add(new TransportTokenBuilder());
        assertionBuilders.add(new Trust10Builder());
        assertionBuilders.add(new Trust13Builder());
        assertionBuilders.add(new UsernameTokenBuilder());
        assertionBuilders.add(new WSS10Builder());
        assertionBuilders.add(new WSS11Builder());
        assertionBuilders.add(new X509TokenBuilder());

        if (customAssertionBuilders != null) {
            for (int i = 0; i < customAssertionBuilders.size(); i++) {
                AssertionBuilder customAssertionBuilder = customAssertionBuilders.get(i);
                assertionBuilders.add(customAssertionBuilder);
            }
        }
    }

    public static PolicyEnforcerFactory newInstance(URL wsdlUrl) throws WSSPolicyException {
        return newInstance(wsdlUrl, null);
    }

    public static PolicyEnforcerFactory newInstance(URL wsdlUrl, List<AssertionBuilder> customAssertionBuilders)
            throws WSSPolicyException {

        PolicyEnforcerFactory policyEnforcerFactory = new PolicyEnforcerFactory(customAssertionBuilders);
        policyEnforcerFactory.parseWsdl(wsdlUrl);
        return policyEnforcerFactory;
    }

    public static PolicyEnforcerFactory newInstance(Document document) throws WSSPolicyException {
        return newInstance(document, null);
    }

    public static PolicyEnforcerFactory newInstance(Document document, List<AssertionBuilder> customAssertionBuilders)
            throws WSSPolicyException {

        PolicyEnforcerFactory policyEnforcerFactory = new PolicyEnforcerFactory(customAssertionBuilders);
        policyEnforcerFactory.parseWsdl(document);
        return policyEnforcerFactory;
    }

    //todo enforce uniqueness of operation names to prevent SOAPAction spoofing.
    private void parseWsdl(URL wsdlUrl) throws WSSPolicyException {
        try {
            WSDLFactory wsdlFactory = WSDLFactory.newInstance();
            WSDLReader reader = wsdlFactory.newWSDLReader();
            reader.setFeature("javax.wsdl.verbose", false);
            wsdlDefinition = reader.readWSDL(wsdlUrl.toString());
            operationPolicies = findPoliciesByOperation(wsdlDefinition);
        } catch (WSDLException e) {
            throw new WSSPolicyException(e.getMessage(), e);
        }
    }

    //todo enforce uniqueness of operation names to prevent SOAPAction spoofing.
    private void parseWsdl(Document document) throws WSSPolicyException {
        try {
            WSDLFactory wsdlFactory = WSDLFactory.newInstance();
            WSDLReader reader = wsdlFactory.newWSDLReader();
            reader.setFeature("javax.wsdl.verbose", false);
            wsdlDefinition = reader.readWSDL(document.getDocumentURI(), document);
            operationPolicies = findPoliciesByOperation(wsdlDefinition);
        } catch (WSDLException e) {
            throw new WSSPolicyException(e.getMessage(), e);
        }
    }

    private List<OperationPolicy> findPoliciesByOperation(Definition wsdlDefinition) throws WSSPolicyException {

        List<OperationPolicy> operationPolicyList = new ArrayList<OperationPolicy>();
        @SuppressWarnings("unchecked")
        Iterator<Map.Entry> services = wsdlDefinition.getAllServices().entrySet().iterator();
        while (services.hasNext()) {
            @SuppressWarnings("unchecked")
            Map.Entry<QName, Service> serviceEntry = services.next();
            Service service = serviceEntry.getValue();
            @SuppressWarnings("unchecked")
            Iterator<Map.Entry> ports = service.getPorts().entrySet().iterator();
            while (ports.hasNext()) {
                @SuppressWarnings("unchecked")
                Map.Entry<QName, Port> portEntry = ports.next();
                Port port = portEntry.getValue();
                Binding binding = port.getBinding();

                @SuppressWarnings("unchecked")
                List<BindingOperation> bindingOperations = binding.getBindingOperations();
                for (int i = 0; i < bindingOperations.size(); i++) {
                    BindingOperation bindingOperation = bindingOperations.get(i);

                    Operation operation = bindingOperation.getOperation();

                    OperationPolicy operationPolicy = new OperationPolicy(operation.getName());
                    operationPolicyList.add(operationPolicy);

                    @SuppressWarnings("unchecked")
                    List<ExtensibilityElement> extensibilityElements = bindingOperation.getExtensibilityElements();
                    for (int j = 0; j < extensibilityElements.size(); j++) {
                        ExtensibilityElement extensibilityElement = extensibilityElements.get(j);
                        if (extensibilityElement instanceof SOAPOperation) {
                            SOAPOperation soapOperation = (SOAPOperation) extensibilityElement;
                            String soapActionUri = soapOperation.getSoapActionURI();
                            operationPolicy.setOperationAction(soapActionUri);
                            operationPolicy.setSoapMessageVersionNamespace(WSSConstants.NS_SOAP11);
                        } else if (extensibilityElement instanceof SOAP12Operation) {
                            SOAP12Operation soap12Operation = (SOAP12Operation) extensibilityElement;
                            String soapActionUri = soap12Operation.getSoapActionURI();
                            operationPolicy.setOperationAction(soapActionUri);
                            operationPolicy.setSoapMessageVersionNamespace(WSSConstants.NS_SOAP12);
                        }
                    }

                    Policy policy = getPolicy(service, port, binding, bindingOperation, operation);
                    operationPolicy.setPolicy(policy.normalize(true));
                }
            }
        }
        return operationPolicyList;
    }

    private Policy getPolicy(Service service, Port port, Binding binding, BindingOperation bindingOperation, Operation operation) throws WSSPolicyException {
        List<Policy> policies = new ArrayList<Policy>();

        Policy servicePolicy = findPolicies(service);
        if (servicePolicy != null) {
            policies.add(servicePolicy);
        }
        Policy portPolicy = findPolicies(port);
        if (portPolicy != null) {
            policies.add(portPolicy);
        }
        Policy bindingPolicy = findPolicies(binding);
        if (bindingPolicy != null) {
            policies.add(bindingPolicy);
        }

        Policy bindingOperationPolicy = findPolicies(bindingOperation);
        if (bindingOperationPolicy != null) {
            policies.add(bindingOperationPolicy);
        }

        Policy bindingOperationInputPolicy = findPolicies(bindingOperation.getBindingInput());
        if (bindingOperationInputPolicy != null) {
            policies.add(bindingOperationInputPolicy);
        }

        Policy portTypePolicy = findPortTypePolicy(binding, operation);
        if (portTypePolicy != null) {
            policies.add(portTypePolicy);
        }

        if (policies.size() == 0) {
            return new Policy();
        }

        Policy mergedPolicy = policies.get(0);
        for (int i = 1; i < policies.size(); i++) {
            Policy policy = policies.get(i);
            mergedPolicy = mergedPolicy.merge(policy);
        }
        return mergedPolicy;
    }

    private Policy findPortTypePolicy(Binding binding, Operation operation) throws WSSPolicyException {

        List<Policy> policies = new ArrayList<Policy>();

        PortType portType = binding.getPortType();
        Policy portTypePolicy = findPolicies(portType);
        if (portTypePolicy != null) {
            policies.add(portTypePolicy);
        }

        @SuppressWarnings("unchecked")
        List<Operation> operations = portType.getOperations();
        for (int i = 0; i < operations.size(); i++) {
            Operation portTypeOperation = operations.get(i);
            if (portTypeOperation.getName().equals(operation.getName())) {
                Policy operationPolicy = findPolicies(portTypeOperation);
                if (operationPolicy != null) {
                    policies.add(operationPolicy);
                }

                Policy inputPolicy = findPolicies(portTypeOperation.getInput());
                if (inputPolicy != null) {
                    policies.add(inputPolicy);
                }

                Policy messagePolicy = findPolicies(portTypeOperation.getInput().getMessage());
                if (messagePolicy != null) {
                    policies.add(messagePolicy);
                }
            }
        }

        if (policies.size() == 0) {
            return new Policy();
        }

        Policy mergedPolicy = policies.get(0);
        for (int i = 1; i < policies.size(); i++) {
            Policy policy = policies.get(i);
            mergedPolicy = mergedPolicy.merge(policy);
        }
        return mergedPolicy;
    }

    private Policy findPolicies(WSDLElement wsdlElement) throws WSSPolicyException {
        if (wsdlElement == null) {
            return new Policy();
        }

        List<Policy> policies = new ArrayList<Policy>();

        @SuppressWarnings("unchecked")
        List<ExtensibilityElement> extensibilityElements = wsdlElement.getExtensibilityElements();
        for (int i = 0; i < extensibilityElements.size(); i++) {
            ExtensibilityElement extensibilityElement = extensibilityElements.get(i);
            if (extensibilityElement instanceof UnknownExtensibilityElement) {
                UnknownExtensibilityElement unknownExtensibilityElement = (UnknownExtensibilityElement) extensibilityElement;
                if (unknownExtensibilityElement.getElementType().getLocalPart().equals("PolicyReference")) {
                    String uri = unknownExtensibilityElement.getElement().getAttribute("URI").substring(1);
                    NodeList policyNodeList = unknownExtensibilityElement.getElement().getOwnerDocument().getElementsByTagNameNS("*", "Policy");

                    boolean found = false;
                    for (int j = 0; j < policyNodeList.getLength(); j++) {
                        Element element = (Element) policyNodeList.item(j);
                        String refUri = element.getAttributeNS("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Id");
                        if (refUri != null && refUri.equals(uri)) {
                            found = true;
                            Policy policy = parsePolicy(element);
                            policies.add(policy);
                            break;
                        }
                    }
                    if (!found) {
                        throw new WSSPolicyException("Referenced Policy not found " + uri);
                    }
                } else if (unknownExtensibilityElement.getElementType().getLocalPart().equals("Policy")) {
                    Element element = unknownExtensibilityElement.getElement();
                    Policy policy = parsePolicy(element);
                    policies.add(policy);
                }
            }
        }

        if (policies.size() == 0) {
            return new Policy();
        }

        Policy mergedPolicy = policies.get(0);
        for (int i = 1; i < policies.size(); i++) {
            Policy policy = policies.get(i);
            mergedPolicy = mergedPolicy.merge(policy);
        }
        return mergedPolicy;
    }

    private Policy parsePolicy(Element element) throws WSSPolicyException {
        if (elementPolicyCache.containsKey(element)) {
            return elementPolicyCache.get(element);
        }
        PolicyBuilder policyBuilder = new PolicyBuilder();
        registerDefaultBuilders(policyBuilder.getAssertionBuilderFactory());
        Policy policy = policyBuilder.getPolicy(element);
        elementPolicyCache.put(element, policy);
        return policy;
    }

    private void registerDefaultBuilders(AssertionBuilderFactory assertionBuilderFactory) {
        for (int i = 0; i < assertionBuilders.size(); i++) {
            AssertionBuilder assertionBuilder = assertionBuilders.get(i);
            assertionBuilderFactory.registerBuilder(assertionBuilder);
        }
    }

    public PolicyEnforcer newPolicyEnforcer(String soapAction) throws WSSPolicyException {
        return new PolicyEnforcer(this.operationPolicies, soapAction);
    }
}
