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

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.wsdl.Binding;
import javax.wsdl.BindingOperation;
import javax.wsdl.Definition;
import javax.wsdl.Operation;
import javax.wsdl.Port;
import javax.wsdl.PortType;
import javax.wsdl.Service;
import javax.wsdl.WSDLElement;
import javax.wsdl.WSDLException;
import javax.wsdl.extensions.ExtensibilityElement;
import javax.wsdl.extensions.UnknownExtensibilityElement;
import javax.wsdl.extensions.soap.SOAPOperation;
import javax.wsdl.extensions.soap12.SOAP12Operation;
import javax.wsdl.factory.WSDLFactory;
import javax.wsdl.xml.WSDLReader;
import javax.xml.namespace.QName;

import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyBuilder;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.wss4j.common.WSSPolicyException;
import org.apache.wss4j.policy.builders.AlgorithmSuiteBuilder;
import org.apache.wss4j.policy.builders.AsymmetricBindingBuilder;
import org.apache.wss4j.policy.builders.BootstrapPolicyBuilder;
import org.apache.wss4j.policy.builders.ContentEncryptedElementsBuilder;
import org.apache.wss4j.policy.builders.EncryptedElementsBuilder;
import org.apache.wss4j.policy.builders.EncryptedPartsBuilder;
import org.apache.wss4j.policy.builders.EncryptionTokenBuilder;
import org.apache.wss4j.policy.builders.HttpsTokenBuilder;
import org.apache.wss4j.policy.builders.InitiatorEncryptionTokenBuilder;
import org.apache.wss4j.policy.builders.InitiatorSignatureTokenBuilder;
import org.apache.wss4j.policy.builders.InitiatorTokenBuilder;
import org.apache.wss4j.policy.builders.IssuedTokenBuilder;
import org.apache.wss4j.policy.builders.KerberosTokenBuilder;
import org.apache.wss4j.policy.builders.KeyValueTokenBuilder;
import org.apache.wss4j.policy.builders.LayoutBuilder;
import org.apache.wss4j.policy.builders.ProtectionTokenBuilder;
import org.apache.wss4j.policy.builders.RecipientEncryptionTokenBuilder;
import org.apache.wss4j.policy.builders.RecipientSignatureTokenBuilder;
import org.apache.wss4j.policy.builders.RecipientTokenBuilder;
import org.apache.wss4j.policy.builders.RelTokenBuilder;
import org.apache.wss4j.policy.builders.RequiredElementsBuilder;
import org.apache.wss4j.policy.builders.RequiredPartsBuilder;
import org.apache.wss4j.policy.builders.SamlTokenBuilder;
import org.apache.wss4j.policy.builders.SecureConversationTokenBuilder;
import org.apache.wss4j.policy.builders.SecurityContextTokenBuilder;
import org.apache.wss4j.policy.builders.SignatureTokenBuilder;
import org.apache.wss4j.policy.builders.SignedElementsBuilder;
import org.apache.wss4j.policy.builders.SignedPartsBuilder;
import org.apache.wss4j.policy.builders.SpnegoContextTokenBuilder;
import org.apache.wss4j.policy.builders.SupportingTokensBuilder;
import org.apache.wss4j.policy.builders.SymmetricBindingBuilder;
import org.apache.wss4j.policy.builders.TransportBindingBuilder;
import org.apache.wss4j.policy.builders.TransportTokenBuilder;
import org.apache.wss4j.policy.builders.Trust10Builder;
import org.apache.wss4j.policy.builders.Trust13Builder;
import org.apache.wss4j.policy.builders.UsernameTokenBuilder;
import org.apache.wss4j.policy.builders.WSS10Builder;
import org.apache.wss4j.policy.builders.WSS11Builder;
import org.apache.wss4j.policy.builders.X509TokenBuilder;
import org.apache.wss4j.stax.ext.WSSConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * PolicyEnforcerFactory builds a map of all the possible effective Policies
 * and caches them for reuse
 */
public class PolicyEnforcerFactory {

    protected static final transient org.slf4j.Logger log = 
        org.slf4j.LoggerFactory.getLogger(PolicyEnforcerFactory.class);

    private final List<AssertionBuilder<Element>> assertionBuilders;

    private Definition wsdlDefinition;
    private List<OperationPolicy> operationPolicies;
    private final Map<Element, Policy> elementPolicyCache;

    private PolicyEnforcerFactory(List<AssertionBuilder<Element>> customAssertionBuilders) {
        elementPolicyCache = new HashMap<Element, Policy>();

        assertionBuilders = new ArrayList<AssertionBuilder<Element>>();
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
        assertionBuilders.add(new BootstrapPolicyBuilder());
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
                AssertionBuilder<Element> customAssertionBuilder = customAssertionBuilders.get(i);
                assertionBuilders.add(customAssertionBuilder);
            }
        }
    }

    public static PolicyEnforcerFactory newInstance(URL wsdlUrl) throws WSSPolicyException {
        return newInstance(wsdlUrl, null);
    }

    public static PolicyEnforcerFactory newInstance(URL wsdlUrl, List<AssertionBuilder<Element>> customAssertionBuilders)
            throws WSSPolicyException {

        PolicyEnforcerFactory policyEnforcerFactory = new PolicyEnforcerFactory(customAssertionBuilders);
        policyEnforcerFactory.parseWsdl(wsdlUrl);
        return policyEnforcerFactory;
    }

    public static PolicyEnforcerFactory newInstance(Document document) throws WSSPolicyException {
        return newInstance(document, null);
    }

    public static PolicyEnforcerFactory newInstance(Document document, List<AssertionBuilder<Element>> customAssertionBuilders)
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
        @SuppressWarnings({"unchecked", "rawtypes"})
        Iterator<Map.Entry> services = wsdlDefinition.getAllServices().entrySet().iterator();
        while (services.hasNext()) {
            @SuppressWarnings("unchecked")
            Map.Entry<QName, Service> serviceEntry = services.next();
            Service service = serviceEntry.getValue();
            @SuppressWarnings({"unchecked", "rawtypes"})
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

                    OperationPolicy operationPolicy = 
                        new OperationPolicy(new QName(null, operation.getName()));
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
                    String uri = unknownExtensibilityElement.getElement().getAttributeNS(null, "URI").substring(1);
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
            AssertionBuilder<Element> assertionBuilder = assertionBuilders.get(i);
            assertionBuilderFactory.registerBuilder(assertionBuilder);
        }
    }

    /**
     * creates a new PolicyEnforcer instance
     * @param soapAction The requested soapAction of the actual request
     * @param initiator Boolean flag to tell the engine if it is running in client or server mode
     * @param roleOrActor The actor or role of the security processing. Must be set to the same value as WSSSecurityProperties#setActor()
     * @param attachmentCount The number of Attachments received in the message
     * @return the newly created PolicyEnforcer instance
     * @throws WSSPolicyException
     */
    public PolicyEnforcer newPolicyEnforcer(String soapAction, boolean initiator, 
                                            String roleOrActor, int attachmentCount) throws WSSPolicyException {
        return new PolicyEnforcer(this.operationPolicies, soapAction, initiator, roleOrActor, attachmentCount);
    }
}
