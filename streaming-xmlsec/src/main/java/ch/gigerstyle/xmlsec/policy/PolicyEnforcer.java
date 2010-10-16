package ch.gigerstyle.xmlsec.policy;

import ch.gigerstyle.xmlsec.ext.XMLSecurityException;
import ch.gigerstyle.xmlsec.impl.util.FiFoQueue;
import ch.gigerstyle.xmlsec.policy.assertionStates.AssertionState;
import ch.gigerstyle.xmlsec.policy.secpolicy.WSSPolicyException;
import ch.gigerstyle.xmlsec.policy.secpolicy.model.AbstractSecurityAssertion;
import ch.gigerstyle.xmlsec.policy.secpolicybuilder.*;
import ch.gigerstyle.xmlsec.securityEvent.OperationSecurityEvent;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEvent;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEventListener;
import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.llom.factory.OMXMLBuilderFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.neethi.*;
import org.apache.neethi.builders.AssertionBuilder;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.wsdl.*;
import javax.wsdl.extensions.ExtensibilityElement;
import javax.wsdl.extensions.UnknownExtensibilityElement;
import javax.wsdl.extensions.soap.SOAPOperation;
import javax.wsdl.extensions.soap12.SOAP12Operation;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.dom.DOMSource;
import java.util.*;

/**
 * User: giger
 * Date: Sep 2, 2010
 * Time: 8:07:59 PM
 * Copyright 2010 Marc Giger gigerstyle@gmx.ch
 * <p/>
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 * <p/>
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * <p/>
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */
public class PolicyEnforcer implements SecurityEventListener {

    private static final transient Log logger = LogFactory.getLog(PolicyEnforcer.class);

    //private static final QName TAG_wsdlsoap_operation = new QName("http://schemas.xmlsoap.org/wsdl/soap/", "operation");

    private String soapAction = null;
    private Definition wsdlDefinition;
    private boolean operationPolicyFound = false;

    private Policy policy;
    private Map<SecurityEvent.Event, Collection<AssertionState>> assertionStateMap;

    private FiFoQueue<SecurityEvent> securityEventQueue = new FiFoQueue<SecurityEvent>();

    public PolicyEnforcer(Definition wsdlDefinition, String soapAction) throws WSSPolicyException {
        this.soapAction = soapAction;
        this.wsdlDefinition = wsdlDefinition;

        if (soapAction != null && !soapAction.equals("")) {
            policy = findPolicyBySOAPAction(soapAction);
            assertionStateMap = initAssertionStateMap();
            buildAssertionStateMap(policy, assertionStateMap);
        }
    }

    private Policy parsePolicy(Element element) throws WSSPolicyException {
        XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        XMLStreamReader xmlStreamReader;
        try {
            xmlStreamReader = xmlInputFactory.createXMLStreamReader(new DOMSource(element));
        } catch (XMLStreamException e) {
            throw new WSSPolicyException(e.getMessage(), e);
        }
        OMElement omElement = OMXMLBuilderFactory.createStAXOMBuilder(OMAbstractFactory.getOMFactory(), xmlStreamReader).getDocumentElement();
        return PolicyEngine.getPolicy(omElement);
    }

    private Policy findPolicyBySOAPAction(String action) throws WSSPolicyException {
        Iterator<Map.Entry> services = wsdlDefinition.getAllServices().entrySet().iterator();
        while (services.hasNext()) {
            Map.Entry<QName, Service> serviceEntry = services.next();
            Service service = serviceEntry.getValue();

            Iterator<Map.Entry> ports = service.getPorts().entrySet().iterator();
            while (ports.hasNext()) {
                Map.Entry<QName, Port> portEntry = ports.next();
                Port port = portEntry.getValue();
                Binding binding = port.getBinding();

                List<BindingOperation> bindingOperations = binding.getBindingOperations();
                for (int i = 0; i < bindingOperations.size(); i++) {
                    BindingOperation bindingOperation = bindingOperations.get(i);

                    Operation operation = bindingOperation.getOperation();
                    List<ExtensibilityElement> extensibilityElements = operation.getExtensibilityElements();
                    for (int j = 0; j < extensibilityElements.size(); j++) {
                        ExtensibilityElement extensibilityElement = extensibilityElements.get(j);
                        if (extensibilityElement instanceof SOAPOperation) {
                            SOAPOperation soapOperation = (SOAPOperation) extensibilityElement;
                            String soapActionUri = soapOperation.getSoapActionURI();
                            if (soapActionUri != null && soapActionUri.equals(action)) {
                                Policy policy = getPolicy(service, port, binding, bindingOperation, operation);
                                return (Policy) policy.normalize(true);
                            }
                        } else if (extensibilityElement instanceof SOAP12Operation) {
                            SOAP12Operation soap12Operation = (SOAP12Operation) extensibilityElement;
                            String soapActionUri = soap12Operation.getSoapActionURI();
                            if (soapActionUri != null && soapActionUri.equals(action)) {
                                Policy policy = getPolicy(service, port, binding, bindingOperation, operation);
                                return (Policy) policy.normalize(true);
                            }
                        }
                    }
                }
            }
        }
        throw new WSSPolicyException("No policy found for SOAPAction: " + action);
    }

    private Policy findPolicyByOperation(String operationAction) throws WSSPolicyException {
        Iterator<Map.Entry> services = wsdlDefinition.getAllServices().entrySet().iterator();
        while (services.hasNext()) {
            Map.Entry<QName, Service> serviceEntry = services.next();
            Service service = serviceEntry.getValue();

            Iterator<Map.Entry> ports = service.getPorts().entrySet().iterator();
            while (ports.hasNext()) {
                Map.Entry<QName, Port> portEntry = ports.next();
                Port port = portEntry.getValue();
                Binding binding = port.getBinding();

                List<BindingOperation> bindingOperations = binding.getBindingOperations();
                for (int i = 0; i < bindingOperations.size(); i++) {
                    BindingOperation bindingOperation = bindingOperations.get(i);

                    Operation operation = bindingOperation.getOperation();
                    if (operation.getName().equals(operationAction)) {
                        Policy policy = getPolicy(service, port, binding, bindingOperation, operation);
                        return (Policy) policy.normalize(true);
                    }
                }
            }
        }
        throw new WSSPolicyException("No policy found for operation: " + operationAction);
    }

    private Map<SecurityEvent.Event, Collection<AssertionState>> initAssertionStateMap() {
        Map<SecurityEvent.Event, Collection<AssertionState>> assertionStateMap = new HashMap<SecurityEvent.Event, Collection<AssertionState>>();

        for (SecurityEvent.Event securityEvent : SecurityEvent.Event.values()) {
            assertionStateMap.put(securityEvent, new ArrayList<AssertionState>());
        }

        return assertionStateMap;
    }

    private void buildAssertionStateMap(PolicyComponent policyComponent, Map<SecurityEvent.Event, Collection<AssertionState>> assertionStateMap) throws WSSPolicyException {
        if (policyComponent instanceof PolicyOperator) {
            PolicyOperator policyOperator = (PolicyOperator) policyComponent;
            List<PolicyComponent> policyComponents = policyOperator.getPolicyComponents();
            for (int i = 0; i < policyComponents.size(); i++) {
                PolicyComponent curPolicyComponent = policyComponents.get(i);
                buildAssertionStateMap(curPolicyComponent, assertionStateMap);
            }
        } else if (policyComponent instanceof AbstractSecurityAssertion) {
            AbstractSecurityAssertion abstractSecurityAssertion = (AbstractSecurityAssertion) policyComponent;
            abstractSecurityAssertion.getAssertions(assertionStateMap);
        } else {
            throw new WSSPolicyException("Unknown PolicyComponent: " + policyComponent + " " + policyComponent.getType());
        }
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
            return null;
        }

        Policy mergedPolicy = policies.get(0);
        for (int i = 1; i < policies.size(); i++) {
            Policy policy = policies.get(i);
            mergedPolicy = mergedPolicy.merge(policy);
        }
        return mergedPolicy;
    }

    //todo differentiate between input, output and faults all over the place not just this method

    private Policy findPortTypePolicy(Binding binding, Operation operation) throws WSSPolicyException {

        List<Policy> policies = new ArrayList<Policy>();

        PortType portType = binding.getPortType();
        Policy portTypePolicy = findPolicies(portType);
        if (portTypePolicy != null) {
            policies.add(portTypePolicy);
        }

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
            return null;
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
            return null;
        }

        List<Policy> policies = new ArrayList<Policy>();

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
                            System.out.println("Found PolicyReference " + refUri);
                            Policy policy = parsePolicy(element);
                            policies.add(policy);
                            break;
                        }
                    }
                    if (!found) {
                        throw new WSSPolicyException("Referenced Policy not found " + uri);
                    }
                } else if (unknownExtensibilityElement.getElementType().getLocalPart().equals("Policy")) {
                    System.out.println("Found policy in " + unknownExtensibilityElement);
                    Element element = unknownExtensibilityElement.getElement();
                    Policy policy = parsePolicy(element);
                    policies.add(policy);
                }
            }
        }

        if (policies.size() == 0) {
            return null;
        }

        Policy mergedPolicy = policies.get(0);
        for (int i = 1; i < policies.size(); i++) {
            Policy policy = policies.get(i);
            mergedPolicy = mergedPolicy.merge(policy);
        }
        return mergedPolicy;
    }

    private void verifyPolicy(SecurityEvent securityEvent) throws WSSPolicyException {
        /*
        try {
            verifyPolicy(policy, securityEvent);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new WSSPolicyException(e.getMessage(), e);
        }
        */
        Collection<AssertionState> assertionStates = assertionStateMap.get(securityEvent.getSecurityEventType());
        if (assertionStates != null && assertionStates.size() > 0) {
            int notAssertedCount = 0;
            for (Iterator<AssertionState> assertionStateIterator = assertionStates.iterator(); assertionStateIterator.hasNext();) {
                AssertionState assertionState = assertionStateIterator.next();
                boolean asserted = assertionState.assertEvent(securityEvent);
                if (!asserted) {
                    notAssertedCount++;
                }
            }
            if (notAssertedCount == assertionStates.size()) {
                throw new WSSPolicyException("No policy alternative could be satisfied");
            }
        }
    }

    /*
    private void verifyPolicy(PolicyComponent policyComponent, SecurityEvent securityEvent) throws WSSPolicyException, PolicyViolationException {
        if (policyComponent instanceof PolicyOperator) {
            PolicyOperator policyOperator = (PolicyOperator)policyComponent;

            int violationCount = 0;

            List<PolicyComponent> policyComponents = policyOperator.getPolicyComponents();
            for (int i = 0; i < policyComponents.size(); i++) {
                PolicyComponent curPolicyComponent = policyComponents.get(i);
                try {
                    verifyPolicy(curPolicyComponent, securityEvent);
                } catch (PolicyViolationException e) {
                    if (!(policyOperator instanceof ExactlyOne)) {
                        throw e;
                    } else {
                        violationCount++;
                        //no alternative could be satisfied
                        if (violationCount == policyComponents.size()) {
                            throw e;
                        }
                    }
                }
            }
        } else if (policyComponent instanceof AbstractSecurityAssertion) {
            AbstractSecurityAssertion abstractSecurityAssertion = (AbstractSecurityAssertion)policyComponent;
            abstractSecurityAssertion.assertPolicy(securityEvent);
        } else {
            throw new WSSPolicyException("Unknown PolicyComponent: " + policyComponent + " " + policyComponent.getType());
        }
    }
    */

    private void verifyPolicy() throws WSSPolicyException, PolicyViolationException {
        boolean isAsserted = verifyPolicy(policy);
        if (!isAsserted) {
            throw new PolicyViolationException("No policy alternative could be satisfied");
        }
    }

    private boolean verifyPolicy(PolicyComponent policyComponent) throws WSSPolicyException, PolicyViolationException {
        /*
        boolean isAsserted = false;
        Iterator<List<PolicyComponent>> policyComponentIterator = policy.getAlternatives();
        while (policyComponentIterator.hasNext() && isAsserted == false) {
            List<PolicyComponent> policyComponent = policyComponentIterator.next();
            for (int i = 0; i < policyComponent.size(); i++) {
                AbstractSecurityAssertion abstractSecurityAssertion = (AbstractSecurityAssertion)policyComponent.get(i);
                System.out.println("AbstractSecurityAssertion: " + abstractSecurityAssertion);
                isAsserted = abstractSecurityAssertion.isAsserted();
            }
        }
        if (!isAsserted) {
            throw new PolicyViolationException("No policy alternative could be satisfied");
        }
        */

        if (policyComponent instanceof PolicyOperator) {
            PolicyOperator policyOperator = (PolicyOperator) policyComponent;
            boolean isExactlyOne = policyOperator instanceof ExactlyOne;
            List<PolicyComponent> policyComponents = policyOperator.getPolicyComponents();

            boolean isAsserted = false;
            for (int i = 0; i < policyComponents.size(); i++) {
                PolicyComponent curPolicyComponent = policyComponents.get(i);
                isAsserted = verifyPolicy(curPolicyComponent);
                if (isExactlyOne && isAsserted) {
                    return true; //a satisfied alternative is found
                } else if (!isExactlyOne && !isAsserted) {
                    return false;
                }
            }
            return isAsserted;
        } else if (policyComponent instanceof AbstractSecurityAssertion) {
            AbstractSecurityAssertion abstractSecurityAssertion = (AbstractSecurityAssertion) policyComponent;
            return abstractSecurityAssertion.isAsserted(assertionStateMap);
        } else if (policyComponent == null) {
            throw new WSSPolicyException("Policy not found");
        } else {
            throw new WSSPolicyException("Unknown PolicyComponent: " + policyComponent + " " + policyComponent.getType());
        }
    }

    //multiple threads can call this method concurrently -> synchronize access

    public synchronized void registerSecurityEvent(SecurityEvent securityEvent) throws XMLSecurityException {
        System.out.println("Security Event: " + securityEvent);
        if (operationPolicyFound) {
            verifyPolicy(securityEvent);
        } else {

            if (securityEvent.getSecurityEventType().equals(SecurityEvent.Event.Operation)) {
                policy = findPolicyByOperation(((OperationSecurityEvent) securityEvent).getOperation().getLocalPart());
                assertionStateMap = initAssertionStateMap();
                buildAssertionStateMap(policy, assertionStateMap);
                operationPolicyFound = true;

                while (!securityEventQueue.isEmpty()) {
                    SecurityEvent prevSecurityEvent = securityEventQueue.dequeue();
                    verifyPolicy(prevSecurityEvent);
                }

            } else {
                //queue event until policy is resolved
                securityEventQueue.enqueue(securityEvent);
            }
        }
    }

    public void doFinal() throws PolicyViolationException {
        try {
            verifyPolicy();
        } catch (Exception e) {
            throw new PolicyViolationException(e);
        }
    }

    static {
        addAssertionBuilder(new AlgorithmSuiteBuilder());
        addAssertionBuilder(new AsymmetricBindingBuilder());
        addAssertionBuilder(new ContentEncryptedElementsBuilder());
        addAssertionBuilder(new EncryptedElementsBuilder());
        addAssertionBuilder(new EncryptedPartsBuilder());
        addAssertionBuilder(new HttpsTokenBuilder());
        addAssertionBuilder(new InitiatorTokenBuilder());
        addAssertionBuilder(new IssuedTokenBuilder());
        addAssertionBuilder(new LayoutBuilder());
        addAssertionBuilder(new ProtectionTokenBuilder());
        addAssertionBuilder(new RecipientTokenBuilder());
        addAssertionBuilder(new RequiredElementsBuilder());
        addAssertionBuilder(new RequiredPartsBuilder());
        addAssertionBuilder(new SecureConversationTokenBuilder());
        addAssertionBuilder(new SignedElementsBuilder());
        addAssertionBuilder(new SignedPartsBuilder());
        addAssertionBuilder(new SupportingTokensBuilder());
        addAssertionBuilder(new SymmetricBindingBuilder());
        addAssertionBuilder(new TransportBindingBuilder());
        addAssertionBuilder(new TransportTokenBuilder());
        addAssertionBuilder(new Trust13Builder());
        addAssertionBuilder(new UsernameTokenBuilder());
        addAssertionBuilder(new WSS10Builder());
        addAssertionBuilder(new WSS11Builder());
        addAssertionBuilder(new X509TokenBuilder());
    }

    private static final void addAssertionBuilder(AssertionBuilder assertionBuilder) {
        QName[] knownElements = assertionBuilder.getKnownElements();
        for (int i = 0; i < knownElements.length; i++) {
            QName knownElement = knownElements[i];
            PolicyEngine.registerBuilder(knownElement, assertionBuilder);
        }
    }
}
