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
package org.swssf.policy;

import org.swssf.ext.Constants;
import org.swssf.policy.secpolicy.WSSPolicyException;
import org.swssf.policy.secpolicybuilder.*;
import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.llom.factory.OMXMLBuilderFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
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
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.dom.DOMSource;
import java.net.URL;
import java.util.*;

/**
 * PolicyEnforcerFactory builds a map of all the possible effective Policies
 * and caches them for reuse
 * @author $Author: giger $
 * @version $Revision: 281 $ $Date: 2011-01-04 21:15:27 +0100 (Tue, 04 Jan 2011) $
 */
public class PolicyEnforcerFactory {

    protected static final transient Log log = LogFactory.getLog(PolicyEnforcerFactory.class);

    private Definition wsdlDefinition;

    private List<OperationPolicy> operationPolicies;

    private Map<Element, Policy> elementPolicyCache;

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

    private PolicyEnforcerFactory() {
        elementPolicyCache = new HashMap<Element, Policy>();
    }

    public static PolicyEnforcerFactory newInstance(URL wsdlUrl) throws WSSPolicyException {
        PolicyEnforcerFactory policyEnforcerFactory = new PolicyEnforcerFactory();
        policyEnforcerFactory.parseWsdl(wsdlUrl);
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

    private List<OperationPolicy> findPoliciesByOperation(Definition wsdlDefinition) throws WSSPolicyException {

        List<OperationPolicy> operationPolicyList = new ArrayList<OperationPolicy>();

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

                    OperationPolicy operationPolicy = new OperationPolicy(operation.getName());
                    operationPolicyList.add(operationPolicy);

                    List<ExtensibilityElement> extensibilityElements = bindingOperation.getExtensibilityElements();
                    for (int j = 0; j < extensibilityElements.size(); j++) {
                        ExtensibilityElement extensibilityElement = extensibilityElements.get(j);
                        if (extensibilityElement instanceof SOAPOperation) {
                            SOAPOperation soapOperation = (SOAPOperation) extensibilityElement;
                            String soapActionUri = soapOperation.getSoapActionURI();
                            operationPolicy.setOperationAction(soapActionUri);
                            operationPolicy.setSoapMessageVersionNamespace(Constants.NS_SOAP11);
                        } else if (extensibilityElement instanceof SOAP12Operation) {
                            SOAP12Operation soap12Operation = (SOAP12Operation) extensibilityElement;
                            String soapActionUri = soap12Operation.getSoapActionURI();
                            operationPolicy.setOperationAction(soapActionUri);
                            operationPolicy.setSoapMessageVersionNamespace(Constants.NS_SOAP12);
                        }
                    }

                    Policy policy = getPolicy(service, port, binding, bindingOperation, operation);
                    operationPolicy.setPolicy((Policy) policy.normalize(true));
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
        XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        XMLStreamReader xmlStreamReader;
        try {
            xmlStreamReader = xmlInputFactory.createXMLStreamReader(new DOMSource(element));
        } catch (XMLStreamException e) {
            throw new WSSPolicyException(e.getMessage(), e);
        }
        OMElement omElement = OMXMLBuilderFactory.createStAXOMBuilder(OMAbstractFactory.getOMFactory(), xmlStreamReader).getDocumentElement();
        Policy policy = PolicyEngine.getPolicy(omElement);
        elementPolicyCache.put(element, policy);
        return policy;
    }

    public PolicyEnforcer newPolicyEnforcer(String soapAction) throws WSSPolicyException {
        return new PolicyEnforcer(this.operationPolicies, soapAction);
    }
}
