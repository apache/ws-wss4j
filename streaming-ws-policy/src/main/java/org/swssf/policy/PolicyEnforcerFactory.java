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
package org.swssf.policy;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.llom.factory.OMXMLBuilderFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.swssf.ext.Constants;
import org.swssf.impl.util.ConcreteLSInput;
import org.swssf.policy.secpolicy.WSSPolicyException;
import org.swssf.policy.secpolicybuilder.*;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.w3c.dom.ls.LSInput;
import org.w3c.dom.ls.LSResourceResolver;
import org.xml.sax.SAXException;

import javax.wsdl.*;
import javax.wsdl.extensions.ExtensibilityElement;
import javax.wsdl.extensions.UnknownExtensibilityElement;
import javax.wsdl.extensions.soap.SOAPOperation;
import javax.wsdl.extensions.soap12.SOAP12Operation;
import javax.wsdl.factory.WSDLFactory;
import javax.wsdl.xml.WSDLReader;
import javax.xml.XMLConstants;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;
import javax.xml.validation.Validator;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
    private static final TransformerFactory TRANSFORMER_FACTORY = TransformerFactory.newInstance();

    private static Schema schemas;
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

        List<Source> sourceList = new ArrayList<Source>();

        SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
        sourceList.add(new StreamSource(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/ws-securitypolicy-200507.xsd")));
        sourceList.add(new StreamSource(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/ws-securitypolicy-1.2.xsd")));
        sourceList.add(new StreamSource(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/ws-securitypolicy-1.2-errata-cd-01.xsd")));
        sourceList.add(new StreamSource(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/ws-securitypolicy-1.3.xsd")));
        sourceList.add(new StreamSource(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/ws-securitypolicy-200802.xsd")));

        try {
            schemaFactory.setResourceResolver(new LSResourceResolver() {
                public LSInput resolveResource(String type, String namespaceURI, String publicId, String systemId, String baseURI) {
                    if ("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setSystemId(systemId);
                        concreteLSInput.setBaseURI(baseURI);
                        concreteLSInput.setByteStream(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/oasis-200401-wss-wssecurity-secext-1.0.xsd"));
                        return concreteLSInput;
                    } else if ("http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setSystemId(systemId);
                        concreteLSInput.setBaseURI(baseURI);
                        concreteLSInput.setByteStream(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/oasis-wss-wssecurity-secext-1.1.xsd"));
                        return concreteLSInput;
                    } else if ("http://www.w3.org/TR/xmldsig-core/xmldsig-core-schema.xsd".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setSystemId(systemId);
                        concreteLSInput.setBaseURI(baseURI);
                        concreteLSInput.setByteStream(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/xmldsig-core-schema.xsd"));
                        return concreteLSInput;
                    } else if ("http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setSystemId(systemId);
                        concreteLSInput.setBaseURI(baseURI);
                        concreteLSInput.setByteStream(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/oasis-200401-wss-wssecurity-utility-1.0.xsd"));
                        return concreteLSInput;
                    } else if ("http://www.w3.org/2005/08/addressing".equals(systemId) || "http://www.w3.org/2006/03/addressing/ws-addr.xsd".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setSystemId(systemId);
                        concreteLSInput.setBaseURI(baseURI);
                        concreteLSInput.setByteStream(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/ws-addr200508.xsd"));
                        return concreteLSInput;
                    } else if ("http://schemas.xmlsoap.org/ws/2004/08/addressing".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setSystemId(systemId);
                        concreteLSInput.setBaseURI(baseURI);
                        concreteLSInput.setByteStream(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/ws-addr200408.xsd"));
                        return concreteLSInput;
                    } else if ("http://schemas.xmlsoap.org/ws/2004/09/policy/ws-policy.xsd".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setSystemId(systemId);
                        concreteLSInput.setBaseURI(baseURI);
                        concreteLSInput.setByteStream(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/ws-policy-200409.xsd"));
                        return concreteLSInput;
                    } else if ("http://www.w3.org/2001/xml.xsd".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setSystemId(systemId);
                        concreteLSInput.setBaseURI(baseURI);
                        concreteLSInput.setByteStream(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/xml.xsd"));
                        return concreteLSInput;
                    } else if ("XMLSchema.dtd".equals(systemId) || "http://www.w3.org/2001/XMLSchema.dtd".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setSystemId(systemId);
                        concreteLSInput.setBaseURI(baseURI);
                        concreteLSInput.setByteStream(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/XMLSchema.dtd"));
                        return concreteLSInput;
                    } else if ("datatypes.dtd".equals(systemId)) {
                        ConcreteLSInput concreteLSInput = new ConcreteLSInput();
                        concreteLSInput.setSystemId(systemId);
                        concreteLSInput.setBaseURI(baseURI);
                        concreteLSInput.setByteStream(PolicyEnforcerFactory.class.getClassLoader().getResourceAsStream("schemas/datatypes.dtd"));
                        return concreteLSInput;
                    }
                    throw new IllegalArgumentException("Offline resource not available: " + systemId);
                }
            });
            schemas = schemaFactory.newSchema(sourceList.toArray(new Source[sourceList.size()]));
        } catch (SAXException e) {
            throw new RuntimeException(e);
        }
    }

    private static void addAssertionBuilder(AssertionBuilder assertionBuilder) {
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
        Validator validator = schemas.newValidator();
        try {
            validator.setFeature("http://apache.org/xml/features/honour-all-schemaLocations", true);
            validator.validate(new DOMSource(element));
        } catch (SAXException e) {
            throw new WSSPolicyException(e.getMessage(), e);
        } catch (IOException e) {
            throw new WSSPolicyException(e.getMessage(), e);
        }
        XMLInputFactory xmlInputFactory = XMLInputFactory.newFactory();
        XMLStreamReader xmlStreamReader;
        try {
            //because of old JAXP implementation in the jdk 1.6 we get the
            //following exception when we try to create an XMLStreamReader from DOMSource:
            //java.lang.UnsupportedOperationException: Cannot create XMLStreamReader or XMLEventReader from a javax.xml.transform.dom.DOMSource
            //xmlStreamReader = xmlInputFactory.createXMLStreamReader(new DOMSource(element));
            //so we serialize / deserialze the xml...
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            Transformer transformer = TRANSFORMER_FACTORY.newTransformer();
            transformer.transform(new DOMSource(element), new StreamResult(baos));
            xmlStreamReader = xmlInputFactory.createXMLStreamReader(new ByteArrayInputStream(baos.toByteArray()));
        } catch (XMLStreamException e) {
            throw new WSSPolicyException(e.getMessage(), e);
        } catch (TransformerConfigurationException e) {
            throw new WSSPolicyException(e.getMessage(), e);
        } catch (TransformerException e) {
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
