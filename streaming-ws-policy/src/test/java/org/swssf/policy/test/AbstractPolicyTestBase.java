package org.swssf.policy.test;

import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.WSSPolicyException;
import org.swssf.policy.PolicyEnforcer;
import org.swssf.policy.PolicyEnforcerFactory;
import org.swssf.wss.securityEvent.OperationSecurityEvent;
import org.swssf.wss.securityEvent.SecurityEvent;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;

public class AbstractPolicyTestBase {

    protected PolicyEnforcer buildAndStartPolicyEngine(String policyString) throws ParserConfigurationException, SAXException, IOException, WSSPolicyException {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setValidating(false);
        DocumentBuilder documentBuilder = documentBuilderFactory.newDocumentBuilder();
        Document document = documentBuilder.parse(this.getClass().getClassLoader().getResourceAsStream("testdata/wsdl/wsdl-template.wsdl"));
        NodeList nodeList = document.getElementsByTagNameNS("*", SPConstants.P_LOCALNAME);

        Document policyDocument = documentBuilder.parse(new ByteArrayInputStream(policyString.getBytes("UTF-8")));
        Node polcyNode = document.importNode(policyDocument.getDocumentElement(), true);
        Element element = (Element) nodeList.item(0);
        element.appendChild(polcyNode);
        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(document);
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer("");
        OperationSecurityEvent operationSecurityEvent = new OperationSecurityEvent(SecurityEvent.Event.Operation);
        operationSecurityEvent.setOperation(new QName("definitions"));
        policyEnforcer.registerSecurityEvent(operationSecurityEvent);
        return policyEnforcer;
    }
}
