package ch.gigerstyle.xmlsec.test.policy;

import ch.gigerstyle.xmlsec.ext.Constants;
import ch.gigerstyle.xmlsec.ext.SecurePart;
import ch.gigerstyle.xmlsec.ext.SecurityProperties;
import ch.gigerstyle.xmlsec.policy.PolicyEnforcer;
import ch.gigerstyle.xmlsec.policy.PolicyEnforcerFactory;
import ch.gigerstyle.xmlsec.policy.PolicyInputProcessor;
import ch.gigerstyle.xmlsec.test.AbstractTestBase;
import org.testng.annotations.Test;
import org.w3c.dom.Document;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;

/**
 * User: giger
 * Date: Aug 16, 2010
 * Time: 6:00:22 PM
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
public class PolicyTest extends AbstractTestBase {

    @Test
    public void testAsymmetricBindingIncludeTimestampPolicy() throws Exception {

        SecurityProperties outSecurityProperties = new SecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), "Element"));
        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_soap11_Body.getLocalPart(), Constants.TAG_soap11_Body.getNamespaceURI(), "Element"));
        //outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), "Element"));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Created.getLocalPart(), Constants.TAG_wsu_Created.getNamespaceURI(), "Element"));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Expires.getLocalPart(), Constants.TAG_wsu_Expires.getNamespaceURI(), "Content"));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_soap11_Body.getLocalPart(), Constants.TAG_soap11_Body.getNamespaceURI(), "Element"));
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.TIMESTAMP, Constants.Action.SIGNATURE, Constants.Action.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);


        SecurityProperties inSecurityProperties = new SecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "1234567890".toCharArray());

        PolicyEnforcerFactory policyEnforcerFactory = PolicyEnforcerFactory.newInstance(this.getClass().getClassLoader().getResource("testdata/wsdl/wsdl.wsdl"));
        PolicyEnforcer policyEnforcer = policyEnforcerFactory.newPolicyEnforcer(null);
        inSecurityProperties.addInputProcessor(new PolicyInputProcessor(policyEnforcer, null));

        Document document = doInboundSecurity(inSecurityProperties, new ByteArrayInputStream(baos.toByteArray()), policyEnforcer);

        //read the whole stream:
        Transformer transformer = TransformerFactory.newInstance().newTransformer();
        transformer.transform(new DOMSource(document), new StreamResult(
                new OutputStream() {
                    @Override
                    public void write(int b) throws IOException {
                        // > /dev/null
                    }
                }
        ));
    }

    @Test
    public void testPolicyParsing() throws Exception {
        //Policy policy = PolicyEngine.getPolicy(this.getClass().getClassLoader().getResourceAsStream("testdata/policy/policy1.xml"));
        //System.out.println(policy);

        //PolicyEnforcer policyEnforcer = new PolicyEnforcer(this.getClass().getClassLoader().getResource("testdata/wsdl/wsdl.wsdl"), null);
    }
}
