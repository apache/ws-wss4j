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
package org.swssf.test.policy;

import org.swssf.ext.Constants;
import org.swssf.ext.SecurePart;
import org.swssf.ext.SecurityProperties;
import org.swssf.policy.PolicyEnforcer;
import org.swssf.policy.PolicyEnforcerFactory;
import org.swssf.policy.PolicyInputProcessor;
import org.swssf.test.AbstractTestBase;
import org.swssf.test.CallbackHandlerImpl;
import org.testng.annotations.Test;
import org.w3c.dom.Document;

import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;

/**
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class PolicyTest extends AbstractTestBase {

    @Test
    public void testAsymmetricBindingIncludeTimestampPolicy() throws Exception {

        SecurityProperties outSecurityProperties = new SecurityProperties();
        outSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        outSecurityProperties.setEncryptionUser("receiver");
        outSecurityProperties.loadEncryptionKeystore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());
        outSecurityProperties.setSignatureUser("transmitter");
        outSecurityProperties.loadSignatureKeyStore(this.getClass().getClassLoader().getResource("transmitter.jks"), "default".toCharArray());

        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addSignaturePart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Element));
        //outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Timestamp.getLocalPart(), Constants.TAG_wsu_Timestamp.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Created.getLocalPart(), Constants.TAG_wsu_Created.getNamespaceURI(), SecurePart.Modifier.Element));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_wsu_Expires.getLocalPart(), Constants.TAG_wsu_Expires.getNamespaceURI(), SecurePart.Modifier.Content));
        outSecurityProperties.addEncryptionPart(new SecurePart(Constants.TAG_soap_Body_LocalName, Constants.NS_SOAP11, SecurePart.Modifier.Content));
        Constants.Action[] actions = new Constants.Action[]{Constants.Action.TIMESTAMP, Constants.Action.SIGNATURE, Constants.Action.ENCRYPT};
        outSecurityProperties.setOutAction(actions);

        InputStream sourceDocument = this.getClass().getClassLoader().getResourceAsStream("testdata/plain-soap-1.1.xml");
        ByteArrayOutputStream baos = doOutboundSecurity(outSecurityProperties, sourceDocument);


        SecurityProperties inSecurityProperties = new SecurityProperties();
        inSecurityProperties.setCallbackHandler(new CallbackHandlerImpl());
        inSecurityProperties.loadSignatureVerificationKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());
        inSecurityProperties.loadDecryptionKeystore(this.getClass().getClassLoader().getResource("receiver.jks"), "default".toCharArray());

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
}
