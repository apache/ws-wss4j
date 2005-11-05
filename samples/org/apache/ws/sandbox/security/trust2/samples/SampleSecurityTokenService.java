/*
 * Copyright  2003-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.apache.ws.sandbox.security.trust2.samples;

import org.apache.ws.sandbox.security.trust2.Lifetime;
import org.apache.ws.sandbox.security.trust2.RequestSecurityToken;
import org.apache.ws.sandbox.security.trust2.RequestSecurityTokenResponse;
import org.apache.ws.sandbox.security.trust2.SecurityTokenOrReference;
import org.apache.ws.sandbox.security.trust2.TokenTypes;
import org.apache.ws.sandbox.security.trust2.TrustConstants;
import org.apache.axis.AxisFault;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.message.token.X509Security;
import org.apache.ws.security.WSSConfig;
import org.w3c.dom.Document;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * @author ddelvecc
 *         <p/>
 *         A WS-Trust style security token service. It is intended to be used as an Axis Docmument-style service.
 */
public class SampleSecurityTokenService {

    // Service has a single method called exchange. Really since its a Document service, the method name is arbitrary
    // and won't show up anywhere in the XML of the request. An exchange operation must be properly defined in the
    // Axis WSDD configuration file for this service. Then if Axis sees a SOAP body containing a RequestSecurityToken 
    // element in the WS-Trust namespace it will invoke this method. Assuming that the deserializers are configured 
    // correctly in the WSDD file, Axis should be able to automatically convert the XML into a RequestSecurityToken
    // object as well. 
    public RequestSecurityTokenResponse exchange(RequestSecurityToken tokenRequest) throws AxisFault {
        if (tokenRequest != null) {
            // Check the request type, this service only understands requests for token issue
            if (TrustConstants.REQUEST_ISSUE.equals(tokenRequest.getRequestType())) {
                SecurityTokenOrReference requestedToken = null;
                Document doc = tokenRequest.getDocument();
				
                // Check the token type being requested, this service returns only X509 certs or UsernameTokens 
                if (TokenTypes.X509.equals(tokenRequest.getTokenType())) {
                    try {
                        // Construct an arbitrary x509 certificate (certificate content is hard-coded) any x509 request returns the same certificate
                        // A real service would do something more intelligent
                        InputStream inputStream = new ByteArrayInputStream("-----BEGIN CERTIFICATE-----\nMIICTTCCAbagAwIBAgIDC6tXMA0GCSqGSIb3DQEBBAUAMGExCzAJBgNVBAYTAkRFMQ8wDQYDVQQIEwZCYXllcm4xDzANBgNVBAcTBk11bmljaDEPMA0GA1UEChMGQXBhY2hlMQ4wDAYDVQQLEwVXU1M0SjEPMA0GA1UEAxMGV2VybmVyMB4XDTA0MDUxMDA2MjgzMloXDTA0MDUxMDE4MzMzMlowdjELMAkGA1UEBhMCREUxDzANBgNVBAgTBkJheWVybjEPMA0GA1UEBxMGTXVuaWNoMQ8wDQYDVQQKEwZBcGFjaGUxDjAMBgNVBAsTBVdTUzRKMQ8wDQYDVQQDEwZXZXJuZXIxEzARBgNVBAMTCjEzNDU1MDc0NzQwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAJbir9ayJesk3Yj+L1gDlS8TbtEj5DYLMhIYDA/Ycef2WEQ+pNIPTpeZ27SYEgf8Kmxpt4HHE5WJ8M9wnpB6EDQwi8vIQLTkaemJHGuWH8rbFY4CwFtQKEro63+agiSzbWZkpOFX4RFyX/Y5lOgZcW0q0yhumG2ZdMKViS81gx4BAgMBAAEwDQYJKoZIhvcNAQEEBQADgYEAPxYMCzAIoe0/DhT2NPpfl8+3vHV33YIbzlaejoV47KeR9IjPvKNS3PK0Mke3eKgJo/11DplnVpx9inKYaatPT/ZRz0eJ1+oTPe1kRYMDhO/OWCZhvVWQZPA9M8TWrDWJKwa6HlEmsbZGMnoGwEQ+7S3eD9TsqFf83CD+6Yr8wkM=\n-----END CERTIFICATE-----".getBytes());
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        X509Certificate cert = (X509Certificate) cf.generateCertificate(inputStream);
						
                        // Add the cert to a <BinarySecurityToken> element
                        X509Security binaryToken = new X509Security(doc);
                        binaryToken.setX509Certificate(cert);
						
                        // Set the <BinarySecurityToken> as the <RequestedToken> in our response
                        requestedToken = new SecurityTokenOrReference(binaryToken);
                    } catch (Exception e) {
                        throw new AxisFault("Could not create X.509 Security Token: " + e.getMessage());
                    }
                } else if (TokenTypes.USERNAME.equals(tokenRequest.getTokenType())) {
                    // Create an arbitrary, fixed UsernameToken to return if the client requests one
                    // A real security token service would do something more intelligent
                    UsernameToken userToken = new UsernameToken(WSSConfig.getDefaultWSConfig().isPrecisionInMilliSeconds(),doc);
                    userToken.setName("bob");
                    userToken.setPassword("bobspass");
					
                    // Create a new SecurityTokenOrReference object to use for the <RequestedToken> element
                    // As the class name implies SecurityTokenOrReference objects can hold either a real security token element
                    // or a <SecurityTokenReference> element to a security token found elsewhere 
                    requestedToken = new SecurityTokenOrReference(userToken);
                }
				
                // Create our response object, giving it an XML document object to use for element creation, along with our requestedToken object
                RequestSecurityTokenResponse tokenResponse = new RequestSecurityTokenResponse(doc, requestedToken);
				
                // Set the Context of the response, according to WS-Trust, this must be the same as the Context of the request
                tokenResponse.setContext(tokenRequest.getContext());
				
                // Set the TokenType of the response. To make clients happy we'll return a token of the type they requested
                tokenResponse.setTokenType(tokenRequest.getTokenType());
				
                // Add a Lifetime element to indicate to clients the lifetime of the token we're sending
                // In this case, we're giving the client the lifetime they asked for 
                Lifetime lifetime = tokenRequest.getLifetime();
                tokenResponse.setLifetime(lifetime);

                // Check if the request included a custom element named <TestElement>
                // Note that a list of custom elements can be obtained by calling getCustomElements();
                if (tokenRequest.getCustomElement("http://testElementNs.testElementNs", "TestElement") != null) {
                    // If it did we'll add our own custom element to the response
                    tokenResponse.addCustomElementNS("http://testElementNs.testElementNs", "te:TestElementResponse");
                }
				
                // Return the response object. If our Axis Serializers are configured correctly, this should automatically get converted to XML
                return tokenResponse;
            }
        }

        return null;
    }
}
