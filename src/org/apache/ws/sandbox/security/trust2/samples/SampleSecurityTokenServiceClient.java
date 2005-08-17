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
import org.apache.ws.sandbox.security.trust2.exception.TrustException;
import org.apache.axis.client.Call;
import org.apache.axis.client.Service;
import org.apache.axis.message.SOAPBodyElement;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.axis.utils.XMLUtils;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.WSSConfig;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;

import java.net.URI;
import java.util.Date;

/**
 * @author ddelvecc
 *         <p/>
 *         A client class to test the SecurityTokenService.
 */
public class SampleSecurityTokenServiceClient {

    // First arg passed should be the URL of the service. If none is specified, client tries localhost.
    public static void main(String[] args) throws DOMException, TrustException, Exception {
        Service service = new Service();
        Call call = (Call) service.createCall();
		
        // The default service location
        String url = "http://localhost:8080/JavaTrust/services/SampleSecurityTokenService";
        // Or the user-specified location
        if (args.length > 0)
            url = args[0];
        call.setTargetEndpointAddress(new java.net.URL(url));

        SOAPEnvelope env = new SOAPEnvelope();
        Document doc = env.getAsDocument();
        WSSConfig wssConfig = WSSConfig.getDefaultWSConfig();

        // Create a new request object passing an XML document for element creation and the RequestType (in this case issue)
        RequestSecurityToken tokenRequest = new RequestSecurityToken(doc, TrustConstants.REQUEST_ISSUE);
		
        // Setting the context and the token type we want to be returned
        tokenRequest.setContext(new URI("http://context.context"));
        tokenRequest.setTokenType(TokenTypes.X509);
		
        // Construct a bunch of username tokens to be used as <Base> and <Supporting> elements
        UsernameToken userToken = new UsernameToken(wssConfig, doc);
        userToken.setName("bob");
        userToken.setPassword("bobspass");
        tokenRequest.setBase(new SecurityTokenOrReference(userToken));

        UsernameToken user2Token = new UsernameToken(wssConfig, doc);
        user2Token.setName("joe");
        user2Token.setPassword("bobspass");
        tokenRequest.addSupporting(new SecurityTokenOrReference(user2Token));

        UsernameToken user3Token = new UsernameToken(wssConfig, doc);
        user3Token.setName("mike");
        user3Token.setPassword("bobspass");
        tokenRequest.addSupporting(new SecurityTokenOrReference(user3Token));

        // Set the desired Lifetime of the token being requested in this case to 250 seconds
        Date start = new Date();
        Date end = new Date();
        end.setTime(start.getTime() + 250 * 1000);
        tokenRequest.setLifetime(new Lifetime(wssConfig, doc, start, end));

        // Add a custom element of our own creation
        tokenRequest.addCustomElementNS("http://testElementNs.testElementNs", "te:TestElement");

        // Create a SOAP body and set the XML element of the token request (a <RequestSecurityToken> element)
        // as its only child
        SOAPBodyElement sbe = new SOAPBodyElement(tokenRequest.getElement());

        // Add the body element to the SOAP envelope
        env.addBodyElement(sbe);

        System.out.println("\n============= Request ==============");
        System.out.println(XMLUtils.DocumentToString(env.getAsDocument()));
		
        // This is where we actually invoke the service, sending the request we've constructed
        // Assuming we did everything right, it will return to us a SOAP envelope containing the response
        SOAPEnvelope response = call.invoke(env);

        System.out.println("\n============= Response ==============");
        XMLUtils.PrettyElementToStream(response.getAsDOM(), System.out);
		
        // Find the <RequestSecurityTokenResponse> element the SOAP body should contain
        SOAPBodyElement responseBody = response.getBodyByName(TrustConstants.WST_NS, TrustConstants.RESPONSE_TAG);

        // Construct a Java object from the XML
        RequestSecurityTokenResponse tokenResponse = new RequestSecurityTokenResponse(responseBody.getAsDOM());

        System.out.println("\n------- RequestSecurityTokenResponse object ------------- \n" + tokenResponse);
    }
}
