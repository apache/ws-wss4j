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

package org.apache.ws.security.trust2.serialization;

import org.apache.ws.security.trust2.RequestSecurityTokenResponse;
import org.apache.ws.security.trust2.SecurityTokenOrReference;
import org.apache.ws.security.trust2.TokenTypes;
import org.apache.ws.security.trust2.TrustConstants;
import org.apache.axis.Constants;
import org.apache.axis.MessageContext;
import org.apache.axis.encoding.DeserializationContext;
import org.apache.axis.encoding.SerializationContext;
import org.apache.axis.encoding.TypeMapping;
import org.apache.axis.encoding.TypeMappingRegistry;
import org.apache.axis.message.RPCElement;
import org.apache.axis.message.RPCParam;
import org.apache.axis.message.SOAPEnvelope;
import org.apache.axis.server.AxisServer;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.WSSConfig;
import org.w3c.dom.Document;
import org.xml.sax.InputSource;

import java.io.FileReader;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.net.URI;

public class TestSerialization {

    public static void main(String[] args) throws Exception {
        MessageContext msgContext = new MessageContext(new AxisServer());
        SOAPEnvelope msg = new SOAPEnvelope();
        RPCParam arg1 = new RPCParam("urn:myNamespace", "testParam", "this is a string");
        //QName dataQName = new QName("typeNS", "Data");

        Document doc = msg.getAsDocument();

        UsernameToken userToken = new UsernameToken(WSSConfig.getDefaultWSConfig(),doc);
        userToken.setName("bob");
        userToken.setPassword("bobspass");

        RequestSecurityTokenResponse tokenResponse = new RequestSecurityTokenResponse(doc, new SecurityTokenOrReference(userToken));
        tokenResponse.setContext(new URI("http://context.context"));
        tokenResponse.setTokenType(TokenTypes.USERNAME);
		
        /*
        Data data = new Data();
        Data data2 = new Data();
        data.stringMember = "String member";
        data.floatMember = new Float("1.23");
        data.dataMember = data2;
        
        data2.stringMember = "another str member";
        data2.floatMember = new Float("4.56");
        data2.dataMember = null;  // "data;" for loop-test of multi-refs
*/
        RPCParam arg2 = new RPCParam("", "struct", tokenResponse);
        RPCElement body = new RPCElement("urn:myNamespace", "method1", new Object[]{arg1, arg2});
        msg.addBodyElement(body);

        try {
            Reader reader = null;

            if (args.length == 0) {
                Writer stringWriter = new StringWriter();
                SerializationContext context = new SerializationContext(stringWriter, msgContext);

                TypeMappingRegistry reg = context.getTypeMappingRegistry();
                TypeMapping tm = (TypeMapping) reg.getTypeMapping(Constants.URI_SOAP11_ENC);
                if (tm == null) {
                    tm = (TypeMapping) reg.createTypeMapping();
                    reg.register(Constants.URI_DEFAULT_SOAP_ENC, tm);
                }
                tm.register(RequestSecurityTokenResponse.class, TrustConstants.RESPONSE_NAME, new RSTResponseSerializerFactory(), new RSTResponseDeserializerFactory());

                msg.output(context);

                String msgString = stringWriter.toString();
                System.out.println("Serialized msg:");
                System.out.println(msgString);

                System.out.println("-------");
                System.out.println("Testing deserialization...");

                reader = new StringReader(msgString);
            } else {
                reader = new FileReader(args[0]);
            }

            DeserializationContext dser = new DeserializationContext(new InputSource(reader), msgContext, org.apache.axis.Message.REQUEST);
            dser.parse();
            SOAPEnvelope env = dser.getEnvelope();
            //System.out.println("********\n" + DOM2Writer.nodeToString(env, true) + "\n********");
            
            RPCElement rpcElem = (RPCElement) env.getFirstBody();
            RPCParam struct = rpcElem.getParam("struct");
            if (struct == null)
                throw new Exception("No <struct> param");

            if (!(struct.getObjectValue() instanceof RequestSecurityTokenResponse)) {
                System.out.println("Not a RST object! ");
                System.out.println(struct.getValue());
                System.exit(1);
            }

            RequestSecurityTokenResponse val = (RequestSecurityTokenResponse) struct.getObjectValue();
            if (val == null)
                throw new Exception("No value for struct param");

            System.out.println(val.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
