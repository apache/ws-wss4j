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

package wssec;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPMessage;

import org.apache.axis.Message;
import org.apache.axis.MessageContext;
import org.apache.axis.client.AxisClient;
import org.apache.axis.configuration.NullProvider;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

public class SOAPUtil {
    
    /**
     * Convert an SOAP Envelope as a String to a org.w3c.dom.Document. The way this
     * is done is delegated to one of the other methods in this class.
     */
    public static org.w3c.dom.Document toSOAPPart(String xml) throws Exception {
        // return toSOAPPartSAAJ(xml);
        return toSOAPPartAxis(xml);
    }

    /**
     * Convert an xml String to a Document using the SAAJ API
     */
    public static org.w3c.dom.Document toSOAPPartSAAJ(String xml) throws Exception {
        ByteArrayInputStream in = new ByteArrayInputStream(xml.getBytes());
        MessageFactory factory = MessageFactory.newInstance();
        SOAPMessage soapMessage = factory.createMessage(null, in);
        return soapMessage.getSOAPPart();
    }
    
    /**
     * Convert an xml String to a Document using Axis
     */
    public static org.w3c.dom.Document toSOAPPartAxis(String xml) throws Exception {
        AxisClient tmpEngine = new AxisClient(new NullProvider());
        MessageContext msgContext = new MessageContext(tmpEngine);
        InputStream in = new ByteArrayInputStream(xml.getBytes());
        Message msg = new Message(in);
        msg.setMessageContext(msgContext);
        org.apache.axis.message.SOAPEnvelope soapEnvelope = msg.getSOAPEnvelope();
        return soapEnvelope.getAsDocument();
    }
    
}
