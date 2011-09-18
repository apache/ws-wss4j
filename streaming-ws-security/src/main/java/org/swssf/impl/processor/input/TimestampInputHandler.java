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
package org.swssf.impl.processor.input;

import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_utility_1_0.TimestampType;
import org.swssf.ext.*;
import org.swssf.securityEvent.SecurityEvent;
import org.swssf.securityEvent.TimestampSecurityEvent;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.Calendar;
import java.util.Deque;
import java.util.GregorianCalendar;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class TimestampInputHandler extends AbstractInputSecurityHeaderHandler {

    //Chapter 10 Security Timestamps: ...may only be present at most once per header (that is, per SOAP actor/role)
    public TimestampInputHandler(InputProcessorChain inputProcessorChain,
                                 final SecurityProperties securityProperties,
                                 Deque<XMLEvent> eventQueue,
                                 Integer index) throws WSSecurityException {

        Boolean alreadyProcessed = inputProcessorChain.getSecurityContext().<Boolean>get(Constants.TIMESTAMP_PROCESSED);
        if (Boolean.TRUE.equals(alreadyProcessed)) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.MESSAGE_EXPIRED, "invalidTimestamp",
                    "Message contains two or more timestamps");
        }
        inputProcessorChain.getSecurityContext().put(Constants.TIMESTAMP_PROCESSED, Boolean.TRUE);

        final TimestampType timestampType = (TimestampType) parseStructure(eventQueue, index);

        try {
            DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();

            // Validate whether the security semantics have expired
            //created and expires is optional per spec. But we enforce the created element in the validation
            Calendar crea = null;
            if (timestampType.getCreated() != null) {
                XMLGregorianCalendar created = datatypeFactory.newXMLGregorianCalendar(timestampType.getCreated().getValue());
                logger.debug("Timestamp created: " + created);
                crea = created.toGregorianCalendar();
            }

            Calendar exp = null;
            if (timestampType.getExpires() != null) {
                XMLGregorianCalendar expires = datatypeFactory.newXMLGregorianCalendar(timestampType.getExpires().getValue());
                logger.debug("Timestamp expires: " + expires);
                exp = expires.toGregorianCalendar();
            }

            Calendar rightNow = Calendar.getInstance();
            Calendar ttl = Calendar.getInstance();
            ttl.add(Calendar.SECOND, -securityProperties.getTimestampTTL());

            if (exp != null && securityProperties.isStrictTimestampCheck() && exp.before(rightNow)) {
                logger.debug("Time now: " + datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar()).toXMLFormat());
                throw new WSSecurityException(WSSecurityException.ErrorCode.MESSAGE_EXPIRED, "invalidTimestamp",
                        "The security semantics of the message have expired");
            }

            if (crea != null && securityProperties.isStrictTimestampCheck() && crea.before(ttl)) {
                logger.debug("Time now: " + datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar()).toXMLFormat());
                throw new WSSecurityException(WSSecurityException.ErrorCode.MESSAGE_EXPIRED, "invalidTimestamp",
                        "The security semantics of the message have expired");
            }

            if (crea != null && crea.after(rightNow)) {
                logger.debug("Time now: " + datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar()).toXMLFormat());
                throw new WSSecurityException(WSSecurityException.ErrorCode.MESSAGE_EXPIRED, "invalidTimestamp",
                        "The security semantics of the message is invalid");
            }

            TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent(SecurityEvent.Event.Timestamp);
            timestampSecurityEvent.setCreated(crea);
            timestampSecurityEvent.setExpires(exp);
            inputProcessorChain.getSecurityContext().registerSecurityEvent(timestampSecurityEvent);
            inputProcessorChain.getSecurityContext().put(Constants.PROP_TIMESTAMP_SECURITYEVENT, timestampSecurityEvent);

        } catch (DatatypeConfigurationException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        } catch (IllegalArgumentException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e);
        }
    }

    @Override
    protected Parseable getParseable(StartElement startElement) {
        return new TimestampType(startElement);
    }

    /*
    <wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="Timestamp-1106985890">
        <wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2009-11-18T10:11:28.358Z</wsu:Created>
        <wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2009-11-18T10:26:28.358Z</wsu:Expires>
    </wsu:Timestamp>
     */
}
