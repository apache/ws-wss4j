package ch.gigerstyle.xmlsec.impl.processor.input;

import ch.gigerstyle.xmlsec.ext.*;
import ch.gigerstyle.xmlsec.securityEvent.SecurityEvent;
import ch.gigerstyle.xmlsec.securityEvent.TimestampSecurityEvent;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_utility_1_0.TimestampType;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.Calendar;
import java.util.GregorianCalendar;

/**
 * User: giger
 * Date: May 15, 2010
 * Time: 10:51:33 AM
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
public class TimestampInputProcessor extends AbstractInputProcessor {
    //todo only one timestamp is allowed per security-header @see spec
    private TimestampType currentTimestampType;

    public TimestampInputProcessor(SecurityProperties securityProperties, StartElement startElement) {
        super(securityProperties);
        currentTimestampType = new TimestampType(startElement);
    }

    /*
    <wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="Timestamp-1106985890">
        <wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2009-11-18T10:11:28.358Z</wsu:Created>
        <wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2009-11-18T10:26:28.358Z</wsu:Expires>
    </wsu:Timestamp>
     */

    @Override
    public XMLEvent processNextHeaderEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        XMLEvent xmlEvent = inputProcessorChain.processHeaderEvent();

        boolean isFinishedcurrentTimestamp = false;

        if (currentTimestampType != null) {
            try {
                isFinishedcurrentTimestamp = currentTimestampType.parseXMLEvent(xmlEvent);
                if (isFinishedcurrentTimestamp) {
                    currentTimestampType.validate();
                }
            } catch (ParseException e) {
                throw new XMLSecurityException(e);
            }
        }

        if (currentTimestampType != null && isFinishedcurrentTimestamp) {
            try {
                DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();

                // Validate whether the security semantics have expired
                //created and expires is optional per spec. But we enforce the created element in the validation
                Calendar crea = null;
                if (currentTimestampType.getCreated() != null) {
                    XMLGregorianCalendar created = datatypeFactory.newXMLGregorianCalendar(currentTimestampType.getCreated().getValue());
                    logger.debug("Timestamp created: " + created);
                    crea = created.toGregorianCalendar();
                }

                Calendar exp = null;
                if (currentTimestampType.getExpires() != null) {
                    XMLGregorianCalendar expires = datatypeFactory.newXMLGregorianCalendar(currentTimestampType.getExpires().getValue());
                    logger.debug("Timestamp expires: " + expires);
                    exp = expires.toGregorianCalendar();
                }

                Calendar rightNow = Calendar.getInstance();
                Calendar ttl = Calendar.getInstance();
                ttl.add(Calendar.SECOND, -getSecurityProperties().getTimestampTTL());

                if (exp != null && getSecurityProperties().isStrictTimestampCheck() && exp.before(rightNow)) {
                    logger.debug("Time now: " + datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar()).toXMLFormat());
                    throw new XMLSecurityException("invalidTimestamp " +
                            "The security semantics of the message have expired");
                }

                if (crea != null && getSecurityProperties().isStrictTimestampCheck() && crea.before(ttl)) {
                    logger.debug("Time now: " + datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar()).toXMLFormat());
                    throw new XMLSecurityException("invalidTimestampTTL " +
                            "The security semantics of the message have expired");
                }

                if (crea != null && crea.after(rightNow)) {
                    logger.debug("Time now: " + datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar()).toXMLFormat());
                    throw new XMLSecurityException("invalidTimestamp " +
                            "The security semantics of the message is invalid");
                }

                TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent(SecurityEvent.Event.Timestamp);
                timestampSecurityEvent.setCreated(crea);
                timestampSecurityEvent.setExpires(exp);
                inputProcessorChain.getSecurityContext().registerSecurityEvent(timestampSecurityEvent);

            } catch (DatatypeConfigurationException e) {
                throw new XMLSecurityException(e.getMessage(), e);
            }
            finally {
                inputProcessorChain.removeProcessor(this);
                currentTimestampType = null;
                isFinishedcurrentTimestamp = false;
            }
        }
        return xmlEvent;
    }

    @Override
    public XMLEvent processNextEvent(InputProcessorChain inputProcessorChain) throws XMLStreamException, XMLSecurityException {
        //this method should not be called (processor will be removed after processing header
        return null;
    }
}
