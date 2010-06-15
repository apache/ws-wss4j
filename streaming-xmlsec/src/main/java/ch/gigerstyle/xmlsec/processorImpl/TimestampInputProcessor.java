package ch.gigerstyle.xmlsec.processorImpl;

import ch.gigerstyle.xmlsec.*;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_utility_1_0.AttributedDateTime;
import org.oasis_open.docs.wss._2004._01.oasis_200401_wss_wssecurity_utility_1_0.TimestampType;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.*;
import java.util.Calendar;
import java.util.Date;
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

    private TimestampType currentTimestampType;

    public TimestampInputProcessor(SecurityProperties securityProperties) {
        super(securityProperties);
    }

    /*
    <wsu:Timestamp xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd" wsu:Id="Timestamp-1106985890">
        <wsu:Created xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2009-11-18T10:11:28.358Z</wsu:Created>
        <wsu:Expires xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">2009-11-18T10:26:28.358Z</wsu:Expires>
    </wsu:Timestamp>
     */

    public void processEvent(XMLEvent xmlEvent, InputProcessorChain inputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();

            if (startElement.getName().equals(Constants.TAG_wsu_Timestamp)) {
                if (currentTimestampType != null) {
                    throw new XMLSecurityException("Multiple Timestamps found");
                }

                currentTimestampType = new TimestampType();

                //only one timestamp is allowed -> todo prove in doc...
                Attribute attribute = startElement.getAttributeByName(Constants.ATT_wsu_Id);
                if (attribute != null) {
                    currentTimestampType.setId(attribute.getValue());
                }
            } else if (currentTimestampType == null) {
                //do nothing...fall out
            } else if (startElement.getName().equals(Constants.TAG_wsu_Created)) {
                AttributedDateTime created = new AttributedDateTime();

                Attribute id = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (id != null) {
                    created.setId(id.getValue());
                }
                currentTimestampType.setCreated(created);
            } else if (startElement.getName().equals(Constants.TAG_wsu_Expires)) {
                AttributedDateTime expires = new AttributedDateTime();

                Attribute id = startElement.getAttributeByName(Constants.ATT_NULL_Id);
                if (id != null) {
                    expires.setId(id.getValue());
                }
                currentTimestampType.setExpires(expires);
            }
        } else if (currentTimestampType != null && xmlEvent.isCharacters()) {
            //todo handle multiple character events for same text-node
            Characters characters = xmlEvent.asCharacters();
            if (!characters.isWhiteSpace() && getLastStartElementName().equals(Constants.TAG_wsu_Created)) {
                currentTimestampType.getCreated().setValue(characters.getData());
            } else if (!characters.isWhiteSpace() && getLastStartElementName().equals(Constants.TAG_wsu_Expires)) {
                currentTimestampType.getExpires().setValue(characters.getData());
            }
        } else if (currentTimestampType != null && xmlEvent.isEndElement()) {
            EndElement endElement = xmlEvent.asEndElement();
            //probably we can remove this processor from the chain now?

            if (endElement.getName().equals(Constants.TAG_wsu_Timestamp)) {
                try {
                    DatatypeFactory datatypeFactory = DatatypeFactory.newInstance();
                    XMLGregorianCalendar created = datatypeFactory.newXMLGregorianCalendar(currentTimestampType.getCreated().getValue());
                    XMLGregorianCalendar expires = datatypeFactory.newXMLGregorianCalendar(currentTimestampType.getExpires().getValue());

                    System.out.println("Timestamp created: " + created);
                    System.out.println("Timestamp expires: " + expires);

                    // Validate whether the security semantics have expired
                    Calendar exp = expires.toGregorianCalendar();
                    //todo strict timestamp
                    //if (exp != null && wssConfig.isTimeStampStrict()) {
                        Calendar rightNow = Calendar.getInstance();
                        if (exp.before(rightNow)) {
                            System.out.println("Time now: " + datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar()).toXMLFormat());
                            throw new XMLSecurityException("invalidTimestamp " +
                                "The security semantics of the message have expired");
                        }
                    //}

                    //todo more checks on timestamp e.g future created date?

                } catch (DatatypeConfigurationException e) {
                    throw new XMLSecurityException(e.getMessage(), e);
                }
            }
        }

        inputProcessorChain.processEvent(xmlEvent);
    }
}
