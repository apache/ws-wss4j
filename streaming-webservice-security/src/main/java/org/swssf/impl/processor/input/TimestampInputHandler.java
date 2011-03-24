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
 * @author $Author: giger $
 * @version $Revision: 272 $ $Date: 2010-12-23 14:30:56 +0100 (Thu, 23 Dec 2010) $
 */
public class TimestampInputHandler extends AbstractInputSecurityHeaderHandler {
    //todo only one timestamp is allowed per security-header @see spec

    public TimestampInputHandler(InputProcessorChain inputProcessorChain, final SecurityProperties securityProperties, Deque<XMLEvent> eventQueue, Integer index) throws WSSecurityException {

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
                throw new WSSecurityException("invalidTimestamp " +
                        "The security semantics of the message have expired");
            }

            if (crea != null && securityProperties.isStrictTimestampCheck() && crea.before(ttl)) {
                logger.debug("Time now: " + datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar()).toXMLFormat());
                throw new WSSecurityException("invalidTimestampTTL " +
                        "The security semantics of the message have expired");
            }

            if (crea != null && crea.after(rightNow)) {
                logger.debug("Time now: " + datatypeFactory.newXMLGregorianCalendar(new GregorianCalendar()).toXMLFormat());
                throw new WSSecurityException("invalidTimestamp " +
                        "The security semantics of the message is invalid");
            }

            TimestampSecurityEvent timestampSecurityEvent = new TimestampSecurityEvent(SecurityEvent.Event.Timestamp);
            timestampSecurityEvent.setCreated(crea);
            timestampSecurityEvent.setExpires(exp);
            inputProcessorChain.getSecurityContext().registerSecurityEvent(timestampSecurityEvent);

        } catch (DatatypeConfigurationException e) {
            throw new WSSecurityException(e.getMessage(), e);
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
