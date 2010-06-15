package ch.gigerstyle.xmlsec.processorImpl;

import ch.gigerstyle.xmlsec.*;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.events.StartElement;
import javax.xml.stream.events.XMLEvent;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * User: giger
 * Date: Jun 13, 2010
 * Time: 4:47:32 PM
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
public class BinarySecurityTokenOutputProcessor extends AbstractOutputProcessor {

    public BinarySecurityTokenOutputProcessor(SecurityProperties securityProperties) throws XMLSecurityException {
        super(securityProperties);
    }

    @Override
    public void processEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        outputProcessorChain.processEvent(xmlEvent);
    }

    @Override
    public void processHeaderEvent(XMLEvent xmlEvent, OutputProcessorChain outputProcessorChain, SecurityContext securityContext) throws XMLStreamException, XMLSecurityException {
        outputProcessorChain.processHeaderEvent(xmlEvent);

        if (xmlEvent.isStartElement()) {
            StartElement startElement = xmlEvent.asStartElement();
            if (startElement.getName().equals(Constants.TAG_wsse_Security)) {

                OutputProcessorChain subOutputProcessorChain = outputProcessorChain.createSubChain(this);

                Map<QName, String> attributes = new HashMap<QName, String>();
                attributes.put(Constants.ATT_NULL_EncodingType, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary");
                attributes.put(Constants.ATT_NULL_ValueType, "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3");
                attributes.put(Constants.ATT_wsu_Id, "CertId-3458500");
                createStartElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken, attributes);
                createCharactersAndOutputAsHeaderEvent(subOutputProcessorChain, "MIIDEzCCAfugAwIBAgIBAzANBgkqhkiG9w0BAQUFADAgMQswCQYDVQQGEwJDSDERMA8GA1UEAxMIU3dpc3NkZWMwHhcNMDYwNTAxMTYyMjEwWhcNMzEwNDI1MTYyMjEwWjA7MQswCQYDVQQGEwJDSDERMA8GA1UEChMIU3dpc3NkZWMxDTALBgNVBAMTBFRlc3QxCjAIBgNVBAUTATMwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAM0BXDQYClTt417yIYrf579xbJ3GgIEuvn3MERwWQqN96fQW6HnT5nLbQvhzkNCWvdEA+IVFYGjBiupuFOqqxTrqf/7AU97aJd8w6SfUItoeDfKvPytj8xVdVgmmZkOObrxxFqve9nDknOdW6e8f07tyiZn7ujb8Vj0n1+QEZx2tAgMBAAGjgcAwgb0wCQYDVR0TBAIwADALBgNVHQ8EBAMCBPAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFNRzj4QAiYWM69mIWCqD3JC+QBI8MEgGA1UdIwRBMD+AFJb+i8DmIQ0IIqgnBF4mmb8GGK1poSSkIjAgMQswCQYDVQQGEwJDSDERMA8GA1UEAxMIU3dpc3NkZWOCAQAwGgYDVR0RBBMwEYEPcGtpQHN3aXNzZGVjLmNoMAkGA1UdEgQCMAAwDQYJKoZIhvcNAQEFBQADggEBAJr48OTCNvb14stpTcpRo6PB59Kf7+rBaK+s5YdMD9mCS8TdZoQFJbeq9IUgOhpArxG6nEfvcQEk4DmujCBoOi9cEaa6LZ+VEHUHtUtL7n0cbTXpipf63i4hSyqHHnF/sfUNUjU0rxtynFEgsUsPgkK+DlARExMU8DPa69sCS2pK0CJzICQGaojAJHQtEp1CwxbEKoUP9Yf+E8xMT7x1e5RFPKw6UxyBJagpXHMyX71tCqdOIkHhA62gmnciF0LqYDz8QMApQlMu2rNRDR7/bMRWsjNU3+liT404s9lmO4JyCsLOUCP5DYXjJUBhFkZPPVaBXTNziCRDIyTeSOB+3mE=");
                createEndElementAndOutputAsHeaderEvent(subOutputProcessorChain, Constants.TAG_wsse_BinarySecurityToken);

                /*
                <wsse:BinarySecurityToken xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
                    EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary"
                    ValueType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3"
                    wsu:Id="CertId-3458500">
                    ...
                </wsse:BinarySecurityToken>
                 */
            }
        }
    }
}
