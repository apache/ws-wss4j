package wssec;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPMessage;
import java.io.ByteArrayInputStream;

public class SOAPUtil {

    /**
     * Convert an xml String to a Document
     */
    public static org.w3c.dom.Document toSOAPPart(String xml) throws Exception {
        ByteArrayInputStream in = new ByteArrayInputStream(xml.getBytes());
        MessageFactory factory = MessageFactory.newInstance();
        SOAPMessage soapMessage = factory.createMessage(null, in);
        return soapMessage.getSOAPPart();
    }

}
