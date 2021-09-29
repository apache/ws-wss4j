package org.apache.wss4j.common.token;

import org.apache.wss4j.common.util.SOAPUtil;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;

class DOMX509IssuerSerialTest {

    @Test
    public void whenConstructingForWsSecUsersUsingConstructorThenUseDefaultIssuerDelimiting() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        String input = "CN=EOIR,OU=Some Unit";

        BigInteger serialNumber = new BigInteger("123");
        DOMX509IssuerSerial subject = new DOMX509IssuerSerial(doc, input, serialNumber);
        String expected = "CN=EOIR,OU=Some Unit";
        assertEquals(expected,subject.getIssuer());
    }

    @Test
    public void whenConstructingForWsSecUsersUsingNewConstructorWithCommaDelimitedThenUseWcfCompatibleDelimiting() throws Exception {
        Document doc = SOAPUtil.toSOAPPart(SOAPUtil.SAMPLE_SOAP_MSG);
        String input = "CN=EOIR,OU=Some Unit";

        BigInteger serialNumber = new BigInteger("123");
        DOMX509IssuerSerial subject = new DOMX509IssuerSerial(doc, input, serialNumber,true);
        String expected = "CN=EOIR, OU=Some Unit";
        assertEquals(expected,subject.getIssuer());
        System.out.println(subject.getIssuer());
    }

}