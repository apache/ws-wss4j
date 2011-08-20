/**
 * Copyright 2010, 2011 Marc Giger
 *
 * This file is part of the streaming-webservice-security-framework (swssf).
 *
 * The streaming-webservice-security-framework is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The streaming-webservice-security-framework is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with the streaming-webservice-security-framework.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.swssf.test;

import org.swssf.impl.util.RFC2253Parser;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * @author $Author$
 * @version $Revision$ $Date$
 */
public class RFC2253ParserTest {

    @Test
    public void testToXML1() throws Exception {
        Assert.assertEquals(RFC2253Parser.rfc2253toXMLdsig("CN=\"Steve, Kille\",  O=Isode Limited, C=GB"), "CN=Steve\\, Kille,O=Isode Limited,C=GB");
    }

    @Test
    public void testToXML2() throws Exception {
        Assert.assertEquals(RFC2253Parser.rfc2253toXMLdsig("CN=Steve Kille    ,   O=Isode Limited,C=GB"), "CN=Steve Kille,O=Isode Limited,C=GB");
    }

    @Test
    public void testToXML3() throws Exception {
        Assert.assertEquals(RFC2253Parser.rfc2253toXMLdsig("\\ OU=Sales+CN=J. Smith,O=Widget Inc.,C=US\\ \\ "), "\\20OU=Sales+CN=J. Smith,O=Widget Inc.,C=US\\20\\20");
    }

    @Test
    public void testToXML4() throws Exception {
        Assert.assertEquals(RFC2253Parser.rfc2253toXMLdsig("CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB"), "CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB");
    }

    @Test
    public void testToXML5() throws Exception {
        Assert.assertEquals(RFC2253Parser.rfc2253toXMLdsig("CN=Before\\0DAfter,O=Test,C=GB"), "CN=Before\\0DAfter,O=Test,C=GB");
    }

    @Test
    public void testToXML6() throws Exception {
        Assert.assertEquals(RFC2253Parser.rfc2253toXMLdsig("CN=\"L. Eagle,O=Sue, = + < > # ;Grabbit and Runn\",C=GB"), "CN=L. Eagle\\,O\\=Sue\\, \\= \\+ \\< \\> \\# \\;Grabbit and Runn,C=GB");
    }

    @Test
    public void testToXML7() throws Exception {
        Assert.assertEquals(RFC2253Parser.rfc2253toXMLdsig("1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB"), "1.3.6.1.4.1.1466.0=#04024869,O=Test,C=GB");
    }

    @Test
    public void testToXML8() throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append('L');
        sb.append('u');
        sb.append('\uc48d');
        sb.append('i');
        sb.append('\uc487');
        Assert.assertEquals(RFC2253Parser.rfc2253toXMLdsig("SN=" + sb.toString()), "SN=Lu\uc48di\uc487");
    }

    @Test
    public void testToRFC1() throws Exception {
        Assert.assertEquals(RFC2253Parser.xmldsigtoRFC2253("CN=\"Steve, Kille\",  O=Isode Limited, C=GB"), "CN=Steve\\, Kille,O=Isode Limited,C=GB");
    }

    @Test
    public void testToRFC2() throws Exception {
        Assert.assertEquals(RFC2253Parser.xmldsigtoRFC2253("CN=Steve Kille    ,   O=Isode Limited,C=GB"), "CN=Steve Kille,O=Isode Limited,C=GB");
    }

    @Test
    public void testToRFC3() throws Exception {
        Assert.assertEquals(RFC2253Parser.xmldsigtoRFC2253("\\20OU=Sales+CN=J. Smith,O=Widget Inc.,C=US\\20\\20 "), "\\ OU=Sales+CN=J. Smith,O=Widget Inc.,C=US\\ \\ ");
    }

    @Test
    public void testToRFC4() throws Exception {
        Assert.assertEquals(RFC2253Parser.xmldsigtoRFC2253("CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB"), "CN=L. Eagle,O=Sue\\, Grabbit and Runn,C=GB");
    }

    @Test
    public void testToRFC5() throws Exception {
        Assert.assertEquals(RFC2253Parser.xmldsigtoRFC2253("CN=Before\\12After,O=Test,C=GB"), "CN=Before\\\u0012After,O=Test,C=GB");
    }

    @Test
    public void testToRFC6() throws Exception {
        Assert.assertEquals(RFC2253Parser.xmldsigtoRFC2253("CN=\"L. Eagle,O=Sue, = + < > # ;Grabbit and Runn\",C=GB"), "CN=L. Eagle\\,O\\=Sue\\, \\= \\+ \\< \\> \\# \\;Grabbit and Runn,C=GB");
    }

    @Test
    public void testToRFC7() throws Exception {
        Assert.assertEquals(RFC2253Parser.xmldsigtoRFC2253("1.3.6.1.4.1.1466.0=\\#04024869,O=Test,C=GB"), "1.3.6.1.4.1.1466.0=\\#04024869,O=Test,C=GB");
    }

    @Test
    public void testToRFC8() throws Exception {
        StringBuilder sb = new StringBuilder();
        sb.append('L');
        sb.append('u');
        sb.append('\uc48d');
        sb.append('i');
        sb.append('\uc487');
        Assert.assertEquals(RFC2253Parser.xmldsigtoRFC2253("SN=" + sb.toString()), "SN=Lu\uc48di\uc487");
    }
}
