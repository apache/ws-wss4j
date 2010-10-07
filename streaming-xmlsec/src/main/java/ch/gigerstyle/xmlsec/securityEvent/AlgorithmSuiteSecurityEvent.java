package ch.gigerstyle.xmlsec.securityEvent;

/**
 * User: giger
 * Date: Sep 14, 2010
 * Time: 6:36:29 PM
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
public class AlgorithmSuiteSecurityEvent extends SecurityEvent {

    //@see http://docs.oasis-open.org/ws-sx/ws-securitypolicy/v1.3/os/ws-securitypolicy-1.3-spec-os.html#_Toc212617893
    //6.1
    public enum Usage {
        Sym_Sig,
        Asym_Sig,
        Dig,
        Enc,
        Sym_Key_Wrap,
        Asym_Key_Wrap,
        Comp_Key,
        Enc_KD,
        Sig_KD,
        C14n,
        Soap_Norm,
        STR_Trans,
        XPath,
    }

    private String algorithmURI;
    private Usage usage;

    public AlgorithmSuiteSecurityEvent(Event securityEventType) {
        super(securityEventType);
    }

    public String getAlgorithmURI() {
        return algorithmURI;
    }

    public void setAlgorithmURI(String algorithmURI) {
        this.algorithmURI = algorithmURI;
    }

    public Usage getUsage() {
        return usage;
    }

    public void setUsage(Usage usage) {
        this.usage = usage;
    }
}
