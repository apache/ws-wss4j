<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
                xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
                xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
                xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
        >

    <xsl:template match="/">
        <xsl:apply-templates/>
    </xsl:template>

    <!-- don't copy ReferenceList -->
    <xsl:template match="/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security/xenc:EncryptedKey/xenc:ReferenceList"/>

    <!-- copy ReferenceList to the end of Security Header -->
    <xsl:template match="/SOAP-ENV:Envelope/SOAP-ENV:Header/wsse:Security">
        <xsl:copy>
            <xsl:apply-templates/>
            <xsl:copy-of select="xenc:EncryptedKey/xenc:ReferenceList"/>
        </xsl:copy>
    </xsl:template>

    <!-- default templates to copy everything but special rules above -->
    <xsl:template match="@*">
        <xsl:copy-of select="."/>
    </xsl:template>

    <xsl:template match="*">
        <xsl:copy>
            <xsl:apply-templates select="@*"/>
            <xsl:apply-templates/>
        </xsl:copy>
    </xsl:template>

</xsl:stylesheet>