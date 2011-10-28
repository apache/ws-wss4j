<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform" version="1.0"
        xmlns:jaxb="http://java.sun.com/xml/ns/jaxb">

    <xsl:output omit-xml-declaration="yes"/>

    <xsl:template match="/">
        <xsl:apply-templates select="jaxb:bindings/jaxb:bindings[namespace::*[.='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd']]"/>
        <xsl:apply-templates select="jaxb:bindings/jaxb:bindings[namespace::*[.='http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd']]"/>
        <xsl:apply-templates select="jaxb:bindings/jaxb:bindings[namespace::*[.='http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd']]"/>
    </xsl:template>

    <xsl:template match="jaxb:bindings">
        <xsl:copy-of select="."/>
    </xsl:template>
</xsl:stylesheet>