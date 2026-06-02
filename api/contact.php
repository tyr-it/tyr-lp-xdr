<?php
header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: https://tyr.digital');
header('Access-Control-Allow-Methods: POST');

// Honeypot: campo oculto preenchido = bot
if (!empty($_POST['website'])) {
    http_response_code(200);
    echo json_encode(['ok' => true]);
    exit;
}

function sanitize(string $v, int $max = 200): string {
    return substr(strip_tags(trim($v)), 0, $max);
}

$nome      = sanitize($_POST['nome']      ?? '');
$sobrenome = sanitize($_POST['sobrenome'] ?? '');
$email     = sanitize($_POST['email']     ?? '', 254);
$tel       = sanitize($_POST['tel']       ?? '', 30);
$msg       = sanitize($_POST['msg']       ?? '', 2000);

if (!$nome || !$email || !$msg) {
    http_response_code(422);
    echo json_encode(['ok' => false, 'error' => 'Missing required fields']);
    exit;
}

if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    http_response_code(422);
    echo json_encode(['ok' => false, 'error' => 'Invalid email']);
    exit;
}

$blocked = [
    'gmail.com','gmail.com.br','googlemail.com',
    'hotmail.com','hotmail.com.br','hotmail.co.uk',
    'outlook.com','outlook.com.br','live.com','live.com.br',
    'yahoo.com','yahoo.com.br',
    'bol.com.br','ig.com.br','uol.com.br','terra.com.br',
    'icloud.com','me.com','mac.com',
    'protonmail.com','proton.me',
    'yandex.com','mail.ru','msn.com','zoho.com',
    'aol.com','gmx.com','zipmail.com.br','globo.com','r7.com',
];
$domain = strtolower(substr(strrchr($email, '@'), 1));
if (in_array($domain, $blocked)) {
    http_response_code(422);
    echo json_encode(['ok' => false, 'error' => 'Personal email not allowed']);
    exit;
}

// Log CSV
$log_dir = __DIR__ . '/../logs';
if (!is_dir($log_dir)) @mkdir($log_dir, 0750, true);
$fp = fopen($log_dir . '/contacts.csv', 'a');
fputcsv($fp, [date('Y-m-d H:i:s'), $nome, $sobrenome, $email, $tel, $msg]);
fclose($fp);

// E-mail
$subject = "=?UTF-8?B?" . base64_encode("Fale Conosco — XDR — $nome $sobrenome | $email") . "?=";
$body  = "Nova mensagem — Fale Conosco (XDR)\n\n";
$body .= "Nome:     $nome $sobrenome\n";
$body .= "E-mail:   $email\n";
$body .= "Telefone: $tel\n";
$body .= "Data:     " . date('d/m/Y H:i:s') . "\n\n";
$body .= "Mensagem:\n$msg\n";

$headers  = "From: Site TYR <contato.tyr@vivasol.com.br>\r\n";
$email_header = str_replace(["\r", "\n"], '', $email);
$headers .= "Reply-To: $email_header\r\n";
$headers .= "MIME-Version: 1.0\r\n";
$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
$headers .= "Content-Transfer-Encoding: 8bit\r\n";
mail('contato@tyr.com.br', $subject, $body, $headers);

echo json_encode(['ok' => true]);
