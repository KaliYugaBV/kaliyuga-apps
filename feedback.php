<?php
// feedback.php — neemt het formulier op feedback.html aan, schrijft het weg in
// een inbox BUITEN public_html (niet via het web bereikbaar) en stuurt het als
// e-mail naar info@kaliyuga-apps.nl. De inbox wordt door de Mac opgehaald
// (scripts/pull_feedback.sh) zodat de triage-taak ernaar kijkt.
// Geen database en geen IP-adressen: alleen wat de inzender zelf heeft
// ingetypt, plus een tijdstempel en een id. Voor de rate limit bewaren we een
// gezouten hash van het IP-adres (niet terug te rekenen), hoogstens 48 uur.
declare(strict_types=1);
ini_set('display_errors', '0');     // nooit paden of fouten naar de bezoeker
ini_set('log_errors', '0');
error_reporting(0);
umask(0077);                        // alles wat we aanmaken: alleen voor de eigenaar

const TO      = 'info@kaliyuga-apps.nl';
const DOMAIN  = 'kaliyuga-apps.nl';
const THANKS  = '/thanks.html';
const BACK    = '/feedback.html';
const DATA    = __DIR__ . '/../feedback';   // ~/domains/<domein>/feedback/ (buiten public_html)
const INBOX   = DATA . '/inbox.jsonl';
const RATE    = DATA . '/rate';
const MAX_POST_BYTES  = 16384;              // groter kan het formulier niet worden
const MAX_PER_HOUR    = 5;                  // per inzender (gehasht IP)
const MAX_PER_DAY_ALL = 100;                // alle inzenders samen, per 24 uur
const MAX_INBOX_BYTES = 5242880;            // 5 MB; daarboven niet meer bijschrijven, wel mailen

function go(string $to): void { header('Location: ' . $to, true, 303); exit; }

function too_many(): void {
    http_response_code(429);
    header('Retry-After: 3600');
    header('Content-Type: text/html; charset=UTF-8');
    echo '<!doctype html><html lang="en"><meta charset="utf-8"><title>Please try again later</title>'
       . '<div style="font-family:system-ui,sans-serif;max-width:34em;margin:4em auto;line-height:1.5">'
       . '<p>Thanks — we already received several messages from here in the last hour. '
       . 'Please try again later, or email <a href="mailto:' . TO . '">' . TO . '</a>.</p>'
       . '<p><a href="/index.html">Back to Kali Yuga</a></p></div></html>';
    exit;
}

// Geheim zout voor de IP-hash; wordt één keer aangemaakt en blijft op de server.
function salt(): string {
    $f = RATE . '/.salt';
    $s = @file_get_contents($f);
    if (!is_string($s) || strlen($s) < 64) {
        $s = bin2hex(random_bytes(32));
        @file_put_contents($f, $s, LOCK_EX);
        @chmod($f, 0600);
    }
    return $s;
}

// Schuivend venster: true = binnen de limiet (en meegeteld), false = limiet bereikt.
function bump(string $file, int $window, int $max): bool {
    $fh = @fopen($file, 'c+');
    if ($fh === false) { return true; }     // opslag stuk: liever doorlaten dan een echte melding weigeren
    flock($fh, LOCK_EX);
    $now = time();
    $ts = [];
    foreach (explode(',', (string)stream_get_contents($fh)) as $t) {
        $t = (int)$t;
        if ($t > $now - $window) { $ts[] = $t; }
    }
    $ok = count($ts) < $max;
    if ($ok) { $ts[] = $now; }
    ftruncate($fh, 0);
    rewind($fh);
    fwrite($fh, implode(',', $ts));
    fflush($fh);
    flock($fh, LOCK_UN);
    fclose($fh);
    @chmod($file, 0600);
    return $ok;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') { go(BACK); }
if ((int)($_SERVER['CONTENT_LENGTH'] ?? 0) > MAX_POST_BYTES) { go(BACK); }
// Alleen ons eigen formulier: een Origin van een ander domein wordt geweigerd.
$origin = (string)($_SERVER['HTTP_ORIGIN'] ?? '');
if ($origin !== '' && $origin !== 'null') {
    $host = strtolower((string)parse_url($origin, PHP_URL_HOST));
    if ($host !== DOMAIN && $host !== 'www.' . DOMAIN) { go(BACK); }
}
// honeypot: mensen zien dit veld niet; bots vullen het in.
if (!empty($_POST['website_url'])) { go(THANKS); }

// Rate limit (per gehasht IP én voor alle inzenders samen).
if (!is_dir(RATE)) { @mkdir(RATE, 0700, true); }
@chmod(DATA, 0700);
$key = substr(hash_hmac('sha256', (string)($_SERVER['REMOTE_ADDR'] ?? ''), salt()), 0, 32);
if (!bump(RATE . '/ip-' . $key, 3600, MAX_PER_HOUR)) { too_many(); }
if (!bump(RATE . '/all', 86400, MAX_PER_DAY_ALL)) { too_many(); }
// Opruimen: IP-hashes ouder dan 48 uur gaan weg.
if (random_int(1, 20) === 1) {
    foreach (glob(RATE . '/ip-*') ?: [] as $f) {
        if ((int)@filemtime($f) < time() - 172800) { @unlink($f); }
    }
}

function field(string $k, int $max): string {
    $v = (isset($_POST[$k]) && is_string($_POST[$k])) ? $_POST[$k] : '';
    if (!mb_check_encoding($v, 'UTF-8')) { return ''; }
    $v = str_replace(["\r\n", "\r"], "\n", $v);
    $v = preg_replace('/[^\P{C}\n\t]/u', '', $v) ?? '';   // stuurtekens eruit, regeleinden en tabs mogen
    return mb_substr(trim($v), 0, $max);
}
$kind    = field('kind', 20);
$app     = field('app', 60);
$message = field('message', 4000);
$device  = field('device', 120);
$where   = field('where', 2000);
$email   = field('email', 200);
if ($message === '' || $app === '') { go(BACK); }
if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) { $email = ''; }

$kinds = ['idea' => 'Idee', 'change' => 'Zou anders moeten werken', 'bug' => 'Werkt niet'];
if (!isset($kinds[$kind])) { $kind = 'other'; }
$label = $kinds[$kind] ?? 'Feedback';
$subject = "[$app] $label";
$body = "App:      $app\n"
      . "Soort:    $label\n"
      . ($device !== '' ? "Toestel:  $device\n" : '')
      . ($email  !== '' ? "Afzender: $email\n" : "Afzender: (niet opgegeven)\n")
      . "\n--- Bericht ---\n$message\n"
      . ($where !== '' ? "\n--- Waar het misgaat ---\n$where\n" : '')
      . "\n(verstuurd via " . DOMAIN . "/feedback.html)\n";

// Onderwerp en headers mogen geen regeleinden bevatten (header injection).
$subject = str_replace(["\r", "\n"], ' ', $subject);
$headers = "From: Kali Yuga feedback <noreply@" . DOMAIN . ">\r\n"
         . "Content-Type: text/plain; charset=UTF-8\r\n";
if ($email !== '') { $headers .= "Reply-To: " . str_replace(["\r", "\n"], '', $email) . "\r\n"; }

// 1. inbox (JSON Lines, één regel per inzending, alleen leesbaar voor de eigenaar).
//    Is de inbox vol of mislukt schrijven, dan gaat de mail alsnog.
$id = gmdate('Ymd\THis\Z') . '-' . substr(hash('sha256', $message . microtime(true)), 0, 8);
$rec = ['id' => $id, 'received' => gmdate('c'), 'kind' => $kind, 'app' => $app,
        'message' => $message, 'device' => $device, 'where' => $where, 'email' => $email];
clearstatcache();
if (!is_file(INBOX) || (int)filesize(INBOX) < MAX_INBOX_BYTES) {
    @file_put_contents(INBOX, json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
                                                | JSON_INVALID_UTF8_SUBSTITUTE) . "\n",
                       FILE_APPEND | LOCK_EX);
    @chmod(INBOX, 0600);
} else {
    $body .= "\nLET OP: de inbox op de server is vol (5 MB) — dit bericht staat alleen in deze mail.\n";
}

// 2. mail
$body .= "id: $id\n";
@mail(TO, '=?UTF-8?B?' . base64_encode($subject) . '?=', $body, $headers);
go(THANKS);
