<?php
// feedback.php — neemt het formulier op feedback.html aan, schrijft het weg in
// een inbox BUITEN public_html (niet via het web bereikbaar) en stuurt het als
// e-mail naar info@kaliyuga-apps.nl. De inbox wordt door de Mac opgehaald
// (scripts/pull_feedback.sh) zodat de triage-taak er drie keer per dag naar
// kijkt. Geen database, geen logbestand met IP-adressen: alleen wat de
// inzender zelf heeft ingetypt, plus een tijdstempel en een id.
declare(strict_types=1);
const TO      = 'info@kaliyuga-apps.nl';
const DOMAIN  = 'kaliyuga-apps.nl';
const THANKS  = '/thanks.html';
const BACK    = '/feedback.html';
const INBOX   = __DIR__ . '/../feedback/inbox.jsonl';   // ~/domains/<domein>/feedback/

if ($_SERVER['REQUEST_METHOD'] !== 'POST') { header('Location: ' . BACK, true, 303); exit; }
// honeypot: mensen zien dit veld niet; bots vullen het in.
if (!empty($_POST['website_url'])) { header('Location: ' . THANKS, true, 303); exit; }

function field(string $k, int $max): string {
    $v = isset($_POST[$k]) ? (string)$_POST[$k] : '';
    $v = str_replace(["
", "
"], "
", $v);
    $v = preg_replace('/[^\P{C}
	]/u', '', $v) ?? '';   // stuurtekens eruit, regeleinden mogen
    return mb_substr(trim($v), 0, $max);
}
$kind    = field('kind', 20);
$app     = field('app', 60);
$message = field('message', 4000);
$device  = field('device', 120);
$where   = field('where', 2000);
$email   = field('email', 200);
if ($message === '' || $app === '') { header('Location: ' . BACK, true, 303); exit; }
if ($email !== '' && !filter_var($email, FILTER_VALIDATE_EMAIL)) { $email = ''; }

$kinds = ['idea' => 'Idee', 'change' => 'Zou anders moeten werken', 'bug' => 'Werkt niet'];
$label = $kinds[$kind] ?? 'Feedback';
$subject = "[$app] $label";
$body = "App:      $app
Soort:    $label
"
      . ($device !== '' ? "Toestel:  $device
" : '')
      . ($email  !== '' ? "Afzender: $email
" : "Afzender: (niet opgegeven)
")
      . "
--- Bericht ---
$message
"
      . ($where !== '' ? "
--- Waar het misgaat ---
$where
" : '')
      . "
(verstuurd via " . DOMAIN . "/feedback.html)
";

// Onderwerp en headers mogen geen regeleinden bevatten (header injection).
$subject = str_replace(["
", "
"], ' ', $subject);
$headers = "From: Kali Yuga feedback <noreply@" . DOMAIN . ">
"
         . "Content-Type: text/plain; charset=UTF-8
";
if ($email !== '') { $headers .= "Reply-To: " . str_replace(["
", "
"], '', $email) . "
"; }

// 1. inbox (JSON Lines, één regel per inzending). Mislukt dit, dan gaat de
//    mail alsnog; de inzender merkt er niets van.
$id = gmdate('Ymd\THis\Z') . '-' . substr(hash('sha256', $message . microtime(true)), 0, 8);
$rec = ['id' => $id, 'received' => gmdate('c'), 'kind' => $kind, 'app' => $app,
        'message' => $message, 'device' => $device, 'where' => $where, 'email' => $email];
$dir = dirname(INBOX);
if (!is_dir($dir)) { @mkdir($dir, 0700, true); }
@file_put_contents(INBOX, json_encode($rec, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n",
                   FILE_APPEND | LOCK_EX);

// 2. mail
$body .= "id: $id\n";
@mail(TO, '=?UTF-8?B?' . base64_encode($subject) . '?=', $body, $headers);
header('Location: ' . THANKS, true, 303);
