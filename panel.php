<?php
// ===== SENTINELOPS // SECURITY CONTROL PLANE =====
// Este archivo puede operar con privilegios elevados. Las capacidades destructivas
// permanecen desactivadas salvo que el administrador las habilite expresamente.
function env_bool($name, $default = false)
{
    $value = getenv($name);
    if ($value === false || $value === '') return $default;
    return filter_var($value, FILTER_VALIDATE_BOOLEAN);
}

function env_int($name, $default, $minimum, $maximum)
{
    $value = getenv($name);
    if ($value === false || !preg_match('/^-?\d+$/D', trim($value))) return intval($default);
    return max(intval($minimum), min(intval($maximum), intval($value)));
}

function secure_random_hex($bytes = 32)
{
    if (function_exists('random_bytes')) {
        try { return bin2hex(random_bytes($bytes)); } catch (Exception $e) { /* fallback */ }
    }
    return bin2hex(openssl_random_pseudo_bytes($bytes));
}

$requestIsHttps = (!empty($_SERVER['HTTPS']) && strtolower($_SERVER['HTTPS']) !== 'off') ||
    (isset($_SERVER['SERVER_PORT']) && intval($_SERVER['SERVER_PORT']) === 443);
$remoteAddress = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
$trustedProxies = array_values(array_filter(array_map('trim', explode(',', getenv('PANEL_TRUSTED_PROXIES') ?: ''))));
// Helper: detect common private/loopback addresses when no explicit trust list provided
function is_private_or_loopback_ip($ip)
{
    if (!is_string($ip) || $ip === '') return false;
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        // IPv4 private ranges and loopback
        return (bool)preg_match('/^(127\\.|10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[0-1])\\.)/', $ip);
    }
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        // IPv6 loopback and unique/local addresses (fc00::/7) and link-local fe80::/10
        $lower = strtolower($ip);
        if ($lower === '::1') return true;
        return (bool)(strpos($lower, 'fc') === 0 || strpos($lower, 'fd') === 0 || strpos($lower, 'fe80') === 0);
    }
    return false;
}

// Decide whether to trust forwarded headers from the remote address.
$useForwardedProto = false;
if (!empty($trustedProxies)) {
    $useForwardedProto = in_array($remoteAddress, $trustedProxies, true);
} else {
    // Convenience: if no trust list is configured, treat private/loopback remote addrs as proxies
    $useForwardedProto = is_private_or_loopback_ip($remoteAddress);
}

if (!$requestIsHttps && $useForwardedProto && isset($_SERVER['HTTP_X_FORWARDED_PROTO'])) {
    $forwardedProto = strtolower(trim(explode(',', $_SERVER['HTTP_X_FORWARDED_PROTO'])[0]));
    $requestIsHttps = $forwardedProto === 'https';
}
$loopbackRequest = in_array($remoteAddress, array('127.0.0.1', '::1'), true);

ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_secure', $requestIsHttps ? '1' : '0');
ini_set('session.cookie_samesite', 'Strict');
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.use_trans_sid', '0');
session_name('SENTINELOPS_SID');
session_save_path(sys_get_temp_dir());
session_start();

// Logging de errores sin exposición al cliente
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// Headers de seguridad HTTP
$cspNonce = base64_encode(pack('H*', secure_random_hex(18)));
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: no-referrer');
header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
header('Cross-Origin-Opener-Policy: same-origin');
header('Cross-Origin-Resource-Policy: same-origin');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header("Content-Security-Policy: default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; object-src 'none'; script-src 'self' 'nonce-" . $cspNonce . "'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'");
if ($requestIsHttps) {
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
}

// Configuración
define('SESSION_LIFETIME', 3600); // 1 hora
define('SESSION_IDLE_TIMEOUT', 1200); // 20 minutos sin actividad
define('MAX_FILE_SIZE', 65536);   // 64KB para visualización
define('MAX_LOGIN_ATTEMPTS', 5);  // Intentos máximos de login
define('LOGIN_LOCKOUT_TIME', 900); // 15 minutos de bloqueo

$configuredDataDir = getenv('PANEL_DATA_DIR');
$panelDataDir = $configuredDataDir ? rtrim($configuredDataDir, DIRECTORY_SEPARATOR) :
    sys_get_temp_dir() . '/sentinelops-' . substr(hash('sha256', __FILE__), 0, 12);
if (!file_exists($panelDataDir)) @mkdir($panelDataDir, 0700, true);
if (is_dir($panelDataDir) && !is_link($panelDataDir)) @chmod($panelDataDir, 0700);
$dataOwnerOk = !function_exists('posix_geteuid') || (@fileowner($panelDataDir) === posix_geteuid());
$dataMode = @fileperms($panelDataDir);
$storageReady = is_dir($panelDataDir) && !is_link($panelDataDir) && is_writable($panelDataDir) && $dataOwnerOk && $dataMode !== false && (($dataMode & 0077) === 0);
define('PANEL_DATA_DIR', $panelDataDir);
define('PANEL_STORAGE_READY', $storageReady);
define('LOCKOUT_FILE', PANEL_DATA_DIR . '/login-lockouts.json');
define('PANEL_EVENT_LOG', PANEL_DATA_DIR . '/security-events.jsonl');
define('NETWORK_DISCOVERY_LOCK', PANEL_DATA_DIR . '/network-discovery.lock');
define('NETWORK_DISCOVERY_STATE', PANEL_DATA_DIR . '/network-discovery.json');
define('NETWORK_INVENTORY_LOCK', PANEL_DATA_DIR . '/network-inventory-rate.json');

$configuredBase = getenv('PANEL_ALLOWED_BASE_PATH');
$resolvedBase = realpath($configuredBase ? $configuredBase : dirname(__FILE__));
define('ALLOWED_BASE_PATH', $resolvedBase !== false ? $resolvedBase : dirname(__FILE__));
define('ENABLE_SHELL', env_bool('PANEL_ENABLE_SHELL', true));
define('ENABLE_FILE_WRITE', env_bool('PANEL_ENABLE_FILE_WRITE', false));
define('ENABLE_PROCESS_CONTROL', env_bool('PANEL_ENABLE_PROCESS_CONTROL', false));
define('ENABLE_NETWORK_DISCOVERY', env_bool('PANEL_ENABLE_NETWORK_DISCOVERY', false));
define('ENABLE_CONTAINER_NETWORK_DISCOVERY', env_bool('PANEL_NETWORK_ALLOW_CONTAINER', false));
define('NETWORK_DISCOVERY_ALLOWED_CIDRS', trim(getenv('PANEL_NETWORK_ALLOWED_CIDRS') ?: ''));
define('NETWORK_DISCOVERY_MAX_HOSTS', env_int('PANEL_NETWORK_MAX_HOSTS', 256, 16, 256));
define('NETWORK_DISCOVERY_TIMEOUT', env_int('PANEL_NETWORK_TIMEOUT', 20, 3, 30));
define('NETWORK_DISCOVERY_COOLDOWN', env_int('PANEL_NETWORK_COOLDOWN', 45, 15, 3600));
define('AUDIT_SCAN_MAX_FILES', 2500);
define('AUDIT_SCAN_MAX_SECONDS', 8);

// URL segura para redirecciones (evita Open Redirect via PHP_SELF)
define('SELF_URL', $_SERVER['SCRIPT_NAME']);

// ===== CSRF TOKEN =====
function csrf_token() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = secure_random_hex(32);
    }
    return $_SESSION['csrf_token'];
}

function csrf_validate() {
    $token = isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '';
    if (!is_string($token) || empty($_SESSION['csrf_token']) || empty($token) || !hash_equals($_SESSION['csrf_token'], $token)) {
        security_event('csrf_rejected', array('route' => isset($_GET['api']) ? $_GET['api'] : 'form'));
        http_response_code(403);
        echo json_encode(array('error' => 'CSRF token invalid'));
        exit;
    }
}

function csrf_validate_or_die() {
    $token = isset($_POST['csrf_token']) ? $_POST['csrf_token'] : '';
    if (!is_string($token) || empty($_SESSION['csrf_token']) || empty($token) || !hash_equals($_SESSION['csrf_token'], $token)) {
        security_event('csrf_rejected', array('route' => 'logout'));
        http_response_code(403);
        die('Forbidden: Invalid CSRF token.');
    }
}

// ===== RATE LIMITING (Brute Force Protection) =====
function get_client_ip() {
    // No confiar en X-Forwarded-For (spoofable), usar REMOTE_ADDR
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'unknown';
    return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : 'unknown';
}

function security_event($event, $details = array())
{
    $safeDetails = array();
    foreach ($details as $key => $value) {
        if (preg_match('/pass|secret|token|command|cookie/i', (string)$key)) continue;
        if (is_scalar($value) || $value === null) $safeDetails[$key] = substr((string)$value, 0, 180);
    }
    $entry = array(
        'time' => gmdate('c'),
        'event' => substr((string)$event, 0, 64),
        'ip' => get_client_ip(),
        'principal' => isset($_SESSION['principal']) ? substr((string)$_SESSION['principal'], 0, 128) : (isset($safeDetails['principal']) ? $safeDetails['principal'] : 'anonymous'),
        'role' => isset($_SESSION['role']) ? substr((string)$_SESSION['role'], 0, 24) : 'none',
        'client' => substr(hash('sha256', isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : ''), 0, 12),
        'session' => session_id() ? substr(hash('sha256', session_id()), 0, 12) : null,
        'details' => $safeDetails
    );
    $line = json_encode($entry, JSON_UNESCAPED_SLASHES) . "\n";
    if (env_bool('PANEL_SYSLOG', true) && function_exists('syslog')) {
        @openlog('sentinelops-panel', LOG_PID, defined('LOG_AUTHPRIV') ? LOG_AUTHPRIV : LOG_USER);
        @syslog(LOG_NOTICE, trim($line));
        @closelog();
    }
    if (PANEL_STORAGE_READY && is_file(PANEL_EVENT_LOG) && !is_link(PANEL_EVENT_LOG) && @filesize(PANEL_EVENT_LOG) > 5242880) {
        @rename(PANEL_EVENT_LOG, PANEL_EVENT_LOG . '.1');
    }
    $fp = PANEL_STORAGE_READY && !is_link(PANEL_EVENT_LOG) ? @fopen(PANEL_EVENT_LOG, 'ab') : false;
    if ($fp) {
        if (flock($fp, LOCK_EX)) {
            fwrite($fp, $line);
            fflush($fp);
            flock($fp, LOCK_UN);
        }
        fclose($fp);
        @chmod(PANEL_EVENT_LOG, 0600);
    } else {
        error_log('[sentinelops] ' . trim($line));
    }
}

function mutate_lockout_data($callback)
{
    $fp = PANEL_STORAGE_READY && !is_link(LOCKOUT_FILE) ? @fopen(LOCKOUT_FILE, 'c+') : false;
    if (!$fp) return null;
    @chmod(LOCKOUT_FILE, 0600);
    if (!flock($fp, LOCK_EX)) {
        fclose($fp);
        return null;
    }
    rewind($fp);
    $raw = stream_get_contents($fp);
    $data = json_decode($raw ?: '{}', true);
    if (!is_array($data)) $data = array();
    foreach ($data as $key => $entry) {
        if (!is_array($entry) || empty($entry['last_attempt']) || time() - intval($entry['last_attempt']) > 86400) {
            unset($data[$key]);
        }
    }
    $result = $callback($data);
    $newData = isset($result['data']) && is_array($result['data']) ? $result['data'] : $data;
    rewind($fp);
    ftruncate($fp, 0);
    fwrite($fp, json_encode($newData));
    fflush($fp);
    flock($fp, LOCK_UN);
    fclose($fp);
    return isset($result['value']) ? $result['value'] : null;
}

function rate_limit_keys($username = '')
{
    $keys = array('ip:' . hash('sha256', get_client_ip()), 'global');
    if (is_string($username) && trim($username) !== '') $keys[] = 'account:' . hash('sha256', strtolower(trim($username)));
    return $keys;
}

function is_locked_out($username = '')
{
    $keys = rate_limit_keys($username);
    $result = mutate_lockout_data(function ($data) use ($keys) {
        $locked = false;
        foreach ($keys as $key) {
            if (!isset($data[$key])) continue;
            $age = time() - intval($data[$key]['last_attempt']);
            if ($age >= LOGIN_LOCKOUT_TIME) { unset($data[$key]); continue; }
            $threshold = $key === 'global' ? 50 : (strpos($key, 'account:') === 0 ? 10 : MAX_LOGIN_ATTEMPTS);
            if (intval($data[$key]['attempts']) >= $threshold) $locked = true;
        }
        return array('data' => $data, 'value' => $locked);
    });
    return $result === null ? true : (bool)$result;
}

function record_failed_attempt($username = '')
{
    $keys = rate_limit_keys($username);
    mutate_lockout_data(function ($data) use ($keys) {
        foreach ($keys as $key) {
            if (!isset($data[$key]) || time() - intval($data[$key]['last_attempt']) >= LOGIN_LOCKOUT_TIME) $data[$key] = array('attempts' => 0, 'last_attempt' => 0);
            $data[$key]['attempts'] = intval($data[$key]['attempts']) + 1;
            $data[$key]['last_attempt'] = time();
        }
        return array('data' => $data, 'value' => null);
    });
}

function clear_failed_attempts($username = '')
{
    $keys = rate_limit_keys($username);
    mutate_lockout_data(function ($data) use ($keys) {
        foreach ($keys as $key) if ($key !== 'global') unset($data[$key]);
        return array('data' => $data, 'value' => null);
    });
}

$defaultUserHash = '$2y$12$646Iz4CnYD1aeskdo/l0t.SjDH2m2447RoVkmeSh2TuuQo04ZCXCO';
$defaultPassHash = '$2y$12$eOF10qO36HbuwrJFhUSF3OhCfZFhTs8hicyoTzAtO6/0AFX0R7sG2';
$HASH_USER = getenv('PANEL_USER_HASH') ?: $defaultUserHash;
$HASH_PASS = getenv('PANEL_PASSWORD_HASH') ?: $defaultPassHash;

function load_panel_users_file(&$error)
{
    $error = null;
    $configured = getenv('PANEL_USERS_FILE');
    if ($configured === false || trim($configured) === '') return array();
    $path = realpath($configured);
    if ($path === false || !is_file($path) || !is_readable($path) || @filesize($path) > 131072) {
        $error = 'PANEL_USERS_FILE is missing, unreadable or too large';
        return array();
    }
    $panelRoot = realpath(dirname(__FILE__));
    if ($panelRoot && ($path === $panelRoot || strpos($path, $panelRoot . DIRECTORY_SEPARATOR) === 0)) {
        $error = 'PANEL_USERS_FILE must be outside the webroot';
        return array();
    }
    $mode = @fileperms($path);
    if ($mode === false || ($mode & 0027)) {
        $error = 'PANEL_USERS_FILE must use mode 0640 or stricter';
        return array();
    }
    $decoded = json_decode(@file_get_contents($path, false, null, 0, 131072), true);
    if (!is_array($decoded)) {
        $error = 'PANEL_USERS_FILE contains invalid JSON';
        return array();
    }
    $source = isset($decoded['users']) && is_array($decoded['users']) ? $decoded['users'] : $decoded;
    $users = array();
    foreach ($source as $username => $record) {
        if (!is_string($username) || !preg_match('/^[a-zA-Z0-9_.@-]{1,128}$/D', $username) || !is_array($record)) continue;
        $hash = isset($record['password_hash']) && is_string($record['password_hash']) ? $record['password_hash'] : '';
        $role = isset($record['role']) && is_string($record['role']) ? strtolower($record['role']) : 'auditor';
        $hashInfo = function_exists('password_get_info') ? password_get_info($hash) : array('algoName' => 'unknown');
        if (strlen($hash) < 20 || strlen($hash) > 255 || !isset($hashInfo['algoName']) || $hashInfo['algoName'] === 'unknown' || !in_array($role, array('admin', 'operator', 'auditor'), true)) continue;
        $users[$username] = array('password_hash' => $hash, 'role' => $role, 'enabled' => !isset($record['enabled']) || $record['enabled'] === true);
    }
    if (!$users) $error = 'PANEL_USERS_FILE has no valid users';
    return $users;
}

$PANEL_USERS_ERROR = null;
$PANEL_USERS = load_panel_users_file($PANEL_USERS_ERROR);
define('PANEL_USERS_CONFIGURED', getenv('PANEL_USERS_FILE') !== false && trim(getenv('PANEL_USERS_FILE')) !== '');
define('MULTI_USER_AUTH', PANEL_USERS_CONFIGURED && !$PANEL_USERS_ERROR && count($PANEL_USERS) > 0);
define('USING_EMBEDDED_CREDENTIALS', !MULTI_USER_AUTH && ($HASH_USER === $defaultUserHash || $HASH_PASS === $defaultPassHash));

function session_can_capability($capability)
{
    $role = isset($_SESSION['role']) ? $_SESSION['role'] : 'admin';
    if ($capability === 'shell') return $role === 'admin' && ENABLE_SHELL;
    if ($capability === 'file_write') return in_array($role, array('admin', 'operator'), true) && ENABLE_FILE_WRITE;
    if ($capability === 'process_control') return in_array($role, array('admin', 'operator'), true) && ENABLE_PROCESS_CONTROL;
    if ($capability === 'file_read') return in_array($role, array('admin', 'operator'), true);
    if ($capability === 'raw_observability') return in_array($role, array('admin', 'operator'), true);
    if ($capability === 'network_discovery') {
        $containerAllowed = ENABLE_CONTAINER_NETWORK_DISCOVERY || !network_namespace_info()['container'];
        return in_array($role, array('admin', 'operator'), true) && ENABLE_NETWORK_DISCOVERY && (bool)network_configured_allowed_cidrs() && $containerAllowed;
    }
    return false;
}

if (!function_exists('password_verify')) {
    function password_verify($password, $hash)
    {
        if (!function_exists('crypt'))
            return false;
        $res = crypt($password, $hash);
        if (!is_string($res) || strlen($res) <= 13)
            return false;
        return hash_equals($hash, $res);
    }
}
if (!function_exists('hash_equals')) {
    function hash_equals($a, $b)
    {
        if (strlen($a) !== strlen($b))
            return false;
        $res = 0;
        for ($i = 0; $i < strlen($a); $i++)
            $res |= (ord($a[$i]) ^ ord($b[$i]));
        return $res === 0;
    }
}

// Expiración absoluta, inactividad y enlace ligero al navegador.
if (!empty($_SESSION['authenticated'])) {
    $now = time();
    $loginAt = isset($_SESSION['login_time']) ? intval($_SESSION['login_time']) : 0;
    $lastSeen = isset($_SESSION['last_activity']) ? intval($_SESSION['last_activity']) : $loginAt;
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    $uaFingerprint = hash('sha256', $ua);
    $expired = !$loginAt || ($now - $loginAt) > SESSION_LIFETIME || ($now - $lastSeen) > SESSION_IDLE_TIMEOUT;
    $changedClient = !empty($_SESSION['ua_fingerprint']) && !hash_equals($_SESSION['ua_fingerprint'], $uaFingerprint);
    if ($expired || $changedClient) {
        security_event('session_terminated', array('reason' => $changedClient ? 'client_changed' : 'expired'));
        if (!empty($_SESSION['terminal_ids']) && is_array($_SESSION['terminal_ids'])) foreach ($_SESSION['terminal_ids'] as $termId) if (wsValidId($termId)) wsKill($termId);
        $_SESSION = array();
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
        }
        session_destroy();
        header('Location: ' . SELF_URL);
        exit;
    }
    $_SESSION['last_activity'] = $now;
}

function cmd($c, $fallback = '')
{
    $shell = is_executable('/bin/sh') ? '/bin/sh' : 'sh';
    $wrapped = escapeshellcmd($shell) . ' -c ' . escapeshellarg($c);
    if (is_executable('/usr/bin/timeout')) {
        $wrapped = '/usr/bin/timeout 8s ' . $wrapped;
    } elseif (is_executable('/bin/timeout')) {
        $wrapped = '/bin/timeout 8s ' . $wrapped;
    }
    $o = @shell_exec($wrapped . ' 2>/dev/null');
    if ($o === null) return $fallback;
    return trim(substr($o, 0, 1048576));
}

function command_exists($cmd)
{
    if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $cmd)) return false;
    $where = cmd('command -v ' . escapeshellarg($cmd));
    return !empty($where);
}

function run_shell_limited($command, $cwd, $timeoutSeconds = 30, $maxOutputBytes = 262144)
{
    if (!is_string($command) || $command === '' || strlen($command) > 8192) {
        return array('stdout' => '', 'stderr' => 'Invalid command', 'exit_code' => 126, 'timed_out' => false, 'truncated' => false);
    }
    $cwd = validate_path($cwd);
    if (!$cwd || !is_dir($cwd)) $cwd = ALLOWED_BASE_PATH;
    $shell = is_executable('/bin/bash') ? '/bin/bash' : '/bin/sh';
    $timeoutSeconds = max(1, min(30, intval($timeoutSeconds)));
    $timeoutBin = is_executable('/usr/bin/timeout') ? '/usr/bin/timeout' : (is_executable('/bin/timeout') ? '/bin/timeout' : null);
    $runner = $timeoutBin ? escapeshellarg($timeoutBin) . ' -k 2s ' . $timeoutSeconds . 's ' : '';
    $runner .= escapeshellarg($shell) . ' -c ' . escapeshellarg($command);
    $descriptors = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
    $environment = array('PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LANG' => 'C.UTF-8', 'TERM' => 'xterm-256color');
    $process = @proc_open($runner, $descriptors, $pipes, $cwd, $environment);
    if (!is_resource($process)) return array('stdout' => '', 'stderr' => 'Execution failed', 'exit_code' => 126, 'timed_out' => false, 'truncated' => false);
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $stdout = '';
    $stderr = '';
    $started = microtime(true);
    $timedOut = false;
    $truncated = false;
    while (true) {
        $read = array();
        if (!feof($pipes[1])) $read[] = $pipes[1];
        if (!feof($pipes[2])) $read[] = $pipes[2];
        if ($read) {
            $write = null;
            $except = null;
            @stream_select($read, $write, $except, 0, 200000);
            foreach ($read as $stream) {
                $chunk = fread($stream, 8192);
                if ($chunk === false || $chunk === '') continue;
                if ($stream === $pipes[1]) $stdout .= $chunk; else $stderr .= $chunk;
            }
        } else {
            usleep(20000);
        }
        if (strlen($stdout) + strlen($stderr) > $maxOutputBytes) {
            $truncated = true;
            @proc_terminate($process, 9);
            break;
        }
        $status = proc_get_status($process);
        if (!$status['running']) break;
        if ((microtime(true) - $started) > ($timeoutSeconds + 2)) {
            $timedOut = true;
            @proc_terminate($process, 9);
            break;
        }
    }
    $stdout .= stream_get_contents($pipes[1]);
    $stderr .= stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exitCode = proc_close($process);
    if ($exitCode === 124 || $exitCode === 137) $timedOut = true;
    if (strlen($stdout) + strlen($stderr) > $maxOutputBytes) {
        $truncated = true;
        $stdout = substr($stdout, 0, $maxOutputBytes);
        $stderr = substr($stderr, 0, max(0, $maxOutputBytes - strlen($stdout)));
    }
    return array('stdout' => $stdout, 'stderr' => $stderr, 'exit_code' => $exitCode, 'timed_out' => $timedOut, 'truncated' => $truncated);
}

// ---------- WebShell Terminal ----------
function wsGenId()
{
    return secure_random_hex(8);
}

function wsValidId($id)
{
    return is_string($id) && preg_match('/^[a-f0-9]{16}$/D', $id);
}

function wsDir($id)
{
    if (!wsValidId($id)) return false;
    return PANEL_DATA_DIR . '/terminal-' . substr(hash('sha256', session_id()), 0, 24) . '-' . $id;
}

function wsInit($id)
{
    $dir = wsDir($id);
    if (!$dir) return false;
    @mkdir($dir, 0700, true);
    file_put_contents("$dir/cwd", ALLOWED_BASE_PATH);
    file_put_contents("$dir/created", time());
    return true;
}

function wsExists($id)
{
    $dir = wsDir($id);
    return $dir && is_dir($dir) && file_exists("$dir/cwd");
}

function wsGetCwd($id)
{
    $dir = wsDir($id);
    if (!$dir) return '/tmp';
    $cwd = @file_get_contents("$dir/cwd");
    $validated = $cwd ? validate_path(trim($cwd)) : false;
    return ($validated && is_dir($validated)) ? $validated : ALLOWED_BASE_PATH;
}

function wsExec($id, $command)
{
    $dir = wsDir($id);
    if (!wsExists($id))
        return array('output' => '[!] Session expired or not found', 'cwd' => ALLOWED_BASE_PATH, 'active' => false);

    $cwd = wsGetCwd($id);
    $command = trim($command);

    if ($command === '')
        return array('output' => '', 'cwd' => $cwd, 'active' => true);

    // clear / reset
    if ($command === 'clear' || $command === 'reset')
        return array('output' => '__CLEAR__', 'cwd' => $cwd, 'active' => true);

    // exit
    if ($command === 'exit' || $command === 'logout') {
        wsKill($id);
        return array('output' => '[*] Session terminated.', 'cwd' => $cwd, 'active' => false);
    }

    // cd handling
    if (preg_match('/^cd\s*(.*)?$/', $command, $m)) {
        $target = trim(isset($m[1]) ? $m[1] : '');
        if ($target === '' || $target === '~') {
            $target = @getenv('HOME') ?: '/root';
        } elseif ($target === '-') {
            $prev = @file_get_contents("$dir/prev_cwd");
            $target = ($prev && is_dir($prev)) ? $prev : $cwd;
        }
        if ($target[0] !== '/')
            $target = $cwd . '/' . $target;
        $real = validate_path($target);
        if ($real && is_dir($real)) {
            file_put_contents("$dir/prev_cwd", $cwd);
            file_put_contents("$dir/cwd", $real);
            return array('output' => '', 'cwd' => $real, 'active' => true);
        } else {
            return array('output' => "bash: cd: $target: No such file or directory", 'cwd' => $cwd, 'active' => true);
        }
    }

    // Ejecución acotada; se añade pwd para conservar el directorio de la terminal.
    $fullCmd = "cd " . escapeshellarg($cwd) . " 2>/dev/null; " . $command . "; echo '___GSTXX_CWD___'; pwd";
    $execution = run_shell_limited($fullCmd, $cwd, 30, 262144);
    $stdout = $execution['stdout'];
    $stderr = $execution['stderr'];
    $exitCode = $execution['exit_code'];

    // Extract new CWD from output
    $output = $stdout;
    $marker = '___GSTXX_CWD___';
    $markerPos = strrpos($output, $marker);
    if ($markerPos !== false) {
        $afterMarker = trim(substr($output, $markerPos + strlen($marker)));
        $output = substr($output, 0, $markerPos);
        $validatedCwd = $afterMarker ? validate_path($afterMarker) : false;
        if ($validatedCwd && is_dir($validatedCwd)) {
            file_put_contents("$dir/prev_cwd", $cwd);
            file_put_contents("$dir/cwd", $validatedCwd);
            $cwd = $validatedCwd;
        }
    }

    // Combine stdout/stderr
    $combined = rtrim($output);
    if ($stderr)
        $combined .= ($combined ? "\n" : '') . rtrim($stderr);

    if ($execution['truncated']) $combined .= "\n[!] Output truncated at 256 KiB.";
    if ($execution['timed_out']) $combined .= "\n[!] Command timed out.";
    return array('output' => $combined, 'cwd' => $cwd, 'active' => true, 'exit_code' => $exitCode, 'truncated' => $execution['truncated'], 'timed_out' => $execution['timed_out']);
}

function wsKill($id)
{
    $dir = wsDir($id);
    if (!$dir || strpos($dir, PANEL_DATA_DIR . '/terminal-') !== 0) return false;
    @array_map('unlink', glob("$dir/*"));
    @rmdir($dir);
    return true;
}

// ---------- Información del sistema ----------
function getSystemInfo()
{
    $i = array();
    $load = sys_getloadavg();
    $cores = intval(cmd("nproc")) ?: 1;
    $i['cpu'] = array(
        'usage' => min(round($load[0] * 100 / $cores, 1), 100),
        'cores' => $cores,
        'load' => $load,
        'model' => cmd("grep 'model name' /proc/cpuinfo|head -1|cut -d: -f2") ?: 'Unknown',
        'freq' => cmd("grep 'cpu MHz' /proc/cpuinfo|head -1|awk '{print $4}'") . ' MHz'
    );
    $m = preg_split('/\s+/', cmd("free -m|grep Mem"));
    $mt = intval(isset($m[1]) ? $m[1] : 0);
    $mu = intval(isset($m[2]) ? $m[2] : 0);
    $i['mem'] = array(
        'total' => $mt,
        'used' => $mu,
        'free' => $mt - $mu,
        'pct' => $mt > 0 ? round($mu / $mt * 100, 1) : 0
    );
    $sw = preg_split('/\s+/', cmd("free -m|grep Swap"));
    $st = intval(isset($sw[1]) ? $sw[1] : 0);
    $su = intval(isset($sw[2]) ? $sw[2] : 0);
    $i['swap'] = array(
        'total' => $st,
        'used' => $su,
        'pct' => $st > 0 ? round($su / $st * 100, 1) : 0
    );
    $nv = cmd("nvidia-smi --query-gpu=utilization.gpu,memory.total,memory.used,temperature.gpu,name --format=csv,noheader,nounits");
    if ($nv) {
        $g = array_map('trim', explode(',', $nv));
        $i['gpu'] = array(
            'usage' => intval(isset($g[0]) ? $g[0] : 0),
            'mem_total' => round((isset($g[1]) ? $g[1] : 0) / 1024, 1),
            'mem_used' => round((isset($g[2]) ? $g[2] : 0) / 1024, 1),
            'temp' => isset($g[3]) ? $g[3] : 0,
            'name' => isset($g[4]) ? $g[4] : 'GPU'
        );
    } else {
        $i['gpu'] = array('usage' => 0, 'name' => 'No GPU', 'mem_total' => 0, 'mem_used' => 0, 'temp' => 0);
    }
    $ifs = array(); $networkSources = array();
    foreach (network_collect_interfaces($networkSources) as $interface) {
        if (!$interface['addresses']) {
            $ifs[] = array('n' => $interface['name'], 'ip' => 'sin dirección', 'family' => null, 'prefix' => null, 'state' => $interface['state']);
            continue;
        }
        foreach ($interface['addresses'] as $address) {
            $ifs[] = array('n' => $interface['name'], 'ip' => $address['address'], 'family' => $address['family'], 'prefix' => $address['prefix'], 'state' => $interface['state']);
        }
    }
    $i['net'] = $ifs;
    $i['host'] = cmd("hostname") ?: 'localhost';
    $i['up'] = cmd("uptime -p") ?: 'N/A';
    $i['kern'] = cmd("uname -r") ?: 'N/A';
    $i['os'] = cmd("grep PRETTY_NAME /etc/os-release|cut -d= -f2|tr -d '\"'") ?: 'Linux';
    $i['arch'] = cmd("uname -m") ?: 'N/A';
    $i['user'] = cmd("whoami") ?: 'N/A';
    $i['priv'] = cmd("id") ?: 'N/A';

    $disks = array();
    foreach (explode("\n", cmd("df -h|grep '^/dev'")) as $dl) {
        if (trim($dl) == '')
            continue;
        $dp = preg_split('/\s+/', trim($dl));
        if (count($dp) >= 6) {
            $disks[] = array(
                'dev' => $dp[0],
                'size' => $dp[1],
                'used' => $dp[2],
                'avail' => $dp[3],
                'pct' => intval($dp[4]),
                'mount' => $dp[5]
            );
        }
    }
    $i['disks'] = $disks;
    return $i;
}

function getProcesses($sort = 'cpu', $count = 25)
{
    if (!command_exists('ps'))
        return [];
    $s = $sort === 'mem' ? '-%mem' : '-%cpu';
    $o = cmd("ps aux --sort=$s|head -" . ($count + 1));
    $ps = array();
    foreach (explode("\n", $o) as $n => $l) {
        if ($n === 0 || trim($l) == '')
            continue;
        $p = preg_split('/\s+/', trim($l), 11);
        if (count($p) >= 11) {
            $ps[] = array(
                'u' => $p[0],
                'pid' => $p[1],
                'cpu' => $p[2],
                'mem' => $p[3],
                'vsz' => $p[4],
                'rss' => $p[5],
                'stat' => $p[7],
                'start' => $p[8],
                'time' => $p[9],
                'cmd' => $p[10]
            );
        }
    }
    return $ps;
}

function killProcess($pid)
{
    $pid = abs(intval($pid));
    if ($pid <= 0) return false;
    // Usar posix_kill si está disponible, sino kill con PID sanitizado
    if (function_exists('posix_kill')) {
        return posix_kill($pid, 9);
    }
    return cmd("kill -9 " . intval($pid) . " 2>/dev/null") === '';
}

function getConnections()
{
    $o = cmd("ss -tunap|tail -n +2|head -40");
    $cs = array();
    foreach (explode("\n", $o) as $l) {
        if (trim($l) == '')
            continue;
        $p = preg_split('/\s+/', trim($l));
        if (count($p) >= 5) {
            $cs[] = array(
                'proto' => $p[0],
                'state' => $p[1],
                'local' => isset($p[4]) ? $p[4] : '',
                'foreign' => isset($p[5]) ? $p[5] : '',
                'proc' => isset($p[6]) ? $p[6] : ''
            );
        }
    }
    return $cs;
}

// ---------- Inventario y mapa de red ----------
// El inventario es pasivo. El descubrimiento activo, cuando se habilita, solo
// usa redes privadas conectadas que además estén autorizadas por configuración.
function network_find_binary($names)
{
    if (!is_array($names)) $names = array($names);
    $directories = array('/usr/local/sbin', '/usr/local/bin', '/usr/sbin', '/usr/bin', '/sbin', '/bin');
    foreach ($names as $name) {
        if (!is_string($name) || !preg_match('/^[a-zA-Z0-9_.-]+$/D', $name)) continue;
        foreach ($directories as $directory) {
            $candidate = $directory . '/' . $name;
            $resolved = realpath($candidate);
            $mode = $resolved ? @fileperms($resolved) : false;
            $owner = $resolved ? @fileowner($resolved) : false;
            $trustedOwner = $owner !== false && (!function_exists('posix_geteuid') || intval($owner) === 0 || intval($owner) === intval(posix_geteuid()));
            if ($resolved && is_file($resolved) && is_executable($resolved) && $mode !== false && (($mode & 0022) === 0) && $trustedOwner) return $resolved;
        }
    }
    return null;
}

function network_run_fixed($binary, $arguments, $timeoutSeconds = 4, $maxOutputBytes = 524288)
{
    $result = array('stdout' => '', 'stderr' => '', 'exit_code' => 126, 'timed_out' => false, 'truncated' => false, 'available' => false);
    if (!function_exists('proc_open') || !is_string($binary) || !is_file($binary) || !is_executable($binary) || !is_array($arguments)) return $result;
    $safeArguments = array();
    foreach ($arguments as $argument) {
        if (!is_scalar($argument) || strpos((string)$argument, "\0") !== false || strlen((string)$argument) > 512) return $result;
        $safeArguments[] = (string)$argument;
    }
    $timeoutSeconds = max(1, min(30, intval($timeoutSeconds)));
    $maxOutputBytes = max(4096, min(1048576, intval($maxOutputBytes)));
    if (defined('PHP_VERSION_ID') && PHP_VERSION_ID >= 70400) {
        $command = array_merge(array($binary), $safeArguments);
        $options = array('bypass_shell' => true);
    } else {
        $escaped = array(escapeshellarg($binary));
        foreach ($safeArguments as $argument) $escaped[] = escapeshellarg($argument);
        $command = implode(' ', $escaped);
        $options = array();
    }
    $descriptors = array(0 => array('pipe', 'r'), 1 => array('pipe', 'w'), 2 => array('pipe', 'w'));
    $environment = array('PATH' => '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL' => 'C', 'LANG' => 'C');
    $process = @proc_open($command, $descriptors, $pipes, null, $environment, $options);
    if (!is_resource($process)) return $result;
    $result['available'] = true;
    fclose($pipes[0]);
    stream_set_blocking($pipes[1], false);
    stream_set_blocking($pipes[2], false);
    $started = microtime(true);
    $knownExitCode = null;
    while (true) {
        $read = array();
        if (!feof($pipes[1])) $read[] = $pipes[1];
        if (!feof($pipes[2])) $read[] = $pipes[2];
        if ($read) {
            $write = null; $except = null;
            @stream_select($read, $write, $except, 0, 100000);
            foreach ($read as $stream) {
                $chunk = @fread($stream, 8192);
                if (!is_string($chunk) || $chunk === '') continue;
                if ($stream === $pipes[1]) $result['stdout'] .= $chunk; else $result['stderr'] .= $chunk;
            }
        }
        if (strlen($result['stdout']) + strlen($result['stderr']) > $maxOutputBytes) {
            $result['truncated'] = true;
            @proc_terminate($process, 9);
            break;
        }
        $status = proc_get_status($process);
        if (!$status['running']) {
            if (isset($status['exitcode']) && intval($status['exitcode']) >= 0) $knownExitCode = intval($status['exitcode']);
            break;
        }
        if ((microtime(true) - $started) >= $timeoutSeconds) {
            $result['timed_out'] = true;
            @proc_terminate($process, 9);
            break;
        }
    }
    $result['stdout'] .= (string)@stream_get_contents($pipes[1]);
    $result['stderr'] .= (string)@stream_get_contents($pipes[2]);
    fclose($pipes[1]); fclose($pipes[2]);
    $closedExitCode = @proc_close($process);
    $result['exit_code'] = $knownExitCode !== null ? $knownExitCode : intval($closedExitCode);
    if (strlen($result['stdout']) + strlen($result['stderr']) > $maxOutputBytes) {
        $result['truncated'] = true;
        $result['stdout'] = substr($result['stdout'], 0, $maxOutputBytes);
        $result['stderr'] = substr($result['stderr'], 0, max(0, $maxOutputBytes - strlen($result['stdout'])));
    }
    return $result;
}

function network_mask_packed($packed, $prefix)
{
    $length = strlen($packed);
    $prefix = max(0, min($length * 8, intval($prefix)));
    $masked = '';
    for ($index = 0; $index < $length; $index++) {
        $bits = max(0, min(8, $prefix - ($index * 8)));
        $mask = $bits === 0 ? 0 : ((0xff << (8 - $bits)) & 0xff);
        $masked .= chr(ord($packed[$index]) & $mask);
    }
    return $masked;
}

function network_parse_cidr($cidr, $ipv4Only = false)
{
    if (!is_string($cidr) || substr_count($cidr, '/') !== 1) return false;
    list($address, $prefixRaw) = explode('/', trim($cidr), 2);
    if (!preg_match('/^\d{1,3}$/D', $prefixRaw)) return false;
    $packed = @inet_pton($address);
    if ($packed === false || ($ipv4Only && strlen($packed) !== 4)) return false;
    $maximum = strlen($packed) === 4 ? 32 : 128;
    $prefix = intval($prefixRaw);
    if ($prefix < 0 || $prefix > $maximum) return false;
    $networkPacked = network_mask_packed($packed, $prefix);
    $network = @inet_ntop($networkPacked);
    if ($network === false) return false;
    return array('family' => strlen($packed) === 4 ? 'ipv4' : 'ipv6', 'prefix' => $prefix, 'network' => $network, 'cidr' => $network . '/' . $prefix, 'packed' => $packed, 'network_packed' => $networkPacked);
}

function network_ip_in_cidr($address, $cidr)
{
    $parsed = network_parse_cidr($cidr);
    $packed = @inet_pton($address);
    if (!$parsed || $packed === false || strlen($packed) !== strlen($parsed['network_packed'])) return false;
    return hash_equals($parsed['network_packed'], network_mask_packed($packed, $parsed['prefix']));
}

function network_cidr_contains($outer, $inner)
{
    $outerParsed = network_parse_cidr($outer);
    $innerParsed = network_parse_cidr($inner);
    if (!$outerParsed || !$innerParsed || $outerParsed['family'] !== $innerParsed['family'] || $outerParsed['prefix'] > $innerParsed['prefix']) return false;
    return hash_equals($outerParsed['network_packed'], network_mask_packed($innerParsed['network_packed'], $outerParsed['prefix']));
}

function network_prefix_from_netmask($netmask, $family)
{
    $packed = @inet_pton($netmask);
    $expectedLength = $family === 'ipv4' ? 4 : 16;
    if ($packed === false || strlen($packed) !== $expectedLength) return null;
    $prefix = 0; $zeroSeen = false;
    for ($index = 0; $index < strlen($packed); $index++) {
        for ($bit = 7; $bit >= 0; $bit--) {
            $set = (ord($packed[$index]) & (1 << $bit)) !== 0;
            if ($zeroSeen && $set) return null;
            if ($set) $prefix++; else $zeroSeen = true;
        }
    }
    return $prefix;
}

function network_ipv4_add($packed, $offset)
{
    if (!is_string($packed) || strlen($packed) !== 4 || $offset < 0 || $offset > 65536) return false;
    $bytes = array_values(unpack('C4', $packed));
    for ($index = 3; $index >= 0 && $offset > 0; $index--) {
        $sum = $bytes[$index] + ($offset & 0xff);
        $bytes[$index] = $sum & 0xff;
        $offset = ($offset >> 8) + ($sum >> 8);
    }
    return pack('C4', $bytes[0], $bytes[1], $bytes[2], $bytes[3]);
}

function network_is_private_ipv4($address)
{
    $packed = @inet_pton($address);
    if ($packed === false || strlen($packed) !== 4) return false;
    $bytes = array_values(unpack('C4', $packed));
    return $bytes[0] === 10 ||
        ($bytes[0] === 172 && $bytes[1] >= 16 && $bytes[1] <= 31) ||
        ($bytes[0] === 192 && $bytes[1] === 168);
}

function network_address_scope($address)
{
    $packed = @inet_pton($address);
    if ($packed === false) return 'invalid';
    if (strlen($packed) === 4) {
        $bytes = array_values(unpack('C4', $packed));
        if ($bytes[0] === 127) return 'loopback';
        if ($bytes[0] === 0) return 'unspecified_or_software';
        if ($bytes[0] === 169 && $bytes[1] === 254) return 'link_local';
        if ($bytes[0] === 100 && $bytes[1] >= 64 && $bytes[1] <= 127) return 'shared_cgnat';
        if (($bytes[0] === 192 && $bytes[1] === 0 && $bytes[2] === 2) || ($bytes[0] === 198 && $bytes[1] === 51 && $bytes[2] === 100) || ($bytes[0] === 203 && $bytes[1] === 0 && $bytes[2] === 113)) return 'documentation';
        if ($bytes[0] === 198 && ($bytes[1] === 18 || $bytes[1] === 19)) return 'benchmark';
        if ($bytes[0] >= 224) return 'multicast_or_reserved';
        return network_is_private_ipv4($address) ? 'private' : 'public';
    }
    if ($address === '::') return 'unspecified';
    if ($address === '::1') return 'loopback';
    $first = ord($packed[0]); $second = ord($packed[1]);
    if ($first === 0xfe && (($second & 0xc0) === 0x80)) return 'link_local';
    if (($first & 0xfe) === 0xfc) return 'private';
    if ($first === 0xff) return 'multicast';
    return 'public';
}

function network_configured_allowed_cidrs()
{
    $allowed = array();
    $tokens = array_slice(preg_split('/[\s,]+/', substr(NETWORK_DISCOVERY_ALLOWED_CIDRS, 0, 8192), -1, PREG_SPLIT_NO_EMPTY), 0, 64);
    foreach ($tokens as $candidate) {
        $parsed = network_parse_cidr($candidate, true);
        if (!$parsed || $parsed['prefix'] < 8 || $parsed['prefix'] > 30 || !network_is_private_ipv4($parsed['network'])) continue;
        $allowed[$parsed['cidr']] = $parsed['cidr'];
    }
    return array_values($allowed);
}

function network_read_small_file($path, $maximum = 128)
{
    if (!is_file($path) || !is_readable($path) || is_link($path)) return null;
    $value = @file_get_contents($path, false, null, 0, $maximum);
    return $value === false ? null : trim($value);
}

function network_deadline_timeout($deadline, $maximum)
{
    $maximum = max(1, min(30, intval($maximum)));
    if ($deadline === null) return $maximum;
    return max(0, min($maximum, intval(floor(floatval($deadline) - microtime(true)))));
}

function network_namespace_info()
{
    $link = @readlink('/proc/self/ns/net');
    $inode = $link && preg_match('/\[(\d+)\]/', $link, $match) ? $match[1] : 'unknown';
    $indicators = array();
    if (file_exists('/.dockerenv') || file_exists('/run/.containerenv')) $indicators[] = 'container_marker';
    $systemdContainer = network_read_small_file('/run/systemd/container', 128);
    if (is_string($systemdContainer) && $systemdContainer !== '') $indicators[] = 'systemd_container';
    foreach (array('/proc/1/cgroup', '/proc/self/cgroup') as $cgroupPath) {
        $cgroup = @file_get_contents($cgroupPath, false, null, 0, 16384);
        if (is_string($cgroup) && preg_match('/docker|containerd|kubepods|podman|lxc|machine\.slice|nspawn/i', $cgroup)) { $indicators[] = basename(dirname($cgroupPath)) . '_cgroup'; break; }
    }
    $pidOneNamespace = @readlink('/proc/1/ns/net');
    if ($link && $pidOneNamespace && $link !== $pidOneNamespace) $indicators[] = 'isolated_netns';
    $indicators = array_values(array_unique($indicators));
    return array('inode' => (string)$inode, 'container' => (bool)$indicators, 'scope' => 'current_process_namespace', 'isolation_indicators' => $indicators);
}

function network_collect_interfaces(&$sources, $deadline = null)
{
    $interfaces = array();
    $truncated = false;
    $ipBinary = network_find_binary(array('ip'));
    $decoded = null;
    $interfaceTimeout = network_deadline_timeout($deadline, 5);
    if ($ipBinary && $interfaceTimeout > 0) {
        $response = network_run_fixed($ipBinary, array('-j', '-details', '-statistics', 'address', 'show'), $interfaceTimeout, 786432);
        $decoded = $response['available'] ? json_decode($response['stdout'], true) : null;
    }
    if (is_array($decoded)) {
        if (count($decoded) > 128) $truncated = true;
        foreach (array_slice($decoded, 0, 128) as $raw) {
            if (!is_array($raw) || empty($raw['ifname'])) continue;
            $name = substr((string)$raw['ifname'], 0, 64);
            $addresses = array();
            if (isset($raw['addr_info']) && is_array($raw['addr_info']) && count($raw['addr_info']) > 64) $truncated = true;
            foreach (isset($raw['addr_info']) && is_array($raw['addr_info']) ? array_slice($raw['addr_info'], 0, 64) : array() as $addressRaw) {
                $address = isset($addressRaw['local']) ? (string)$addressRaw['local'] : '';
                $packed = @inet_pton($address);
                if ($packed === false) continue;
                $maximum = strlen($packed) === 4 ? 32 : 128;
                $prefix = isset($addressRaw['prefixlen']) ? max(0, min($maximum, intval($addressRaw['prefixlen']))) : $maximum;
                $parsed = network_parse_cidr($address . '/' . $prefix);
                $addresses[] = array(
                    'family' => strlen($packed) === 4 ? 'ipv4' : 'ipv6',
                    'address' => $address,
                    'prefix' => $prefix,
                    'cidr' => $address . '/' . $prefix,
                    'network' => $parsed ? $parsed['cidr'] : null,
                    'scope' => network_address_scope($address),
                    'kernel_scope' => isset($addressRaw['scope']) ? substr((string)$addressRaw['scope'], 0, 24) : 'unknown',
                    'dynamic' => !empty($addressRaw['dynamic']),
                    'temporary' => !empty($addressRaw['temporary']),
                    'deprecated' => !empty($addressRaw['deprecated']),
                    'tentative' => !empty($addressRaw['tentative']),
                    'dad_failed' => !empty($addressRaw['dadfailed'])
                );
            }
            $kind = isset($raw['linkinfo']['info_kind']) ? (string)$raw['linkinfo']['info_kind'] : (isset($raw['link_type']) ? (string)$raw['link_type'] : ($name === 'lo' ? 'loopback' : 'unknown'));
            $flags = isset($raw['flags']) && is_array($raw['flags']) ? array_values(array_slice(array_map('strval', $raw['flags']), 0, 24)) : array();
            $interfaces[$name] = array(
                'id' => 'if-' . substr(hash('sha256', $name . '|' . (isset($raw['ifindex']) ? $raw['ifindex'] : '0')), 0, 12),
                'ifindex' => isset($raw['ifindex']) ? intval($raw['ifindex']) : 0,
                'name' => $name,
                'kind' => substr($kind, 0, 40),
                'state' => strtolower(substr(isset($raw['operstate']) ? (string)$raw['operstate'] : 'unknown', 0, 24)),
                'carrier' => in_array('LOWER_UP', $flags, true),
                'promiscuity' => isset($raw['promiscuity']) ? max(0, intval($raw['promiscuity'])) : (in_array('PROMISC', $flags, true) ? 1 : 0),
                'flags' => $flags,
                'mtu' => isset($raw['mtu']) ? max(0, intval($raw['mtu'])) : 0,
                'mac' => isset($raw['address']) && preg_match('/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/iD', $raw['address']) ? strtolower($raw['address']) : null,
                'addresses' => $addresses,
                'stats' => array(
                    'rx_bytes' => isset($raw['stats64']['rx']['bytes']) ? max(0, intval($raw['stats64']['rx']['bytes'])) : 0,
                    'tx_bytes' => isset($raw['stats64']['tx']['bytes']) ? max(0, intval($raw['stats64']['tx']['bytes'])) : 0,
                    'rx_errors' => isset($raw['stats64']['rx']['errors']) ? max(0, intval($raw['stats64']['rx']['errors'])) : 0,
                    'tx_errors' => isset($raw['stats64']['tx']['errors']) ? max(0, intval($raw['stats64']['tx']['errors'])) : 0
                )
            );
        }
        $sources[] = array('id' => 'interfaces', 'status' => $truncated ? 'partial' : 'ok', 'method' => 'ip-json', 'count' => count($interfaces), 'truncated' => $truncated);
    }

    // /sys completa interfaces aun si iproute2 no está presente o ve datos parciales.
    foreach (array_slice(glob('/sys/class/net/*') ?: array(), 0, 128) as $sysPath) {
        $name = basename($sysPath);
        if (!preg_match('/^[a-zA-Z0-9_.:@-]{1,64}$/D', $name)) continue;
        if (!isset($interfaces[$name])) {
            $interfaces[$name] = array(
                'id' => 'if-' . substr(hash('sha256', $name), 0, 12),
                'ifindex' => intval(network_read_small_file($sysPath . '/ifindex') ?: 0),
                'name' => $name,
                'kind' => $name === 'lo' ? 'loopback' : 'unknown',
                'state' => strtolower((string)(network_read_small_file($sysPath . '/operstate') ?: 'unknown')),
                'carrier' => network_read_small_file($sysPath . '/carrier') === '1',
                'promiscuity' => (($flagValue = network_read_small_file($sysPath . '/flags')) && preg_match('/^0x[0-9a-f]+$/iD', $flagValue)) ? ((hexdec(substr($flagValue, 2)) & 0x100) ? 1 : 0) : 0,
                'flags' => array(),
                'mtu' => intval(network_read_small_file($sysPath . '/mtu') ?: 0),
                'mac' => (($mac = network_read_small_file($sysPath . '/address')) && preg_match('/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/iD', $mac)) ? strtolower($mac) : null,
                'addresses' => array(),
                'stats' => array()
            );
        }
        foreach (array('rx_bytes', 'tx_bytes', 'rx_errors', 'tx_errors') as $statName) {
            $interfaces[$name]['stats'][$statName] = max(0, intval(network_read_small_file($sysPath . '/statistics/' . $statName) ?: 0));
        }
    }

    // Fallback de direcciones para implementaciones de ip sin salida JSON.
    $interfaceFallbackTimeout = network_deadline_timeout($deadline, 4);
    if ($ipBinary && $interfaceFallbackTimeout > 0 && (!$decoded || !array_filter($interfaces, function ($item) { return !empty($item['addresses']); }))) {
        $response = network_run_fixed($ipBinary, array('-o', 'address', 'show'), $interfaceFallbackTimeout, 262144);
        foreach (preg_split('/\R/', $response['stdout']) as $line) {
            if (!preg_match('/^\d+:\s+([^\s]+)\s+(inet6?)\s+([0-9a-f:.]+)\/(\d+)/i', trim($line), $match)) continue;
            $name = explode('@', $match[1])[0];
            if (!isset($interfaces[$name]) || @inet_pton($match[3]) === false) continue;
            $family = strtolower($match[2]) === 'inet' ? 'ipv4' : 'ipv6';
            $maximum = $family === 'ipv4' ? 32 : 128;
            $prefix = max(0, min($maximum, intval($match[4])));
            $duplicate = false;
            foreach ($interfaces[$name]['addresses'] as $known) if ($known['address'] === $match[3] && $known['prefix'] === $prefix) $duplicate = true;
            if (!$duplicate) {
                $parsed = network_parse_cidr($match[3] . '/' . $prefix);
                $interfaces[$name]['addresses'][] = array('family' => $family, 'address' => $match[3], 'prefix' => $prefix, 'cidr' => $match[3] . '/' . $prefix, 'network' => $parsed ? $parsed['cidr'] : null, 'scope' => network_address_scope($match[3]), 'kernel_scope' => 'unknown', 'dynamic' => false, 'temporary' => false, 'deprecated' => false, 'tentative' => false, 'dad_failed' => false);
            }
        }
        if (!is_array($decoded)) $sources[] = array('id' => 'interfaces', 'status' => 'partial', 'method' => 'ip-text+sysfs', 'count' => count($interfaces));
    }

    if (function_exists('net_get_interfaces')) {
        $native = @net_get_interfaces();
        if (is_array($native)) foreach ($native as $name => $raw) {
            if (!is_string($name) || !preg_match('/^[a-zA-Z0-9_.:@-]{1,64}$/D', $name) || !isset($raw['unicast']) || !is_array($raw['unicast'])) continue;
            if (!isset($interfaces[$name])) {
                $interfaces[$name] = array('id' => 'if-' . substr(hash('sha256', $name), 0, 12), 'ifindex' => 0, 'name' => $name, 'kind' => $name === 'lo' ? 'loopback' : 'unknown', 'state' => 'unknown', 'carrier' => false, 'promiscuity' => 0, 'flags' => array(), 'mtu' => 0, 'mac' => isset($raw['mac']) && preg_match('/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/iD', $raw['mac']) ? strtolower($raw['mac']) : null, 'addresses' => array(), 'stats' => array('rx_bytes' => 0, 'tx_bytes' => 0, 'rx_errors' => 0, 'tx_errors' => 0));
            }
            foreach ($raw['unicast'] as $unicast) {
                $address = isset($unicast['address']) ? $unicast['address'] : '';
                if (@inet_pton($address) === false) continue;
                $exists = false;
                foreach ($interfaces[$name]['addresses'] as $known) if ($known['address'] === $address) $exists = true;
                if ($exists) continue;
                $family = strpos($address, ':') !== false ? 'ipv6' : 'ipv4';
                $prefix = isset($unicast['netmask']) ? network_prefix_from_netmask($unicast['netmask'], $family) : null;
                if ($prefix === null) $prefix = $family === 'ipv4' ? 32 : 128;
                $parsed = network_parse_cidr($address . '/' . $prefix);
                $interfaces[$name]['addresses'][] = array('family' => $family, 'address' => $address, 'prefix' => $prefix, 'cidr' => $address . '/' . $prefix, 'network' => $parsed ? $parsed['cidr'] : $address . '/' . $prefix, 'scope' => network_address_scope($address), 'kernel_scope' => 'unknown', 'dynamic' => false, 'temporary' => false, 'deprecated' => false, 'tentative' => false, 'dad_failed' => false);
            }
        }
    }
    $interfaceSourceRecorded = false;
    foreach ($sources as $source) if (isset($source['id']) && $source['id'] === 'interfaces') $interfaceSourceRecorded = true;
    if (!$interfaceSourceRecorded) $sources[] = array('id' => 'interfaces', 'status' => $interfaces ? 'partial' : 'missing', 'method' => $interfaces ? 'native+sysfs' : 'none', 'count' => count($interfaces));
    uasort($interfaces, function ($left, $right) {
        if ($left['name'] === 'lo') return 1;
        if ($right['name'] === 'lo') return -1;
        if ($left['state'] !== $right['state']) return $left['state'] === 'up' ? -1 : 1;
        return strnatcasecmp($left['name'], $right['name']);
    });
    return array_values($interfaces);
}

function network_collect_routes(&$sources, $deadline = null)
{
    $routes = array();
    $jsonFamilies = array();
    $truncated = false;
    $ipBinary = network_find_binary(array('ip'));
    foreach (array('ipv4' => '-4', 'ipv6' => '-6') as $family => $familyFlag) {
        if (!$ipBinary) continue;
        $routeTimeout = network_deadline_timeout($deadline, 4);
        if ($routeTimeout < 1) break;
        $response = network_run_fixed($ipBinary, array('-j', $familyFlag, 'route', 'show', 'table', 'all'), $routeTimeout, 524288);
        $decoded = json_decode($response['stdout'], true);
        if (!is_array($decoded)) continue;
        $jsonFamilies[] = $family;
        if (count($decoded) > 512) $truncated = true;
        foreach (array_slice($decoded, 0, 512) as $raw) {
            if (!is_array($raw)) continue;
            $destination = isset($raw['dst']) ? (string)$raw['dst'] : 'default';
            if ($destination !== 'default' && strpos($destination, '/') === false && @inet_pton($destination) !== false) $destination .= $family === 'ipv4' ? '/32' : '/128';
            if ($destination !== 'default' && !network_parse_cidr($destination)) continue;
            $gateway = isset($raw['gateway']) && @inet_pton($raw['gateway']) !== false ? (string)$raw['gateway'] : null;
            $device = isset($raw['dev']) ? substr((string)$raw['dev'], 0, 64) : null;
            $table = isset($raw['table']) ? substr((string)$raw['table'], 0, 32) : 'main';
            $routes[] = array(
                'id' => 'route-' . substr(hash('sha256', $family . '|' . $table . '|' . $destination . '|' . $gateway . '|' . $device . '|' . (isset($raw['metric']) ? $raw['metric'] : '')), 0, 12),
                'family' => $family,
                'table' => $table,
                'destination' => $destination,
                'gateway' => $gateway,
                'device' => $device,
                'protocol' => isset($raw['protocol']) ? substr((string)$raw['protocol'], 0, 32) : 'unknown',
                'scope' => isset($raw['scope']) ? substr((string)$raw['scope'], 0, 32) : ($gateway ? 'global' : 'link'),
                'type' => isset($raw['type']) ? substr((string)$raw['type'], 0, 24) : 'unicast',
                'metric' => isset($raw['metric']) ? max(0, intval($raw['metric'])) : null,
                'prefsrc' => isset($raw['prefsrc']) && @inet_pton($raw['prefsrc']) !== false ? (string)$raw['prefsrc'] : null,
                'directly_connected' => !$gateway && $destination !== 'default' && (!isset($raw['type']) || strtolower((string)$raw['type']) === 'unicast') && (!isset($raw['scope']) || strtolower((string)$raw['scope']) === 'link')
            );
        }
    }
    if ($routes) {
        $sources[] = array('id' => 'routes', 'status' => count(array_unique($jsonFamilies)) === 2 && !$truncated ? 'ok' : 'partial', 'method' => 'ip-json-all-tables', 'count' => count($routes), 'families' => array_values(array_unique($jsonFamilies)), 'truncated' => $truncated);
        return $routes;
    }
    // Fallback IPv4 mínimo desde procfs; no inventa rutas IPv6 ausentes.
    $raw = @file('/proc/net/route', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (is_array($raw)) foreach (array_slice($raw, 1, 512) as $line) {
        $parts = preg_split('/\s+/', trim($line));
        if (count($parts) < 8 || !preg_match('/^[0-9a-f]+$/iD', $parts[1]) || !preg_match('/^[0-9a-f]+$/iD', $parts[2]) || !preg_match('/^[0-9a-f]+$/iD', $parts[7])) continue;
        $destinationPacked = pack('V', hexdec($parts[1]));
        $gatewayPacked = pack('V', hexdec($parts[2]));
        $maskPacked = pack('V', hexdec($parts[7]));
        $prefix = 0;
        for ($index = 0; $index < 4; $index++) $prefix += substr_count(decbin(ord($maskPacked[$index])), '1');
        $destinationAddress = inet_ntop($destinationPacked);
        $destination = $prefix === 0 ? 'default' : $destinationAddress . '/' . $prefix;
        $gatewayAddress = inet_ntop($gatewayPacked);
        $gateway = $gatewayAddress === '0.0.0.0' ? null : $gatewayAddress;
        $routes[] = array('id' => 'route-' . substr(hash('sha256', $line), 0, 12), 'family' => 'ipv4', 'table' => 'main', 'destination' => $destination, 'gateway' => $gateway, 'device' => substr($parts[0], 0, 64), 'protocol' => 'kernel', 'scope' => $gateway ? 'global' : 'link', 'type' => 'unicast', 'metric' => intval($parts[6]), 'prefsrc' => null, 'directly_connected' => !$gateway && $destination !== 'default');
    }
    $sources[] = array('id' => 'routes', 'status' => $routes ? 'partial' : 'missing', 'method' => $routes ? 'procfs-ipv4' : 'none', 'count' => count($routes));
    return $routes;
}

function network_collect_rules(&$sources, $deadline = null)
{
    $rules = array(); $families = array(); $truncated = false;
    $ipBinary = network_find_binary(array('ip'));
    foreach (array('ipv4' => '-4', 'ipv6' => '-6') as $family => $familyFlag) {
        if (!$ipBinary) continue;
        $ruleTimeout = network_deadline_timeout($deadline, 3);
        if ($ruleTimeout < 1) break;
        $response = network_run_fixed($ipBinary, array('-j', $familyFlag, 'rule', 'show'), $ruleTimeout, 262144);
        $decoded = json_decode($response['stdout'], true);
        if (!is_array($decoded)) continue;
        $families[] = $family;
        foreach (array_slice($decoded, 0, 256) as $raw) {
            if (!is_array($raw)) continue;
            $from = isset($raw['from']) ? audit_clean_text($raw['from'], 96) : (isset($raw['src']) ? audit_clean_text($raw['src'], 96) : 'all');
            $to = isset($raw['to']) ? audit_clean_text($raw['to'], 96) : (isset($raw['dst']) ? audit_clean_text($raw['dst'], 96) : 'all');
            $table = isset($raw['table']) ? audit_clean_text($raw['table'], 32) : (isset($raw['lookup']) ? audit_clean_text($raw['lookup'], 32) : null);
            $action = isset($raw['action']) ? audit_clean_text($raw['action'], 32) : ($table !== null ? 'lookup' : 'unknown');
            $rules[] = array(
                'id' => 'rule-' . substr(hash('sha256', $family . '|' . json_encode($raw)), 0, 12),
                'family' => $family,
                'priority' => isset($raw['priority']) ? max(0, intval($raw['priority'])) : null,
                'from' => $from,
                'to' => $to,
                'table' => $table,
                'fwmark' => isset($raw['fwmark']) ? audit_clean_text($raw['fwmark'], 48) : null,
                'iif' => isset($raw['iif']) ? audit_clean_text($raw['iif'], 64) : null,
                'oif' => isset($raw['oif']) ? audit_clean_text($raw['oif'], 64) : null,
                'action' => $action
            );
            if (count($rules) >= 256) { $truncated = true; break 2; }
        }
    }
    $status = count(array_unique($families)) === 2 && !$truncated ? 'ok' : ($families ? 'partial' : 'missing');
    $sources[] = array('id' => 'routing_rules', 'status' => $status, 'method' => $families ? 'ip-json' : 'none', 'count' => count($rules), 'families' => array_values(array_unique($families)), 'truncated' => $truncated);
    return $rules;
}

function network_collect_neighbors(&$sources, $deadline = null)
{
    $neighbors = array();
    $known = array();
    $truncated = false;
    $ipBinary = network_find_binary(array('ip'));
    $ipJsonAvailable = false;
    $neighborTimeout = network_deadline_timeout($deadline, 4);
    if ($ipBinary && $neighborTimeout > 0) {
        $response = network_run_fixed($ipBinary, array('-j', 'neighbor', 'show'), $neighborTimeout, 524288);
        $decoded = json_decode($response['stdout'], true);
        if (is_array($decoded)) {
            $ipJsonAvailable = true;
            if (count($decoded) > 2048) $truncated = true;
            foreach (array_slice($decoded, 0, 2048) as $raw) {
            $address = isset($raw['dst']) ? (string)$raw['dst'] : '';
            $packed = @inet_pton($address);
            if ($packed === false) continue;
            $device = isset($raw['dev']) ? substr((string)$raw['dev'], 0, 64) : 'unknown';
            $stateRaw = isset($raw['state']) ? $raw['state'] : 'unknown';
            $state = is_array($stateRaw) ? implode(',', array_map('strval', $stateRaw)) : (string)$stateRaw;
            $mac = isset($raw['lladdr']) && preg_match('/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/iD', $raw['lladdr']) ? strtolower($raw['lladdr']) : null;
            $key = (strlen($packed) === 4 ? 'ipv4' : 'ipv6') . '|' . $address . '|' . $device;
            $known[$key] = true;
                $neighbors[] = array('family' => strlen($packed) === 4 ? 'ipv4' : 'ipv6', 'address' => $address, 'device' => $device, 'mac' => $mac, 'state' => strtolower(substr($state, 0, 48)), 'router' => !empty($raw['router']), 'source' => 'kernel_cache');
            }
        }
    }
    $arp = @file('/proc/net/arp', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    $arpReadable = is_array($arp);
    if (is_array($arp)) foreach (array_slice($arp, 1, 2048) as $line) {
        $parts = preg_split('/\s+/', trim($line));
        if (count($parts) < 6 || filter_var($parts[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) continue;
        $key = 'ipv4|' . $parts[0] . '|' . $parts[5];
        if (isset($known[$key])) continue;
        $mac = preg_match('/^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$/iD', $parts[3]) && $parts[3] !== '00:00:00:00:00:00' ? strtolower($parts[3]) : null;
        $neighbors[] = array('family' => 'ipv4', 'address' => $parts[0], 'device' => substr($parts[5], 0, 64), 'mac' => $mac, 'state' => $mac ? 'reachable_or_cached' : 'incomplete', 'router' => false, 'source' => 'proc_arp');
    }
    $sources[] = array('id' => 'neighbors', 'status' => $ipJsonAvailable ? ($truncated ? 'partial' : 'ok') : ($arpReadable ? 'partial' : 'missing'), 'method' => $ipJsonAvailable ? 'ip-json+procfs' : ($arpReadable ? 'procfs-ipv4' : 'none'), 'count' => count($neighbors), 'truncated' => $truncated);
    return array_slice($neighbors, 0, 2048);
}

function network_intersect_scan_cidr($connectedCidr, $allowedCidr, $localAddress)
{
    if (network_cidr_contains($connectedCidr, $allowedCidr)) {
        $chosen = network_parse_cidr($allowedCidr, true);
    } elseif (network_cidr_contains($allowedCidr, $connectedCidr)) {
        $chosen = network_parse_cidr($connectedCidr, true);
    } else {
        return false;
    }
    if (!$chosen || !network_is_private_ipv4($chosen['network']) || !network_ip_in_cidr($localAddress, $chosen['cidr'])) return false;
    if ($chosen['prefix'] < 24) {
        $slice = network_parse_cidr($localAddress . '/24', true);
        if (!$slice || !network_cidr_contains($chosen['cidr'], $slice['cidr'])) return false;
        $chosen = $slice;
        $chosen['sampled_from'] = $connectedCidr;
    }
    if ($chosen['prefix'] > 30) return false;
    return $chosen;
}

function network_enumerate_ipv4($cidr, $selfAddresses)
{
    $parsed = network_parse_cidr($cidr, true);
    if (!$parsed || $parsed['prefix'] < 24 || $parsed['prefix'] > 30) return array();
    $blockSize = 1 << (32 - $parsed['prefix']);
    $candidates = array();
    for ($offset = 1; $offset < $blockSize - 1; $offset++) {
        $packed = network_ipv4_add($parsed['network_packed'], $offset);
        $address = $packed === false ? false : @inet_ntop($packed);
        if (!$address || in_array($address, $selfAddresses, true) || !network_is_private_ipv4($address)) continue;
        $candidates[] = $address;
    }
    return $candidates;
}

function network_build_eligible_scopes($interfaces, $routes)
{
    $allowedCidrs = network_configured_allowed_cidrs();
    $interfaceMap = array();
    $selfAddresses = array();
    foreach ($interfaces as $interface) {
        $interfaceMap[$interface['name']] = $interface;
        foreach ($interface['addresses'] as $address) if ($address['family'] === 'ipv4') $selfAddresses[] = $address['address'];
    }
    $scopes = array(); $scopeKeys = array();
    foreach ($routes as $route) {
        if ($route['family'] !== 'ipv4' || (isset($route['table']) && (string)$route['table'] !== 'main') || empty($route['directly_connected']) || empty($route['device']) || !isset($interfaceMap[$route['device']]) || $route['destination'] === 'default') continue;
        $interface = $interfaceMap[$route['device']];
        if ($interface['name'] === 'lo' || !in_array($interface['state'], array('up', 'unknown'), true)) continue;
        $connected = network_parse_cidr($route['destination'], true);
        if (!$connected || !network_is_private_ipv4($connected['network'])) continue;
        foreach ($interface['addresses'] as $local) {
            if ($local['family'] !== 'ipv4' || !network_ip_in_cidr($local['address'], $connected['cidr'])) continue;
            foreach ($allowedCidrs as $allowedCidr) {
                $effective = network_intersect_scan_cidr($connected['cidr'], $allowedCidr, $local['address']);
                if (!$effective) continue;
                $key = $interface['name'] . '|' . $effective['cidr'];
                if (isset($scopeKeys[$key])) continue;
                $scopeKeys[$key] = true;
                $candidates = network_enumerate_ipv4($effective['cidr'], $selfAddresses);
                if (!$candidates) continue;
                $namespace = network_namespace_info();
                $scopeId = substr(hash_hmac('sha256', $namespace['inode'] . '|' . $interface['ifindex'] . '|' . $effective['cidr'], csrf_token()), 0, 24);
                $scopes[] = array(
                    'network_id' => $scopeId,
                    'family' => 'ipv4',
                    'cidr' => $effective['cidr'],
                    'connected_cidr' => $connected['cidr'],
                    'interface' => $interface['name'],
                    'ifindex' => $interface['ifindex'],
                    'local_address' => $local['address'],
                    'candidate_count' => count($candidates),
                    'sampled' => isset($effective['sampled_from']),
                    'active_allowed' => true,
                    '_candidates' => $candidates
                );
                if (count($scopes) >= 64) return $scopes;
            }
        }
    }
    return $scopes;
}

function network_plan_candidates(&$scopes, $availableSeconds = null)
{
    $candidates = array(); $devices = array(); $plannedByScope = array();
    $indexes = array_fill(0, count($scopes), 0);
    $planningSeconds = $availableSeconds === null ? NETWORK_DISCOVERY_TIMEOUT : max(1, floatval($availableSeconds));
    $effectiveBudget = min(NETWORK_DISCOVERY_MAX_HOSTS, max(1, intval(floor(max(0, $planningSeconds - 1) * 20))));
    while (count($candidates) < $effectiveBudget) {
        $added = false;
        foreach ($scopes as $scopeIndex => $scope) {
            $candidateIndex = $indexes[$scopeIndex];
            if (!isset($scope['_candidates'][$candidateIndex])) continue;
            $address = $scope['_candidates'][$candidateIndex];
            $indexes[$scopeIndex]++;
            $added = true;
            if (isset($devices[$address])) continue;
            $candidates[] = $address;
            $devices[$address] = $scope['interface'];
            if (!isset($plannedByScope[$scopeIndex])) $plannedByScope[$scopeIndex] = 0;
            $plannedByScope[$scopeIndex]++;
            if (count($candidates) >= $effectiveBudget) break;
        }
        if (!$added) break;
    }
    foreach ($scopes as $index => &$scope) {
        $scope['planned_count'] = isset($plannedByScope[$index]) ? $plannedByScope[$index] : 0;
        $scope['truncated'] = $scope['planned_count'] < $scope['candidate_count'];
        unset($scope['_candidates']);
    }
    unset($scope);
    return array('addresses' => $candidates, 'devices' => $devices, 'truncated' => array_sum(array_map(function ($scope) { return !empty($scope['truncated']) ? 1 : 0; }, $scopes)) > 0, 'budget' => $effectiveBudget);
}

function network_probe_candidates($candidates, $candidateDevices, $maxSeconds)
{
    $started = microtime(true);
    $responded = array();
    $method = 'unavailable';
    $probesAttempted = 0;
    $timedOut = false;
    $probeReason = null;
    $maxSeconds = max(1.0, min(floatval(NETWORK_DISCOVERY_TIMEOUT), floatval($maxSeconds)));
    $groups = array();
    foreach ($candidates as $candidate) {
        $device = isset($candidateDevices[$candidate]) ? $candidateDevices[$candidate] : '';
        if (!preg_match('/^[a-zA-Z0-9_.:@-]{1,64}$/D', $device)) continue;
        if (!isset($groups[$device])) $groups[$device] = array();
        $groups[$device][] = $candidate;
    }
    // argv sin shell es un requisito del módulo activo.
    if (!defined('PHP_VERSION_ID') || PHP_VERSION_ID < 70400) return array('method' => 'unavailable', 'responded' => array(), 'probes_attempted' => 0, 'planned' => count($candidates), 'timed_out' => false, 'partial' => true, 'duration_ms' => 0, 'reason' => 'php_7_4_required');
    $fping = network_find_binary(array('fping'));
    if ($fping && $groups) {
        $method = 'fping-icmp';
        $completedGroups = 0;
        foreach ($groups as $device => $groupCandidates) {
            $remaining = $maxSeconds - (microtime(true) - $started);
            if ($remaining < 1) { $timedOut = true; $probesAttempted = null; break; }
            // Un proceso por interfaz, 0 reintentos, interfaz fijada y <=20 paquetes/s.
            $arguments = array('-a', '-r', '0', '-t', '600', '-i', '50', '-I', $device);
            foreach ($groupCandidates as $candidate) $arguments[] = $candidate;
            $response = network_run_fixed($fping, $arguments, intval(ceil($remaining)), 262144);
            $validRun = in_array($response['exit_code'], array(0, 1), true) || trim($response['stdout']) !== '';
            if (!$validRun && $completedGroups === 0 && !$response['timed_out']) { $method = 'unavailable'; $probesAttempted = 0; $probeReason = 'fping_rejected'; break; }
            if (!$validRun || $response['timed_out']) { $timedOut = $response['timed_out']; $probesAttempted = null; $probeReason = $response['timed_out'] ? 'fping_timeout' : 'fping_operational_error'; break; }
            $completedGroups++;
            $probesAttempted += count($groupCandidates);
            foreach (preg_split('/\R/', trim($response['stdout'])) as $line) {
                if (!preg_match('/^([0-9]{1,3}(?:\.[0-9]{1,3}){3})(?:\s|$)/', trim($line), $match)) continue;
                $address = $match[1];
                if (in_array($address, $groupCandidates, true) && filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) $responded[$address] = array('latency_ms' => null, 'via' => 'icmp');
            }
        }
    }
    if ($method === 'unavailable') {
        $ping = network_find_binary(array('ping'));
        if ($ping) {
            $method = 'ping-fallback';
            $probeReason = null;
            $completedPingRuns = 0;
            // Fallback deliberadamente pequeño: evita crear cientos de procesos.
            $fallbackCandidates = array_slice($candidates, 0, min(16, count($candidates)));
            foreach ($fallbackCandidates as $candidate) {
                if ((microtime(true) - $started) >= $maxSeconds) { $timedOut = true; $probeReason = 'ping_deadline'; $probesAttempted = $completedPingRuns > 0 ? null : 0; break; }
                $device = isset($candidateDevices[$candidate]) ? $candidateDevices[$candidate] : '';
                if (!preg_match('/^[a-zA-Z0-9_.:@-]{1,64}$/D', $device)) continue;
                $response = network_run_fixed($ping, array('-n', '-c', '1', '-W', '1', '-I', $device, $candidate), min(2, max(1, intval(ceil($maxSeconds - (microtime(true) - $started))))), 16384);
                $validRun = !empty($response['available']) && empty($response['timed_out']) && in_array($response['exit_code'], array(0, 1), true);
                if (!$validRun) {
                    $timedOut = !empty($response['timed_out']);
                    $probeReason = $timedOut ? 'ping_timeout' : 'ping_operational_error';
                    $probesAttempted = $completedPingRuns > 0 ? null : 0;
                    if ($completedPingRuns === 0) $method = 'unavailable';
                    break;
                }
                $probesAttempted++;
                $completedPingRuns++;
                if ($response['exit_code'] === 0) {
                    $latency = preg_match('/time[=<]([0-9.]+)\s*ms/i', $response['stdout'], $match) ? floatval($match[1]) : null;
                    $responded[$candidate] = array('latency_ms' => $latency, 'via' => 'icmp');
                }
            }
        }
    }
    $partial = $timedOut || $probesAttempted === null || $probesAttempted < count($candidates);
    return array('method' => $method, 'responded' => $responded, 'probes_attempted' => $probesAttempted, 'planned' => count($candidates), 'timed_out' => $timedOut, 'partial' => $partial, 'duration_ms' => round((microtime(true) - $started) * 1000), 'reason' => $probeReason ?: ($method === 'unavailable' ? 'tool_unavailable_or_rejected' : null));
}

function network_build_hosts($interfaces, $routes, $neighbors, $activeResponded, $candidateDevices)
{
    $hosts = array();
    $merge = function ($address, $family, $values) use (&$hosts) {
        $interfaces = isset($values['interfaces']) && is_array($values['interfaces']) ? $values['interfaces'] : array();
        $key = $family . '|' . $address . '|' . (isset($interfaces[0]) ? $interfaces[0] : 'global');
        if (!isset($hosts[$key])) $hosts[$key] = array('id' => 'host-' . substr(hash('sha256', $key), 0, 14), 'address' => $address, 'family' => $family, 'mac' => null, 'state' => 'observed', 'interfaces' => array(), 'sources' => array(), 'is_self' => false, 'is_gateway' => false, 'responded' => false, 'latency_ms' => null);
        foreach ($values as $field => $value) {
            if ($field === 'interfaces' || $field === 'sources') {
                $existing = isset($hosts[$key][$field]) && is_array($hosts[$key][$field]) ? $hosts[$key][$field] : array();
                $hosts[$key][$field] = array_values(array_unique(array_merge($existing, is_array($value) ? $value : array($value))));
            } elseif (in_array($field, array('is_self', 'is_gateway', 'responded'), true)) {
                $hosts[$key][$field] = !empty($hosts[$key][$field]) || (bool)$value;
            } elseif ($value !== null) {
                $hosts[$key][$field] = $value;
            }
        }
    };
    foreach ($interfaces as $interface) foreach ($interface['addresses'] as $address) {
        if ($address['scope'] === 'loopback') continue;
        $merge($address['address'], $address['family'], array('interfaces' => array($interface['name']), 'sources' => array('local_interface'), 'is_self' => true, 'state' => $interface['state']));
    }
    foreach ($routes as $route) if (!empty($route['gateway'])) {
        $merge($route['gateway'], $route['family'], array('interfaces' => $route['device'] ? array($route['device']) : array(), 'sources' => array('route_gateway'), 'is_gateway' => true, 'state' => 'gateway'));
    }
    foreach ($neighbors as $neighbor) {
        if (strpos($neighbor['state'], 'failed') !== false || strpos($neighbor['state'], 'incomplete') !== false) continue;
        $merge($neighbor['address'], $neighbor['family'], array('interfaces' => array($neighbor['device']), 'sources' => array($neighbor['source']), 'mac' => $neighbor['mac'], 'state' => $neighbor['state'], 'is_gateway' => !empty($neighbor['router'])));
    }
    foreach ($activeResponded as $address => $probe) {
        $merge($address, 'ipv4', array('interfaces' => isset($candidateDevices[$address]) ? array($candidateDevices[$address]) : array(), 'sources' => array('active_icmp'), 'responded' => true, 'latency_ms' => isset($probe['latency_ms']) ? $probe['latency_ms'] : null, 'state' => 'responded'));
    }
    $hosts = array_values($hosts);
    usort($hosts, function ($left, $right) {
        if ($left['is_self'] !== $right['is_self']) return $left['is_self'] ? -1 : 1;
        if ($left['is_gateway'] !== $right['is_gateway']) return $left['is_gateway'] ? -1 : 1;
        if ($left['family'] !== $right['family']) return $left['family'] === 'ipv4' ? -1 : 1;
        $leftPacked = @inet_pton($left['address']); $rightPacked = @inet_pton($right['address']);
        return $leftPacked && $rightPacked ? strcmp($leftPacked, $rightPacked) : strcmp($left['address'], $right['address']);
    });
    return array_slice($hosts, 0, 4096);
}

function collectNetworkMap($active = false, $selectedNetworkId = null, &$rateReservation = null)
{
    $started = microtime(true);
    $operationDeadline = $active ? $started + NETWORK_DISCOVERY_TIMEOUT : null;
    $sources = array();
    $namespace = network_namespace_info();
    $interfaces = network_collect_interfaces($sources, $operationDeadline);
    $routes = network_collect_routes($sources, $operationDeadline);
    $rules = network_collect_rules($sources, $operationDeadline);
    $neighbors = network_collect_neighbors($sources, $operationDeadline);
    $scopes = network_build_eligible_scopes($interfaces, $routes);
    if ($active) {
        if (!is_string($selectedNetworkId) || !preg_match('/^[a-f0-9]{24}$/D', $selectedNetworkId)) throw new RuntimeException('Seleccione una subred autorizada válida');
        $selectedScope = null;
        foreach ($scopes as $scope) {
            if (isset($scope['network_id']) && hash_equals($scope['network_id'], $selectedNetworkId)) {
                $selectedScope = $scope;
                break;
            }
        }
        if ($selectedScope === null) throw new RuntimeException('La subred seleccionada ya no está disponible o dejó de estar autorizada');
        // Un clic autoriza exactamente un alcance; nunca se amplía de forma implícita a otras interfaces.
        $scopes = array($selectedScope);
    }
    $availablePlanningSeconds = $active ? $operationDeadline - microtime(true) : null;
    if ($active && $availablePlanningSeconds < 2) throw new RuntimeException('El inventario previo agotó el plazo seguro del descubrimiento');
    $plan = network_plan_candidates($scopes, $availablePlanningSeconds);
    $probe = array('method' => 'passive', 'responded' => array(), 'probes_attempted' => 0, 'planned' => 0, 'timed_out' => false, 'partial' => false, 'duration_ms' => 0, 'reason' => null);
    if ($active) {
        if (!$scopes || !$plan['addresses']) throw new RuntimeException('No hay una subred privada, conectada y autorizada disponible para descubrir');
        if (!defined('PHP_VERSION_ID') || PHP_VERSION_ID < 70400 || (!network_find_binary(array('fping')) && !network_find_binary(array('ping')))) throw new RuntimeException('Instale fping o ping y use PHP 7.4 o posterior para habilitar el descubrimiento ICMP');
        if (!is_array($rateReservation)) throw new UnexpectedValueException('El control persistente de frecuencia no está disponible');
        $rateCommitError = null;
        if (!network_discovery_rate_commit($rateReservation, $rateCommitError)) throw new UnexpectedValueException($rateCommitError ?: 'No se pudo reservar el presupuesto del descubrimiento');
        $_SESSION['last_network_discovery_at'] = time();
        $remainingProbeSeconds = $operationDeadline - microtime(true);
        if ($remainingProbeSeconds < 1) throw new RuntimeException('El inventario previo agotó el plazo seguro del descubrimiento');
        $probe = network_probe_candidates($plan['addresses'], $plan['devices'], $remainingProbeSeconds);
        if ($probe['method'] === 'unavailable') throw new RuntimeException('Instale fping o ping y use PHP 7.4 o posterior para habilitar el descubrimiento ICMP');
        // El sondeo refresca ARP/ND; se vuelve a leer sin conservar salida cruda.
        $postProbeSources = array();
        $neighbors = network_collect_neighbors($postProbeSources, $operationDeadline);
        foreach ($postProbeSources as $source) { $source['id'] .= '_post_probe'; $sources[] = $source; }
        $neighbors = array_values(array_filter($neighbors, function ($neighbor) use ($probe) {
            $unresolved = strpos($neighbor['state'], 'failed') !== false || strpos($neighbor['state'], 'incomplete') !== false;
            return !$unresolved || isset($probe['responded'][$neighbor['address']]);
        }));
    }
    $hosts = network_build_hosts($interfaces, $routes, $neighbors, $probe['responded'], $plan['devices']);
    $gateways = array_values(array_filter($hosts, function ($host) { return !empty($host['is_gateway']); }));
    $activeHosts = array_values(array_filter($hosts, function ($host) { return !empty($host['responded']); }));
    $validAllowedCidrs = network_configured_allowed_cidrs();
    $availableMethods = array_values(array_filter(array(network_find_binary(array('fping')) ? 'fping' : null, network_find_binary(array('ping')) ? 'ping' : null)));
    $recentAuth = !empty($_SESSION['login_time']) && time() - intval($_SESSION['login_time']) <= 600;
    $cooldownRemaining = isset($_SESSION['last_network_discovery_at']) ? max(0, NETWORK_DISCOVERY_COOLDOWN - (time() - intval($_SESSION['last_network_discovery_at']))) : 0;
    $roleAllowed = in_array(isset($_SESSION['role']) ? $_SESSION['role'] : 'none', array('admin', 'operator'), true);
    $containerDenied = !empty($namespace['container']) && !ENABLE_CONTAINER_NETWORK_DISCOVERY;
    $reason = !ENABLE_NETWORK_DISCOVERY ? 'disabled_by_policy' : ($containerDenied ? 'container_opt_in_required' : (!$validAllowedCidrs ? 'allowlist_missing' : (!$roleAllowed ? 'role_denied' : (!$recentAuth ? 'recent_auth_required' : (!$availableMethods ? 'tool_missing' : (!$scopes ? 'no_eligible_networks' : ($cooldownRemaining > 0 ? 'cooldown' : 'ready')))))));
    foreach ($scopes as &$scope) $scope['active_allowed'] = $reason === 'ready';
    unset($scope);
    $passiveInventoryAvailable = false;
    foreach ($sources as $source) if ($source['id'] === 'interfaces' && $source['status'] !== 'missing') $passiveInventoryAvailable = true;
    $warnings = array('La topología es la observada desde el namespace de red del proceso PHP; no demuestra alcance desde Internet.');
    if ($active) $warnings[] = 'La ausencia de respuesta ICMP no demuestra que un equipo esté apagado o sea inexistente.';
    if ($plan['truncated']) $warnings[] = 'El presupuesto máximo se repartió entre interfaces; algunas subredes quedaron muestreadas parcialmente.';
    if ($probe['partial']) $warnings[] = 'El sondeo terminó parcialmente; los objetivos sin resultado permanecen en estado desconocido.';
    $result = array(
        'schema' => 'sentinelops.network/1',
        'generated_at' => gmdate('c'),
        'namespace' => $namespace,
        'host' => array('id' => 'local-host', 'hostname' => substr(gethostname() ?: 'localhost', 0, 180)),
        'capabilities' => array(
            'passive_inventory' => $passiveInventoryAvailable,
            'active_enabled' => session_can_capability('network_discovery') && $reason === 'ready',
            'configured' => ENABLE_NETWORK_DISCOVERY,
            'allowlist_configured' => (bool)$validAllowedCidrs,
            'recent_auth' => $recentAuth,
            'cooldown_remaining' => $cooldownRemaining,
            'reason' => $reason,
            'available_methods' => $availableMethods
        ),
        'limits' => array('max_hosts' => $plan['budget'], 'configured_max_hosts' => NETWORK_DISCOVERY_MAX_HOSTS, 'deadline_seconds' => NETWORK_DISCOVERY_TIMEOUT, 'cooldown_seconds' => NETWORK_DISCOVERY_COOLDOWN, 'private_rfc1918_ipv4_only' => true, 'ports_scanned' => 0, 'dns_queries' => 0),
        'interfaces' => $interfaces,
        'routes' => $routes,
        'rules' => $rules,
        'neighbors' => $neighbors,
        'eligible_networks' => $scopes,
        'hosts' => $hosts,
        'sources' => $sources,
        'discovery' => array(
            'id' => $active ? secure_random_hex(8) : null,
            'active' => (bool)$active,
            'network_id' => $active && isset($scopes[0]['network_id']) ? $scopes[0]['network_id'] : null,
            'scope' => $active && isset($scopes[0]) ? array('cidr' => $scopes[0]['cidr'], 'interface' => $scopes[0]['interface'], 'ifindex' => $scopes[0]['ifindex']) : null,
            'method' => $probe['method'],
            'reason' => $probe['reason'],
            'candidate_count' => count($plan['addresses']),
            'probes_planned' => $probe['planned'],
            'probes_attempted' => $probe['probes_attempted'],
            'probes_sent' => $probe['probes_attempted'],
            'responded' => count($activeHosts),
            'no_response_count' => $probe['probes_attempted'] === null ? null : max(0, intval($probe['probes_attempted']) - count($activeHosts)),
            'timed_out' => $probe['timed_out'],
            'truncated' => $plan['truncated'] || $probe['partial'],
            'partial' => $probe['partial'],
            'network_state_mutated' => (bool)$active,
            'duration_ms' => $probe['duration_ms']
        ),
        'summary' => array('interfaces' => count($interfaces), 'addresses' => array_sum(array_map(function ($interface) { return count($interface['addresses']); }, $interfaces)), 'routes' => count($routes), 'routing_rules' => count($rules), 'gateways' => count($gateways), 'neighbors' => count($neighbors), 'hosts_observed' => count($hosts), 'hosts_responded' => count($activeHosts), 'eligible_networks' => count($scopes)),
        'warnings' => $warnings,
        'duration_ms' => round((microtime(true) - $started) * 1000)
    );
    return $result;
}

function network_discovery_rate_keys()
{
    $principal = isset($_SESSION['principal']) ? (string)$_SESSION['principal'] : 'unknown';
    $ip = get_client_ip();
    return array(
        'principal:' . hash('sha256', $principal) => 10,
        'ip:' . hash('sha256', $ip) => 30,
        'pair:' . hash('sha256', $principal . '|' . $ip) => 10,
        'global' => 50
    );
}

function network_discovery_rate_prune($state, $now)
{
    if (!is_array($state)) $state = array();
    $validKey = function ($key) { return $key === 'global' || preg_match('/^(?:principal|ip|pair):[a-f0-9]{64}$/D', (string)$key); };
    $last = array();
    if (isset($state['last_by_key']) && is_array($state['last_by_key'])) foreach ($state['last_by_key'] as $key => $timestamp) {
        $timestamp = intval($timestamp);
        if ($validKey($key) && $timestamp >= $now - 86400 && $timestamp <= $now + 300) $last[$key] = $timestamp;
    }
    if (!isset($last['global']) && isset($state['last_global'])) {
        $legacyGlobal = intval($state['last_global']);
        if ($legacyGlobal >= $now - 86400 && $legacyGlobal <= $now + 300) $last['global'] = $legacyGlobal;
    }
    arsort($last, SORT_NUMERIC);
    $last = array_slice($last, 0, 512, true);

    $history = array();
    if (isset($state['history']) && is_array($state['history'])) foreach ($state['history'] as $key => $timestamps) {
        if (!$validKey($key) || !is_array($timestamps)) continue;
        $clean = array_values(array_filter(array_map('intval', array_slice($timestamps, -64)), function ($timestamp) use ($now) { return $timestamp > $now - 3600 && $timestamp <= $now + 300; }));
        sort($clean, SORT_NUMERIC);
        if ($clean) $history[$key] = $clean;
    }
    uasort($history, function ($left, $right) { return max($right) <=> max($left); });
    $history = array_slice($history, 0, 512, true);

    $requestLast = array();
    if (isset($state['request_last']) && is_array($state['request_last'])) foreach ($state['request_last'] as $key => $timestamp) {
        $timestamp = intval($timestamp);
        if ($validKey($key) && $timestamp >= $now - 3600 && $timestamp <= $now + 300) $requestLast[$key] = $timestamp;
    }
    arsort($requestLast, SORT_NUMERIC);
    $requestLast = array_slice($requestLast, 0, 256, true);
    $requestHistory = array();
    if (isset($state['request_history']) && is_array($state['request_history'])) foreach ($state['request_history'] as $key => $timestamps) {
        if (!$validKey($key) || !is_array($timestamps)) continue;
        $clean = array_values(array_filter(array_map('intval', array_slice($timestamps, -128)), function ($timestamp) use ($now) { return $timestamp > $now - 3600 && $timestamp <= $now + 300; }));
        sort($clean, SORT_NUMERIC);
        if ($clean) $requestHistory[$key] = $clean;
    }
    uasort($requestHistory, function ($left, $right) { return max($right) <=> max($left); });
    $requestHistory = array_slice($requestHistory, 0, 256, true);
    return array('last_by_key' => $last, 'history' => $history, 'request_last' => $requestLast, 'request_history' => $requestHistory);
}

function network_discovery_rate_load(&$error)
{
    $error = null;
    if (!file_exists(NETWORK_DISCOVERY_STATE)) return array();
    if (is_link(NETWORK_DISCOVERY_STATE) || !is_file(NETWORK_DISCOVERY_STATE)) { $error = 'El estado del límite de frecuencia no es un archivo regular'; return false; }
    $size = @filesize(NETWORK_DISCOVERY_STATE);
    if ($size === false || intval($size) > 131072) { $error = 'El estado del límite de frecuencia excede el tamaño seguro'; return false; }
    $stateHandle = @fopen(NETWORK_DISCOVERY_STATE, 'rb');
    if (!$stateHandle) { $error = 'No se pudo abrir el estado del límite de frecuencia'; return false; }
    $raw = stream_get_contents($stateHandle, 131073);
    fclose($stateHandle);
    if ($raw === false || strlen($raw) > 131072) { $error = 'No se pudo leer el estado del límite de frecuencia'; return false; }
    if (trim($raw) === '') return array();
    $state = json_decode($raw, true);
    if (!is_array($state)) { $error = 'El estado del límite de frecuencia está dañado; se bloqueó el descubrimiento'; return false; }
    return $state;
}

function network_discovery_rate_write($state, &$error)
{
    $error = null;
    $encoded = json_encode($state);
    if (!is_string($encoded) || strlen($encoded) > 131072) { $error = 'El estado del límite de frecuencia no cabe en el almacenamiento seguro'; return false; }
    if (is_link(NETWORK_DISCOVERY_STATE)) { $error = 'El archivo de frecuencia no puede ser un enlace simbólico'; return false; }
    $temporaryPath = NETWORK_DISCOVERY_STATE . '.' . secure_random_hex(6) . '.tmp';
    $temporaryHandle = @fopen($temporaryPath, 'x+b');
    if (!$temporaryHandle) { $error = 'No se pudo crear el estado temporal del límite de frecuencia'; return false; }
    @chmod($temporaryPath, 0600);
    $offset = 0; $length = strlen($encoded); $writeOk = true;
    while ($offset < $length) {
        $written = @fwrite($temporaryHandle, substr($encoded, $offset));
        if ($written === false || $written < 1) { $writeOk = false; break; }
        $offset += $written;
    }
    if (!@fflush($temporaryHandle)) $writeOk = false;
    if (function_exists('fsync') && !@fsync($temporaryHandle)) $writeOk = false;
    @fclose($temporaryHandle);
    if (!$writeOk || $offset !== $length || !@rename($temporaryPath, NETWORK_DISCOVERY_STATE)) {
        @unlink($temporaryPath);
        $error = 'No se pudo persistir atómicamente el límite de frecuencia; la operación fue cancelada';
        return false;
    }
    @chmod(NETWORK_DISCOVERY_STATE, 0600);
    return !is_link(NETWORK_DISCOVERY_STATE) && is_file(NETWORK_DISCOVERY_STATE);
}

function network_discovery_lock_release($reservation)
{
    $handle = is_array($reservation) && isset($reservation['handle']) ? $reservation['handle'] : $reservation;
    if (is_resource($handle)) { @flock($handle, LOCK_UN); @fclose($handle); }
}

function network_discovery_lock_acquire(&$error, &$retryAfter)
{
    $error = null; $retryAfter = 0;
    if (!PANEL_STORAGE_READY || is_link(NETWORK_DISCOVERY_LOCK)) { $error = 'El almacenamiento privado del descubrimiento no está disponible'; return false; }
    $handle = @fopen(NETWORK_DISCOVERY_LOCK, 'c+');
    if (!$handle) { $error = 'No se pudo abrir el control de concurrencia'; return false; }
    @chmod(NETWORK_DISCOVERY_LOCK, 0600);
    if (!flock($handle, LOCK_EX | LOCK_NB)) { fclose($handle); $error = 'Ya hay un descubrimiento de red en ejecución'; $retryAfter = 10; return false; }
    $loadError = null;
    $state = network_discovery_rate_load($loadError);
    if ($state === false) { network_discovery_lock_release($handle); $error = $loadError; return false; }
    $now = time();
    $state = network_discovery_rate_prune($state, $now);
    $bucketLimits = network_discovery_rate_keys();
    $retryAfter = 0; $hourlyExceeded = false;
    foreach ($bucketLimits as $bucketKey => $limit) {
        $last = isset($state['last_by_key'][$bucketKey]) ? intval($state['last_by_key'][$bucketKey]) : 0;
        $cooldown = $bucketKey === 'global' ? 15 : NETWORK_DISCOVERY_COOLDOWN;
        if ($last) $retryAfter = max($retryAfter, $cooldown - ($now - $last));
        $history = isset($state['history'][$bucketKey]) ? $state['history'][$bucketKey] : array();
        if (count($history) >= $limit) { $hourlyExceeded = true; $retryAfter = max($retryAfter, 3600 - ($now - min($history))); }
    }
    if ($retryAfter > 0 || $hourlyExceeded) {
        network_discovery_lock_release($handle);
        $error = 'Límite de frecuencia del descubrimiento alcanzado';
        return false;
    }
    // Los intentos inválidos tienen un bucket separado: no consumen cuota de sondeo,
    // pero tampoco pueden forzar inventarios costosos de forma ilimitada.
    $pairKey = null;
    foreach ($bucketLimits as $bucketKey => $limit) if (strpos($bucketKey, 'pair:') === 0) { $pairKey = $bucketKey; break; }
    $requestLimits = array('global' => 100);
    if ($pairKey !== null) $requestLimits[$pairKey] = 30;
    foreach ($requestLimits as $bucketKey => $limit) {
        $last = isset($state['request_last'][$bucketKey]) ? intval($state['request_last'][$bucketKey]) : 0;
        $minimumGap = $bucketKey === 'global' ? 2 : 5;
        if ($last) $retryAfter = max($retryAfter, $minimumGap - ($now - $last));
        $history = isset($state['request_history'][$bucketKey]) ? $state['request_history'][$bucketKey] : array();
        if (count($history) >= $limit) { $hourlyExceeded = true; $retryAfter = max($retryAfter, 3600 - ($now - min($history))); }
    }
    if ($retryAfter > 0 || $hourlyExceeded) {
        network_discovery_lock_release($handle);
        $error = 'Límite de frecuencia de solicitudes de descubrimiento alcanzado';
        return false;
    }
    foreach ($requestLimits as $bucketKey => $limit) {
        $state['request_last'][$bucketKey] = $now;
        $history = isset($state['request_history'][$bucketKey]) && is_array($state['request_history'][$bucketKey]) ? $state['request_history'][$bucketKey] : array();
        $history[] = $now;
        $state['request_history'][$bucketKey] = array_slice($history, -$limit);
    }
    $state = network_discovery_rate_prune($state, $now);
    $requestWriteError = null;
    if (!network_discovery_rate_write($state, $requestWriteError)) { network_discovery_lock_release($handle); $error = $requestWriteError; return false; }
    return array('handle' => $handle, 'state' => $state, 'bucket_limits' => $bucketLimits, 'committed' => false);
}

function network_discovery_rate_commit(&$reservation, &$error)
{
    $error = null;
    if (!is_array($reservation) || empty($reservation['handle']) || !is_resource($reservation['handle']) || !empty($reservation['committed'])) { $error = 'Reserva de frecuencia inválida'; return false; }
    $now = time();
    $state = network_discovery_rate_prune(isset($reservation['state']) ? $reservation['state'] : array(), $now);
    $bucketLimits = isset($reservation['bucket_limits']) && is_array($reservation['bucket_limits']) ? $reservation['bucket_limits'] : network_discovery_rate_keys();
    foreach ($bucketLimits as $bucketKey => $limit) {
        $state['last_by_key'][$bucketKey] = $now;
        $history = isset($state['history'][$bucketKey]) && is_array($state['history'][$bucketKey]) ? $state['history'][$bucketKey] : array();
        $history[] = $now;
        $state['history'][$bucketKey] = array_slice($history, -max(1, intval($limit)));
    }
    $state = network_discovery_rate_prune($state, $now);
    if (!network_discovery_rate_write($state, $error)) return false;
    $reservation['state'] = $state;
    $reservation['committed'] = true;
    return true;
}

function network_inventory_guard_acquire(&$error, &$retryAfter)
{
    $error = null; $retryAfter = 0;
    if (!PANEL_STORAGE_READY || is_link(NETWORK_INVENTORY_LOCK) || is_link(NETWORK_DISCOVERY_LOCK)) { $error = 'El almacenamiento privado del inventario no está disponible'; return false; }
    $rateHandle = @fopen(NETWORK_INVENTORY_LOCK, 'c+');
    if (!$rateHandle) { $error = 'No se pudo abrir el semáforo del inventario'; return false; }
    @chmod(NETWORK_INVENTORY_LOCK, 0600);
    if (!flock($rateHandle, LOCK_EX | LOCK_NB)) { fclose($rateHandle); $error = 'Ya hay un inventario de red en curso'; $retryAfter = 2; return false; }
    rewind($rateHandle);
    $state = json_decode(stream_get_contents($rateHandle, 4096) ?: '{}', true);
    if (!is_array($state)) $state = array();
    $nowMs = intval(round(microtime(true) * 1000));
    $lastMs = isset($state['last_started_ms']) ? intval($state['last_started_ms']) : 0;
    if ($lastMs && $nowMs - $lastMs < 2000) {
        $retryAfter = max(1, intval(ceil((2000 - ($nowMs - $lastMs)) / 1000)));
        flock($rateHandle, LOCK_UN); fclose($rateHandle); $error = 'Espere antes de actualizar nuevamente el inventario'; return false;
    }
    $discoveryHandle = @fopen(NETWORK_DISCOVERY_LOCK, 'c+');
    if (!$discoveryHandle || !flock($discoveryHandle, LOCK_SH | LOCK_NB)) {
        if ($discoveryHandle) fclose($discoveryHandle);
        flock($rateHandle, LOCK_UN); fclose($rateHandle); $error = 'El inventario está pausado mientras se descubre la red'; $retryAfter = 3; return false;
    }
    @chmod(NETWORK_DISCOVERY_LOCK, 0600);
    $encoded = json_encode(array('last_started_ms' => $nowMs));
    rewind($rateHandle);
    $persisted = is_string($encoded) && ftruncate($rateHandle, 0) && fwrite($rateHandle, $encoded) === strlen($encoded) && fflush($rateHandle);
    if (!$persisted) {
        flock($discoveryHandle, LOCK_UN); fclose($discoveryHandle); flock($rateHandle, LOCK_UN); fclose($rateHandle); $error = 'No se pudo persistir el límite del inventario'; return false;
    }
    return array($rateHandle, $discoveryHandle);
}

function network_inventory_guard_release($handles)
{
    if (!is_array($handles)) return;
    foreach (array_reverse($handles) as $handle) if (is_resource($handle)) { flock($handle, LOCK_UN); fclose($handle); }
}

function getCrontabs()
{
    return cmd("crontab -l 2>/dev/null") ?: 'No crontab entries';
}

function getUsers()
{
    $o = cmd("cat /etc/passwd|grep -v nologin|grep -v /bin/false");
    $us = array();
    foreach (explode("\n", $o) as $l) {
        if (trim($l) == '')
            continue;
        $p = explode(':', $l);
        if (count($p) >= 7) {
            $us[] = array(
                'name' => $p[0],
                'uid' => $p[2],
                'gid' => $p[3],
                'home' => $p[5],
                'shell' => $p[6]
            );
        }
    }
    return $us;
}

function getLastLogins()
{
    return cmd("last -20") ?: 'No login records';
}

function getFirewall()
{
    // CentOS: firewalld first
    if (command_exists('firewall-cmd')) {
        $zones = cmd("firewall-cmd --list-all 2>/dev/null");
        $active = cmd("firewall-cmd --get-active-zones 2>/dev/null");
        return "=== Active Zones ===\n" . $active . "\n\n=== Firewall Rules ===\n" . $zones;
    }
    $ipt = cmd("iptables -L -n 2>/dev/null");
    return $ipt ?: 'No firewall data available';
}

function getServices()
{
    if (command_exists('systemctl')) {
        return cmd("systemctl list-units --type=service --state=running --no-pager|head -40");
    } elseif (command_exists('service')) {
        return cmd("service --status-all 2>/dev/null|grep '\\[ + \\]'|head -40");
    } else {
        return 'No service manager detected';
    }
}

function getEnvVars()
{
    $allowed = array('LANG', 'LC_ALL', 'LC_CTYPE', 'TZ', 'TERM', 'SHELL');
    $environment = function_exists('getenv') ? getenv() : array();
    if (!is_array($environment)) return 'Environment inventory unavailable';
    $visible = array();
    $omitted = 0;
    foreach ($environment as $name => $value) {
        if (in_array($name, $allowed, true)) {
            $visible[] = $name . '=' . audit_clean_text($value, 180);
        } else {
            $omitted++;
        }
    }
    sort($visible, SORT_STRING);
    $visible[] = '[security] ' . $omitted . ' variable(s) omitted; secret values are never returned.';
    return implode("\n", $visible);
}

function getLogs($type)
{
    // CentOS/RHEL log paths
    $logFiles = array(
        'messages' => '/var/log/messages',
        'secure' => '/var/log/secure',
        'yum' => '/var/log/yum.log',
        'audit' => '/var/log/audit/audit.log',
        'cron' => '/var/log/cron',
        'maillog' => '/var/log/maillog',
        'boot' => '/var/log/boot.log'
    );
    if ($type === 'dmesg') {
        return cmd("dmesg|tail -50");
    } elseif ($type === 'journal') {
        return cmd("journalctl -n 50 --no-pager 2>/dev/null");
    } elseif (isset($logFiles[$type])) {
        return cmd("tail -50 " . $logFiles[$type] . " 2>/dev/null") ?: 'Log file not available or no permission';
    } else {
        return 'Unknown log type';
    }
}

// ---------- CentOS Exclusive ----------
function getSelinux()
{
    $enforce = cmd("getenforce 2>/dev/null") ?: 'Unknown';
    $status = cmd("sestatus 2>/dev/null") ?: 'sestatus not available';
    $booleans = cmd("getsebool -a 2>/dev/null | head -30") ?: '';
    return array(
        'enforce' => $enforce,
        'status' => $status,
        'booleans' => $booleans
    );
}

function getPackages()
{
    $total = cmd("rpm -qa 2>/dev/null | wc -l") ?: '0';
    $recent = cmd("rpm -qa --last 2>/dev/null | head -30") ?: 'No package data';
    return array(
        'total' => intval($total),
        'recent' => $recent
    );
}

function getYumUpdates()
{
    $updates = cmd("yum check-update 2>/dev/null | tail -n +3 | head -30");
    if (!$updates) {
        $updates = cmd("dnf check-update 2>/dev/null | tail -n +3 | head -30") ?: 'No updates available or command not found';
    }
    return $updates;
}

function getRepos()
{
    $repos = cmd("yum repolist 2>/dev/null");
    if (!$repos) {
        $repos = cmd("dnf repolist 2>/dev/null") ?: 'No repo data';
    }
    return $repos;
}

function getFailedServices()
{
    return cmd("systemctl --failed --no-pager 2>/dev/null") ?: 'No failed services or systemctl not available';
}

function getCentOSVersion()
{
    $release = cmd("cat /etc/redhat-release 2>/dev/null") ?: cmd("cat /etc/centos-release 2>/dev/null") ?: '';
    return $release;
}

// ---------- Auditoría defensiva (solo lectura) ----------
function audit_clean_text($value, $max = 500)
{
    $value = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', (string)$value);
    return strlen($value) > $max ? substr($value, 0, $max) . '…' : $value;
}

function audit_read_file($path, $maxBytes = 262144)
{
    if (!is_string($path) || strpos($path, "\0") !== false || !is_file($path) || !is_readable($path)) return false;
    $handle = @fopen($path, 'rb');
    if (!$handle) return false;
    $content = @stream_get_contents($handle, max(1, intval($maxBytes)));
    fclose($handle);
    return $content === false ? false : $content;
}

function audit_record(&$report, $id, $category, $status, $severity, $title, $evidence, $remediation, $confidence = 'high')
{
    $validStatus = array('pass', 'fail', 'warn', 'skipped', 'error');
    $validSeverity = array('critical', 'high', 'medium', 'low', 'info');
    $status = in_array($status, $validStatus, true) ? $status : 'error';
    $severity = in_array($severity, $validSeverity, true) ? $severity : 'info';
    $check = array(
        'id' => preg_replace('/[^a-z0-9_.-]/i', '', (string)$id),
        'category' => preg_replace('/[^a-z0-9_.-]/i', '', (string)$category),
        'status' => $status,
        'severity' => $severity,
        'confidence' => in_array($confidence, array('high', 'medium', 'low'), true) ? $confidence : 'medium',
        'title' => audit_clean_text($title, 180),
        'evidence' => $evidence,
        'remediation' => audit_clean_text($remediation, 700)
    );
    $report['checks'][] = $check;
    if ($status === 'fail' || $status === 'warn') $report['findings'][] = $check;
}

function audit_file_mode($path)
{
    $mode = @fileperms($path);
    return $mode === false ? null : ($mode & 07777);
}

function audit_mode_string($mode)
{
    return $mode === null ? 'unknown' : str_pad(decoct($mode), 4, '0', STR_PAD_LEFT);
}

function audit_collect_accounts(&$report)
{
    $lines = @file('/etc/passwd', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($lines)) {
        audit_record($report, 'accounts.passwd', 'accounts', 'skipped', 'info', 'No se pudo leer el inventario de cuentas', array('source' => '/etc/passwd'), 'Ejecute el colector con permiso de lectura sobre la base de cuentas.', 'high');
        return;
    }

    $users = array();
    $uids = array();
    $extraRoot = array();
    $systemShells = array();
    $homeIssues = array();
    $sshIssues = array();
    $interactiveShells = array('/bin/bash', '/bin/sh', '/bin/zsh', '/bin/fish', '/bin/ksh', '/usr/bin/bash', '/usr/bin/zsh');
    foreach ($lines as $line) {
        $parts = explode(':', $line);
        if (count($parts) < 7) continue;
        $name = audit_clean_text($parts[0], 64);
        $uid = intval($parts[2]);
        $gid = intval($parts[3]);
        $home = audit_clean_text($parts[5], 220);
        $shell = audit_clean_text($parts[6], 120);
        $interactive = in_array($shell, $interactiveShells, true) || preg_match('#/(ba|z|fi|k)?sh$#', $shell);
        if (!isset($uids[$uid])) $uids[$uid] = array();
        $uids[$uid][] = $name;
        if ($uid === 0 && $name !== 'root') $extraRoot[] = $name;
        if ($uid > 0 && $uid < 1000 && $interactive) $systemShells[] = $name;
        if ($interactive && $uid >= 1000) {
            if (!is_dir($home)) {
                $homeIssues[] = $name . ': home inexistente';
            } else {
                $mode = audit_file_mode($home);
                $homeStat = @stat($home);
                if ($mode !== null && ($mode & 0022)) $homeIssues[] = $name . ': home escribible por grupo/otros (' . audit_mode_string($mode) . ')';
                if (is_array($homeStat) && intval($homeStat['uid']) !== $uid) $homeIssues[] = $name . ': propietario del home no coincide';
            }
        }
        $authorizedKeyCount = 0;
        if ($interactive && is_dir($home . '/.ssh')) {
            $sshMode = audit_file_mode($home . '/.ssh');
            if ($sshMode !== null && ($sshMode & 0077)) $sshIssues[] = $name . ': .ssh modo ' . audit_mode_string($sshMode);
            $authorized = $home . '/.ssh/authorized_keys';
            if (is_file($authorized)) {
                $authorizedMode = audit_file_mode($authorized);
                if ($authorizedMode !== null && ($authorizedMode & 0077)) $sshIssues[] = $name . ': authorized_keys modo ' . audit_mode_string($authorizedMode);
                $keyFile = audit_read_file($authorized, 262144);
                if ($keyFile !== false) foreach (preg_split('/\R/', $keyFile) as $keyLine) if (trim($keyLine) !== '' && trim($keyLine)[0] !== '#') $authorizedKeyCount++;
            }
        }
        $users[] = array(
            'name' => $name,
            'uid' => $uid,
            'gid' => $gid,
            'home' => $home,
            'shell' => $shell,
            'interactive' => (bool)$interactive,
            'authorized_key_count' => $authorizedKeyCount,
            'password_state' => 'not_assessed',
            'password_algorithm' => 'not_assessed',
            'password_max_days' => null
        );
    }
    $duplicates = array();
    foreach ($uids as $uid => $names) if (count($names) > 1) $duplicates[] = 'UID ' . $uid . ': ' . implode(', ', $names);

    audit_record($report, 'accounts.extra_uid0', 'accounts', $extraRoot ? 'fail' : 'pass', 'critical', $extraRoot ? 'Existen cuentas adicionales con UID 0' : 'No hay UID 0 adicionales', array('accounts' => $extraRoot), 'Elimine el UID 0 adicional o asigne privilegios mínimos mediante sudo.');
    audit_record($report, 'accounts.duplicate_uid', 'accounts', $duplicates ? 'fail' : 'pass', 'high', $duplicates ? 'Hay identificadores de usuario duplicados' : 'Los UID son únicos', array('duplicates' => $duplicates), 'Asigne un UID único a cada identidad y revise propiedad de archivos.');
    audit_record($report, 'accounts.system_shells', 'accounts', $systemShells ? 'warn' : 'pass', 'medium', $systemShells ? 'Cuentas de servicio conservan shell interactiva' : 'Las cuentas de servicio no tienen shell interactiva', array('accounts' => $systemShells), 'Cambie a /usr/sbin/nologin cuando la cuenta no requiera acceso interactivo.');
    audit_record($report, 'accounts.home_permissions', 'accounts', $homeIssues ? 'fail' : 'pass', 'high', $homeIssues ? 'Se detectaron homes inseguros o ausentes' : 'Los homes interactivos tienen una configuración básica segura', array('issues' => $homeIssues), 'Cree el home correcto y retire escritura para grupo/otros.');
    audit_record($report, 'accounts.ssh_permissions', 'permissions', $sshIssues ? 'fail' : 'pass', 'high', $sshIssues ? 'Hay permisos inseguros en .ssh o authorized_keys' : 'Los directorios y claves autorizadas revisados tienen modos restrictivos', array('issues' => $sshIssues, 'key_material_exposed' => false), 'Use modo 0700 para .ssh y 0600 para authorized_keys, con propietario correcto.');

    $shadow = @file('/etc/shadow', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!is_array($shadow)) {
        audit_record($report, 'credentials.shadow', 'credentials', 'skipped', 'info', 'Estado de contraseñas no verificado por permisos', array('source' => '/etc/shadow', 'hashes_exposed' => false), 'Ejecute un colector local privilegiado de solo lectura; no exponga /etc/shadow al servidor web.');
    } else {
        $empty = array();
        $weak = array();
        $unlimited = array();
        $hashOwners = array();
        $shadowByUser = array();
        foreach ($shadow as $line) {
            $parts = explode(':', $line);
            if (count($parts) < 5) continue;
            $name = $parts[0];
            $hash = $parts[1];
            $maxDays = isset($parts[4]) && $parts[4] !== '' ? intval($parts[4]) : null;
            $locked = $hash !== '' && ($hash[0] === '!' || $hash[0] === '*');
            $algorithm = 'locked';
            if ($hash === '') {
                $algorithm = 'none';
                $empty[] = $name;
            } elseif (!$locked) {
                if (strpos($hash, '$y$') === 0) $algorithm = 'yescrypt';
                elseif (preg_match('/^\$2[aby]\$/', $hash)) $algorithm = 'bcrypt';
                elseif (strpos($hash, '$6$') === 0) $algorithm = 'sha512crypt';
                elseif (strpos($hash, '$5$') === 0) { $algorithm = 'sha256crypt'; $weak[] = $name . ' (SHA-256 crypt)'; }
                elseif (strpos($hash, '$1$') === 0) { $algorithm = 'md5crypt'; $weak[] = $name . ' (MD5 crypt)'; }
                elseif (strlen($hash) === 13) { $algorithm = 'descrypt'; $weak[] = $name . ' (DES crypt)'; }
                else { $algorithm = 'unknown'; $weak[] = $name . ' (algoritmo desconocido)'; }
                if (!isset($hashOwners[$hash])) $hashOwners[$hash] = array();
                $hashOwners[$hash][] = $name;
            }
            if (!$locked && $hash !== '' && ($maxDays === null || $maxDays < 0 || $maxDays > 365)) $unlimited[] = $name;
            $shadowByUser[$name] = array('state' => $hash === '' ? 'empty' : ($locked ? 'locked' : 'set'), 'algorithm' => $algorithm, 'max_days' => $maxDays);
        }
        $reused = array();
        foreach ($hashOwners as $owners) if (count($owners) > 1) $reused[] = implode(', ', $owners);
        foreach ($users as &$user) {
            if (isset($shadowByUser[$user['name']])) {
                $user['password_state'] = $shadowByUser[$user['name']]['state'];
                $user['password_algorithm'] = $shadowByUser[$user['name']]['algorithm'];
                $user['password_max_days'] = $shadowByUser[$user['name']]['max_days'];
            }
        }
        unset($user);
        audit_record($report, 'credentials.empty_password', 'credentials', $empty ? 'fail' : 'pass', 'critical', $empty ? 'Hay cuentas con contraseña vacía' : 'No hay hashes vacíos en shadow', array('accounts' => $empty, 'hashes_exposed' => false), 'Bloquee inmediatamente la cuenta o establezca una contraseña robusta.');
        audit_record($report, 'credentials.weak_hash', 'credentials', $weak ? 'fail' : 'pass', 'high', $weak ? 'Se detectaron algoritmos de contraseña débiles' : 'Los hashes desbloqueados usan algoritmos aceptables', array('accounts' => $weak, 'hashes_exposed' => false), 'Migre las contraseñas a yescrypt o al algoritmo recomendado por la distribución.');
        audit_record($report, 'credentials.reused_hash', 'credentials', $reused ? 'fail' : 'pass', 'high', $reused ? 'Varias cuentas comparten el mismo verificador de contraseña' : 'No se detectaron verificadores repetidos', array('account_groups' => $reused, 'hashes_exposed' => false), 'Asigne una contraseña única a cada cuenta. El valor del hash no se incluye en este informe.');
        audit_record($report, 'credentials.password_age', 'access_control', $unlimited ? 'warn' : 'pass', 'medium', $unlimited ? 'Hay contraseñas sin caducidad razonable' : 'La vigencia de contraseñas está limitada', array('accounts' => $unlimited), 'Defina PASS_MAX_DAYS y aplique chage -M según la política de la organización.');
    }
    $report['inventory']['accounts'] = $users;
}

function audit_collect_privileges(&$report)
{
    $privilegedNames = array('sudo', 'wheel', 'admin', 'docker', 'lxd', 'libvirt', 'disk', 'shadow');
    $memberships = array();
    $groupIds = array();
    $privilegedGids = array();
    $groupLines = @file('/etc/group', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (is_array($groupLines)) {
        foreach ($groupLines as $line) {
            $parts = explode(':', $line);
            if (count($parts) < 4) continue;
            $gid = intval($parts[2]);
            if (!isset($groupIds[$gid])) $groupIds[$gid] = array();
            $groupIds[$gid][] = audit_clean_text($parts[0], 64);
            if (!in_array($parts[0], $privilegedNames, true)) continue;
            $privilegedGids[$gid] = $parts[0];
            $members = array_values(array_filter(explode(',', $parts[3]), 'strlen'));
            if ($members) $memberships[$parts[0]] = array_map(function ($v) { return audit_clean_text($v, 64); }, $members);
        }
        foreach ($report['inventory']['accounts'] as $account) {
            if (!isset($privilegedGids[intval($account['gid'])])) continue;
            $groupName = $privilegedGids[intval($account['gid'])];
            if (!isset($memberships[$groupName])) $memberships[$groupName] = array();
            $memberships[$groupName][] = $account['name'];
        }
        foreach ($memberships as $groupName => $members) $memberships[$groupName] = array_values(array_unique($members));
        $duplicateGids = array();
        foreach ($groupIds as $gid => $names) if (count($names) > 1) $duplicateGids[] = 'GID ' . $gid . ': ' . implode(', ', $names);
        $dangerous = array_intersect_key($memberships, array_flip(array('docker', 'lxd', 'disk', 'shadow')));
        audit_record($report, 'accounts.duplicate_gid', 'accounts', $duplicateGids ? 'warn' : 'pass', 'medium', $duplicateGids ? 'Hay identificadores de grupo duplicados' : 'Los GID son únicos', array('duplicates' => $duplicateGids), 'Confirme que los GID compartidos sean intencionales; asigne identificadores únicos cuando no lo sean.');
        audit_record($report, 'privileges.powerful_groups', 'privileges', $dangerous ? 'warn' : 'pass', 'high', $dangerous ? 'Usuarios pertenecen a grupos con acceso equivalente a privilegios elevados' : 'No se hallaron miembros explícitos en grupos de alto riesgo', array('groups' => $dangerous, 'administrative_groups' => $memberships), 'Revise cada miembro; retire accesos docker/lxd/disk/shadow que no sean imprescindibles.');
    } else {
        audit_record($report, 'privileges.groups', 'privileges', 'skipped', 'info', 'No se pudo evaluar la pertenencia a grupos', array('source' => '/etc/group'), 'Habilite lectura del inventario de grupos para el colector.');
    }

    $sudoFiles = array('/etc/sudoers');
    if (is_dir('/etc/sudoers.d')) {
        $extra = @scandir('/etc/sudoers.d');
        if (is_array($extra)) foreach ($extra as $name) {
            if ($name !== '.' && $name !== '..' && $name[0] !== '.') $sudoFiles[] = '/etc/sudoers.d/' . $name;
        }
    }
    $nopasswd = array();
    $noauth = array();
    $readAny = false;
    foreach ($sudoFiles as $file) {
        $content = audit_read_file($file, 262144);
        if ($content === false) continue;
        $readAny = true;
        foreach (preg_split('/\R/', $content) as $number => $line) {
            $line = preg_replace('/\s+#.*$/', '', $line);
            if (!trim($line)) continue;
            $subject = preg_split('/\s+/', trim($line))[0];
            if (stripos($line, 'NOPASSWD:') !== false) $nopasswd[] = array('file' => $file, 'line' => $number + 1, 'subject' => audit_clean_text($subject, 80));
            if (stripos($line, '!authenticate') !== false) $noauth[] = array('file' => $file, 'line' => $number + 1, 'subject' => audit_clean_text($subject, 80));
        }
    }
    if (!$readAny) {
        audit_record($report, 'privileges.sudoers', 'privileges', 'skipped', 'info', 'Reglas sudo no verificadas por permisos', array('sources' => $sudoFiles), 'Valide sudoers con un colector privilegiado y visudo -cf.');
    } else {
        audit_record($report, 'privileges.sudo_nopasswd', 'privileges', $nopasswd ? 'warn' : 'pass', 'high', $nopasswd ? 'Hay reglas sudo sin autenticación' : 'No se detectó NOPASSWD en sudoers', array('rules' => $nopasswd), 'Limite NOPASSWD a comandos concretos, con rutas absolutas y sin comodines/intérpretes.');
        audit_record($report, 'privileges.sudo_noauthenticate', 'privileges', $noauth ? 'fail' : 'pass', 'high', $noauth ? 'sudo contiene la opción !authenticate' : 'sudo exige autenticación', array('rules' => $noauth), 'Retire !authenticate salvo excepción documentada y compensada.');
    }
}

function audit_panel_events($limit = 80)
{
    if (!is_file(PANEL_EVENT_LOG) || !is_readable(PANEL_EVENT_LOG)) return array();
    $size = @filesize(PANEL_EVENT_LOG);
    $offset = ($size !== false && $size > 262144) ? $size - 262144 : 0;
    $raw = @file_get_contents(PANEL_EVENT_LOG, false, null, $offset);
    if ($raw === false) return array();
    if ($offset > 0) $raw = substr($raw, strpos($raw, "\n") + 1);
    $events = array();
    foreach (preg_split('/\R/', trim($raw)) as $line) {
        $event = json_decode($line, true);
        if (!is_array($event) || empty($event['event'])) continue;
        $events[] = array(
            'time' => isset($event['time']) ? audit_clean_text($event['time'], 40) : '',
            'event' => audit_clean_text($event['event'], 64),
            'ip' => isset($event['ip']) ? audit_clean_text($event['ip'], 64) : 'unknown',
            'principal' => isset($event['principal']) ? audit_clean_text($event['principal'], 128) : 'unknown',
            'role' => isset($event['role']) ? audit_clean_text($event['role'], 24) : 'none',
            'session' => isset($event['session']) ? audit_clean_text($event['session'], 16) : null,
            'details' => isset($event['details']) && is_array($event['details']) ? $event['details'] : array()
        );
    }
    return array_slice(array_reverse($events), 0, max(1, min(200, intval($limit))));
}

function audit_command_lines($command, $limit = 40)
{
    $output = cmd($command);
    if (!$output) return array();
    $lines = array();
    foreach (preg_split('/\R/', $output) as $line) {
        $line = trim(audit_clean_text($line, 320));
        if ($line === '' || stripos($line, 'wtmp begins') !== false || stripos($line, 'btmp begins') !== false) continue;
        $lines[] = $line;
        if (count($lines) >= $limit) break;
    }
    return $lines;
}

function audit_collect_access(&$report)
{
    $active = command_exists('who') ? audit_command_lines('who', 50) : array();
    $recent = command_exists('last') ? audit_command_lines('last -n 30 -w', 30) : array();
    $failedSourceAvailable = command_exists('lastb') && (!file_exists('/var/log/btmp') || is_readable('/var/log/btmp'));
    $failed = $failedSourceAvailable ? audit_command_lines('lastb -n 30 -w', 30) : array();
    $events = audit_panel_events(80);
    $panelFailures = 0;
    $sensitiveActions = 0;
    foreach ($events as $event) {
        if (in_array($event['event'], array('login_failed', 'login_locked', 'csrf_rejected'), true)) $panelFailures++;
        if (in_array($event['event'], array('shell_exec', 'file_write', 'process_kill', 'terminal_exec'), true)) $sensitiveActions++;
    }
    $report['access'] = array(
        'active_sessions' => $active,
        'recent_logins' => $recent,
        'failed_logins' => $failed,
        'panel_events' => $events
    );
    audit_record($report, 'access.active_sessions', 'access_control', 'pass', 'info', count($active) . ' sesión(es) activa(s) inventariadas', array('count' => count($active)), 'Revise que cada sesión corresponda a un usuario y origen esperado.');
    $failedStatus = (count($failed) >= 10 || $panelFailures >= 5) ? 'warn' : ($failedSourceAvailable ? 'pass' : 'skipped');
    audit_record($report, 'access.failed_logins', 'access_control', $failedStatus, 'medium', (count($failed) || $panelFailures) ? 'Se observaron intentos de autenticación fallidos' : ($failedSourceAvailable ? 'No se observaron fallos en las fuentes disponibles' : 'Los fallos del sistema no pudieron verificarse'), array('system_source_available' => $failedSourceAvailable, 'system_records' => count($failed), 'panel_records' => $panelFailures), 'Correlacione usuario, IP y hora; habilite acceso de solo lectura a btmp/journal y aplique alertas.');
    audit_record($report, 'access.panel_traceability', 'access_control', PANEL_STORAGE_READY ? 'pass' : 'fail', 'high', PANEL_STORAGE_READY ? 'El panel registra accesos y acciones sensibles' : 'El almacenamiento privado de eventos no es seguro', array('events_loaded' => count($events), 'sensitive_actions' => $sensitiveActions, 'storage_ready' => PANEL_STORAGE_READY, 'values_redacted' => true), 'Configure PANEL_DATA_DIR fuera del webroot, propiedad del usuario PHP y modo 0700; reenvíe eventos a journald/SIEM para trazabilidad resistente.');

    $pamFiles = array('/etc/pam.d/system-auth', '/etc/pam.d/password-auth', '/etc/pam.d/common-auth', '/etc/pam.d/common-password');
    $pam = '';
    $pamSources = array();
    foreach ($pamFiles as $file) {
        $content = audit_read_file($file, 131072);
        if ($content !== false) { $pam .= "\n" . $content; $pamSources[] = $file; }
    }
    if (!$pamSources) {
        audit_record($report, 'access.pam_lockout', 'access_control', 'skipped', 'info', 'Política PAM de bloqueo no verificada', array('sources' => $pamFiles), 'Compruebe pam_faillock o un control equivalente en la distribución.');
    } else {
        $hasLockout = stripos($pam, 'pam_faillock') !== false || stripos($pam, 'pam_tally2') !== false;
        $hasNullok = preg_match('/\bnullok\b/i', $pam);
        $hasQuality = stripos($pam, 'pam_pwquality') !== false || stripos($pam, 'pam_cracklib') !== false;
        $hasHistory = stripos($pam, 'pam_pwhistory') !== false || preg_match('/\bremember\s*=\s*[1-9]/i', $pam);
        audit_record($report, 'access.pam_lockout', 'access_control', $hasLockout ? 'pass' : 'warn', 'high', $hasLockout ? 'PAM aplica control de intentos fallidos' : 'No se detectó bloqueo de fuerza bruta en PAM', array('sources' => $pamSources), 'Configure pam_faillock con umbral, ventana y desbloqueo acordes a la política.');
        audit_record($report, 'credentials.pam_nullok', 'credentials', $hasNullok ? 'fail' : 'pass', 'critical', $hasNullok ? 'PAM permite credenciales vacías mediante nullok' : 'PAM no contiene nullok', array('sources' => $pamSources), 'Retire nullok de los módulos de autenticación.');
        audit_record($report, 'credentials.password_quality', 'credentials', $hasQuality ? 'pass' : 'warn', 'medium', $hasQuality ? 'PAM aplica un módulo de calidad de contraseñas' : 'No se detectó pwquality/cracklib', array('sources' => $pamSources), 'Configure pam_pwquality con longitud, clases y diccionario acordes a la política.');
        audit_record($report, 'credentials.password_history', 'credentials', $hasHistory ? 'pass' : 'warn', 'low', $hasHistory ? 'PAM limita la reutilización de contraseñas' : 'No se detectó historial de contraseñas', array('sources' => $pamSources), 'Configure pam_pwhistory y recuerde suficientes credenciales previas.');
    }
}

function audit_collect_ssh(&$report)
{
    $settings = array();
    $source = 'not_available';
    if (command_exists('sshd')) {
        $effective = cmd('sshd -T -C user=root,host=localhost,addr=127.0.0.1');
        if ($effective) {
            foreach (preg_split('/\R/', $effective) as $line) {
                $parts = preg_split('/\s+/', trim($line), 2);
                if (count($parts) === 2) $settings[strtolower($parts[0])] = strtolower(trim($parts[1]));
            }
            $source = 'sshd -T';
        }
    }
    if (!$settings) {
        $config = audit_read_file('/etc/ssh/sshd_config', 262144);
        if ($config !== false) {
            foreach (preg_split('/\R/', $config) as $line) {
                $line = trim(preg_replace('/\s+#.*$/', '', $line));
                if ($line === '' || $line[0] === '#') continue;
                $parts = preg_split('/\s+/', $line, 2);
                if (count($parts) !== 2 || strtolower($parts[0]) === 'match') continue;
                $key = strtolower($parts[0]);
                if (!isset($settings[$key])) $settings[$key] = strtolower(trim($parts[1]));
            }
            $source = '/etc/ssh/sshd_config (parser parcial)';
        }
    }
    if (!$settings) {
        audit_record($report, 'ssh.configuration', 'access_control', 'skipped', 'info', 'SSH no está instalado o su configuración no es legible', array('source' => $source), 'Si SSH está en uso, permita ejecutar sshd -T al colector de solo lectura.');
        return;
    }
    $rootLogin = isset($settings['permitrootlogin']) ? $settings['permitrootlogin'] : null;
    $passwordAuth = isset($settings['passwordauthentication']) ? $settings['passwordauthentication'] : null;
    $emptyPasswords = isset($settings['permitemptypasswords']) ? $settings['permitemptypasswords'] : null;
    $maxTries = isset($settings['maxauthtries']) ? intval($settings['maxauthtries']) : null;
    $idleInterval = isset($settings['clientaliveinterval']) ? intval($settings['clientaliveinterval']) : null;
    $idleCount = isset($settings['clientalivecountmax']) ? intval($settings['clientalivecountmax']) : null;
    $maxSessions = isset($settings['maxsessions']) ? intval($settings['maxsessions']) : null;
    $loginGraceRaw = isset($settings['logingracetime']) ? $settings['logingracetime'] : null;
    $loginGrace = $loginGraceRaw === null ? null : intval($loginGraceRaw) * (substr($loginGraceRaw, -1) === 'm' ? 60 : (substr($loginGraceRaw, -1) === 'h' ? 3600 : 1));
    audit_record($report, 'ssh.root_login', 'access_control', $rootLogin === 'yes' ? 'fail' : ($rootLogin === null ? 'skipped' : 'pass'), 'critical', $rootLogin === 'yes' ? 'SSH permite acceso directo de root' : 'Acceso SSH directo de root restringido o no verificado', array('value' => $rootLogin, 'source' => $source), 'Use PermitRootLogin no y eleve privilegios mediante identidades nominativas.');
    audit_record($report, 'ssh.password_auth', 'access_control', $passwordAuth === 'yes' ? 'warn' : ($passwordAuth === null ? 'skipped' : 'pass'), 'medium', $passwordAuth === 'yes' ? 'SSH acepta autenticación por contraseña' : 'SSH prioriza claves o el valor no pudo verificarse', array('value' => $passwordAuth, 'source' => $source), 'Use claves protegidas y MFA; desactive PasswordAuthentication cuando sea viable.');
    audit_record($report, 'ssh.empty_passwords', 'credentials', $emptyPasswords === 'yes' ? 'fail' : ($emptyPasswords === null ? 'skipped' : 'pass'), 'critical', $emptyPasswords === 'yes' ? 'SSH acepta contraseñas vacías' : 'SSH rechaza contraseñas vacías o no fue verificable', array('value' => $emptyPasswords, 'source' => $source), 'Configure PermitEmptyPasswords no.');
    audit_record($report, 'ssh.max_auth_tries', 'access_control', ($maxTries !== null && $maxTries > 4) ? 'warn' : ($maxTries === null ? 'skipped' : 'pass'), 'medium', ($maxTries !== null && $maxTries > 4) ? 'SSH permite demasiados intentos por conexión' : 'El límite de intentos SSH es razonable o no verificable', array('value' => $maxTries, 'source' => $source), 'Configure MaxAuthTries entre 3 y 4 según la operación.');
    audit_record($report, 'ssh.login_grace_time', 'access_control', ($loginGrace !== null && $loginGrace > 60) ? 'warn' : ($loginGrace === null ? 'skipped' : 'pass'), 'low', ($loginGrace !== null && $loginGrace > 60) ? 'SSH mantiene autenticaciones incompletas durante demasiado tiempo' : 'LoginGraceTime es acotado o no verificable', array('seconds' => $loginGrace, 'source' => $source), 'Reduzca LoginGraceTime a 60 segundos o menos.');
    audit_record($report, 'ssh.max_sessions', 'access_control', ($maxSessions !== null && $maxSessions > 10) ? 'warn' : ($maxSessions === null ? 'skipped' : 'pass'), 'medium', ($maxSessions !== null && $maxSessions > 10) ? 'SSH permite demasiadas sesiones multiplexadas' : 'MaxSessions es razonable o no verificable', array('value' => $maxSessions, 'source' => $source), 'Mantenga MaxSessions en 10 o menos y ajuste MaxStartups para conexiones no autenticadas.');
    $unlimitedIdle = $idleInterval === 0 || ($idleInterval !== null && $idleCount !== null && ($idleInterval * $idleCount) > 3600);
    audit_record($report, 'ssh.idle_timeout', 'access_control', $unlimitedIdle ? 'warn' : (($idleInterval === null || $idleCount === null) ? 'skipped' : 'pass'), 'medium', $unlimitedIdle ? 'Las sesiones SSH no tienen un cierre por inactividad efectivo' : 'SSH tiene un límite de inactividad o no fue verificable', array('client_alive_interval' => $idleInterval, 'client_alive_count_max' => $idleCount, 'source' => $source), 'Defina ClientAliveInterval y ClientAliveCountMax para cerrar sesiones abandonadas.');
    $report['target']['ssh_source'] = $source;
}

function audit_collect_permissions_and_secrets(&$report)
{
    $criticalPaths = array('/etc/passwd', '/etc/shadow', '/etc/group', '/etc/gshadow', '/etc/sudoers', '/etc/ssh/sshd_config', '/etc/crontab', '/usr/local/bin', '/usr/local/sbin');
    $unsafe = array();
    foreach ($criticalPaths as $path) {
        if (!file_exists($path) && !is_link($path)) continue;
        $mode = audit_file_mode($path);
        $owner = @fileowner($path);
        if (is_link($path)) $unsafe[] = array('path' => $path, 'issue' => 'unexpected symbolic link');
        if ($owner !== false && intval($owner) !== 0) $unsafe[] = array('path' => $path, 'owner_uid' => intval($owner), 'issue' => 'unexpected non-root owner');
        if ($mode !== null && ($mode & 0022)) $unsafe[] = array('path' => $path, 'mode' => audit_mode_string($mode), 'issue' => 'writable by group or others');
    }
    $shadowMode = audit_file_mode('/etc/shadow');
    if ($shadowMode !== null && ($shadowMode & 0007)) $unsafe[] = array('path' => '/etc/shadow', 'mode' => audit_mode_string($shadowMode), 'issue' => 'readable/writable by others');
    audit_record($report, 'permissions.critical_paths', 'permissions', $unsafe ? 'fail' : 'pass', 'critical', $unsafe ? 'Rutas sensibles tienen permisos de escritura o lectura inadecuados' : 'Las rutas sensibles superan la verificación básica de modos', array('paths' => $unsafe), 'Retire escritura de grupo/otros y limite shadow a root:shadow según la distribución.');

    $aclIssues = array(); $aclAssessed = false;
    $getfacl = network_find_binary(array('getfacl'));
    if ($getfacl) {
        $existingCriticalPaths = array_values(array_filter($criticalPaths, function ($path) { return file_exists($path) || is_link($path); }));
        if ($existingCriticalPaths) {
            $aclResult = network_run_fixed($getfacl, array_merge(array('-p'), $existingCriticalPaths), 4, 262144);
            $aclAssessed = $aclResult['available'] && ($aclResult['exit_code'] === 0 || trim($aclResult['stdout']) !== '');
            $currentAclPath = null;
            foreach (preg_split('/\R/', $aclResult['stdout']) as $aclLine) {
                if (preg_match('/^# file: (.+)$/', trim($aclLine), $pathMatch)) { $currentAclPath = audit_clean_text($pathMatch[1], 260); continue; }
                $line = trim($aclLine);
                if (!$currentAclPath || !preg_match('/^(user|group|other):([^:]*):([rwx-]{3})(?:\s+#effective:([rwx-]{3}))?$/', $line, $aclMatch)) continue;
                $namedPrincipal = $aclMatch[2] !== '';
                $effectivePermissions = !empty($aclMatch[4]) ? $aclMatch[4] : $aclMatch[3];
                $unexpectedWrite = strpos($effectivePermissions, 'w') !== false && ($namedPrincipal || $aclMatch[1] === 'other');
                if ($unexpectedWrite && count($aclIssues) < 40) $aclIssues[] = array('path' => $currentAclPath, 'entry_type' => $aclMatch[1], 'named_entry' => $namedPrincipal, 'permissions' => $effectivePermissions);
            }
        }
    }
    audit_record($report, 'permissions.critical_acls', 'permissions', !$aclAssessed ? 'skipped' : ($aclIssues ? 'fail' : 'pass'), 'high', !$aclAssessed ? 'ACL extendidas de rutas críticas no verificadas' : ($aclIssues ? 'ACL extendidas conceden escritura inesperada sobre rutas críticas' : 'No se observaron ACL de escritura inesperadas en rutas críticas'), array('issues' => $aclIssues, 'tool' => $getfacl ? 'getfacl' : 'not_available'), 'Retire entradas ACL de escritura no justificadas y verifique el acceso efectivo con getfacl.');

    $persistenceIssues = array();
    $persistenceRoots = array('/etc/cron.d', '/etc/cron.daily', '/etc/cron.hourly', '/etc/systemd/system', '/usr/lib/systemd/system', '/var/spool/cron');
    foreach ($persistenceRoots as $root) {
        if (!is_dir($root) || !is_readable($root)) continue;
        try {
            $entries = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::SELF_FIRST);
            $entries->setMaxDepth(2);
            $seen = 0;
            foreach ($entries as $entry) {
                if (++$seen > 500) break;
                $mode = $entry->getPerms() & 07777;
                if (($mode & 0022) && count($persistenceIssues) < 50) $persistenceIssues[] = array('path' => audit_clean_text($entry->getPathname(), 260), 'mode' => audit_mode_string($mode));
            }
        } catch (Exception $e) { /* fuente parcial */ }
    }
    audit_record($report, 'permissions.persistence_paths', 'permissions', $persistenceIssues ? 'fail' : 'pass', 'high', $persistenceIssues ? 'Cron o unidades de servicio son modificables por grupo/otros' : 'No se detectó escritura amplia en rutas de persistencia revisadas', array('paths' => $persistenceIssues, 'roots' => $persistenceRoots), 'Retire escritura no administrativa de cron, unidades systemd y scripts invocados por ellas.');

    $pathIssues = array();
    foreach (array_unique(explode(PATH_SEPARATOR, getenv('PATH') ?: '')) as $pathDir) {
        if ($pathDir === '' || $pathDir[0] !== DIRECTORY_SEPARATOR || !is_dir($pathDir)) continue;
        $mode = audit_file_mode($pathDir);
        if ($mode !== null && ($mode & 0022)) $pathIssues[] = array('path' => audit_clean_text($pathDir, 220), 'mode' => audit_mode_string($mode));
    }
    audit_record($report, 'permissions.path_directories', 'permissions', $pathIssues ? 'fail' : 'pass', 'high', $pathIssues ? 'PATH contiene directorios modificables por grupo/otros' : 'Los directorios PATH revisados no tienen escritura amplia', array('paths' => $pathIssues), 'Retire directorios escribibles del PATH del proceso web y corrija propietario/modo.');

    $base = ALLOWED_BASE_PATH;
    $started = microtime(true);
    $scanned = 0;
    $truncated = false;
    $worldWritable = array();
    $stickySharedDirectories = array();
    $writableCode = array();
    $sensitiveFiles = array();
    $secretPatterns = array();
    $privateKeys = array();
    $skipDirs = array('.git', 'vendor', 'node_modules', 'proc', 'sys', 'dev', 'run', '.cache');
    try {
        $directory = new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS);
        $filter = new RecursiveCallbackFilterIterator($directory, function ($current) use ($skipDirs) {
            return !($current->isDir() && in_array($current->getFilename(), $skipDirs, true));
        });
        $iterator = new RecursiveIteratorIterator($filter, RecursiveIteratorIterator::SELF_FIRST);
        $iterator->setMaxDepth(6);
        foreach ($iterator as $item) {
            if ($scanned >= AUDIT_SCAN_MAX_FILES || (microtime(true) - $started) >= AUDIT_SCAN_MAX_SECONDS) { $truncated = true; break; }
            $scanned++;
            if ($item->isLink()) continue;
            $path = $item->getPathname();
            $mode = $item->getPerms() & 07777;
            if ($mode & 0002) {
                if ($item->isDir() && ($mode & 01000)) {
                    if (count($stickySharedDirectories) < 30) $stickySharedDirectories[] = array('path' => audit_clean_text($path, 260), 'mode' => audit_mode_string($mode));
                } elseif (count($worldWritable) < 50) {
                    $worldWritable[] = array('path' => audit_clean_text($path, 260), 'mode' => audit_mode_string($mode), 'type' => $item->isDir() ? 'directory' : 'file');
                }
            }
            if (!$item->isFile()) continue;
            $name = $item->getFilename();
            $extension = strtolower(pathinfo($name, PATHINFO_EXTENSION));
            $isExecutableCode = ($mode & 0111) || in_array($extension, array('php', 'phar', 'sh', 'bash', 'py', 'pl', 'rb', 'js'), true);
            if ($isExecutableCode && ($mode & 0022) && count($writableCode) < 50) $writableCode[] = array('path' => audit_clean_text($path, 260), 'mode' => audit_mode_string($mode), 'owner_uid' => intval($item->getOwner()), 'group_gid' => intval($item->getGroup()));
            $isSensitiveName = preg_match('/(^\.env(?:\.|$)|credential|secret|id_rsa|id_dsa|id_ecdsa|id_ed25519|\.p(?:em|12|fx)$|\.key$|config\.(?:php|json|ya?ml|ini)$)/i', $name);
            if ($isSensitiveName && ($mode & 0044) && count($sensitiveFiles) < 50) {
                $sensitiveFiles[] = array('path' => audit_clean_text($path, 260), 'mode' => audit_mode_string($mode));
            }
            $size = $item->getSize();
            $inspect = $size > 0 && $size <= 1048576 && ($isSensitiveName || in_array($extension, array('php', 'env', 'ini', 'conf', 'config', 'json', 'yaml', 'yml', 'xml', 'properties', 'sh'), true));
            if (!$inspect) continue;
            $content = audit_read_file($path, 524288);
            if ($content === false || strpos($content, "\0") !== false) continue;
            if (preg_match('/-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/', $content, $match, PREG_OFFSET_CAPTURE) && count($privateKeys) < 30) {
                $privateKeys[] = array('path' => audit_clean_text($path, 260), 'line' => substr_count(substr($content, 0, $match[0][1]), "\n") + 1, 'mode' => audit_mode_string($mode));
            }
            $matches = array();
            if (preg_match_all('/\b(?:[a-z0-9]+[_-])*(?:password|passwd|api[_-]?key|client[_-]?secret|secret[_-]?key|access[_-]?key(?:[_-]?id)?|access[_-]?token|auth[_-]?token)\b["\']?\s*[=:]\s*["\']?([^\s"\'`,;]{6,})/i', $content, $matches, PREG_SET_ORDER | PREG_OFFSET_CAPTURE)) {
                $foundInFile = 0;
                foreach ($matches as $match) {
                    $candidate = $match[1][0];
                    if (preg_match('/^(?:\$|%|\{|<|getenv|env\(|array\(|isset|function|null|none|false|true|changeme|example|placeholder)/i', $candidate) || preg_match('/^[a-z_][a-z0-9_]*\(/i', $candidate)) continue;
                    if (count($secretPatterns) >= 50 || $foundInFile >= 3) break;
                    $secretPatterns[] = array('path' => audit_clean_text($path, 260), 'line' => substr_count(substr($content, 0, $match[0][1]), "\n") + 1, 'type' => 'asignación sensible', 'mode' => audit_mode_string($mode), 'value_redacted' => true);
                    $foundInFile++;
                }
            }
        }
    } catch (Exception $e) {
        $truncated = true;
    }

    audit_record($report, 'permissions.workspace_world_writable', 'permissions', $worldWritable ? 'fail' : ($truncated ? 'skipped' : 'pass'), 'high', $worldWritable ? 'El alcance administrado contiene rutas escribibles por todos sin protección sticky' : ($truncated ? 'El recorrido no fue suficiente para descartar rutas world-writable' : 'No se detectaron rutas world-writable aprovechables en el alcance recorrido'), array('paths' => $worldWritable, 'sticky_shared_directories' => $stickySharedDirectories, 'scope' => $base, 'scanned_entries' => $scanned, 'scan_truncated' => $truncated), 'Retire el bit de escritura para otros; en directorios compartidos use sticky bit y una justificación explícita.');
    audit_record($report, 'permissions.writable_executable_code', 'permissions', $writableCode ? 'fail' : ($truncated ? 'skipped' : 'pass'), 'critical', $writableCode ? 'Código ejecutable o interpretable puede ser modificado por grupo u otros' : ($truncated ? 'El recorrido no fue suficiente para descartar código modificable' : 'No se detectó código ejecutable con escritura amplia'), array('files' => $writableCode, 'scope' => $base, 'scan_truncated' => $truncated), 'Restrinja el código desplegado a propietario administrativo y modo 0755/0644 o más estricto; separe el usuario de despliegue del usuario web.');
    audit_record($report, 'credentials.sensitive_file_modes', 'credentials', $sensitiveFiles ? 'warn' : ($truncated ? 'skipped' : 'pass'), 'high', $sensitiveFiles ? 'Archivos potencialmente sensibles son legibles por grupo u otros' : ($truncated ? 'El recorrido no fue suficiente para descartar archivos sensibles con permisos amplios' : 'No se hallaron nombres sensibles con permisos amplios'), array('files' => $sensitiveFiles, 'values_exposed' => false, 'scan_truncated' => $truncated), 'Restrinja cada archivo al usuario de servicio, preferiblemente modo 0600/0640 fuera del document root.');
    audit_record($report, 'credentials.literal_secrets', 'credentials', ($secretPatterns || $privateKeys) ? 'fail' : ($truncated ? 'skipped' : 'pass'), 'critical', ($secretPatterns || $privateKeys) ? 'Se detectaron posibles secretos o claves privadas en archivos legibles' : ($truncated ? 'El recorrido no fue suficiente para descartar secretos literales' : 'No se detectaron secretos literales en el alcance analizado'), array('assignments' => $secretPatterns, 'private_keys' => $privateKeys, 'values_redacted' => true, 'scope' => $base, 'scan_truncated' => $truncated), 'Rote el secreto, muévalo a un gestor de secretos y retire copias, backups e historiales.');
    audit_record($report, 'credentials.public_breach_lookup', 'credentials', 'skipped', 'info', 'Filtraciones públicas de contraseñas no evaluadas', array('reason' => 'No hay contraseña en texto claro y el panel no transmite hashes ni secretos.'), 'Use una comprobación k-anónima opt-in sobre una contraseña proporcionada voluntariamente; nunca intente romper /etc/shadow.');
    $report['coverage_notes'][] = $truncated ? 'El recorrido de archivos alcanzó el límite de tiempo o cantidad.' : 'El recorrido de archivos terminó dentro de los límites.';
    $report['inventory']['filesystem_scan'] = array('scope' => $base, 'entries' => $scanned, 'truncated' => $truncated);

    $suid = command_exists('find') ? audit_command_lines("find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -xdev -type f \\( -perm -4000 -o -perm -2000 \\) -printf '%p|%m|%u\\n' | head -100", 100) : array();
    $report['inventory']['suid_sgid_files'] = $suid;
    audit_record($report, 'permissions.suid_inventory', 'permissions', $suid ? 'pass' : 'skipped', 'info', $suid ? count($suid) . ' binario(s) SUID/SGID inventariados' : 'Inventario SUID/SGID no disponible', array('count' => count($suid)), 'Compare este inventario con una línea base de la distribución y retire bits innecesarios.');
    $riskyPrivilegeBinaries = array(); $customPrivilegeBinaries = array();
    $interpreterNames = array('bash', 'sh', 'dash', 'zsh', 'ksh', 'python', 'python2', 'python3', 'perl', 'ruby', 'php', 'node', 'lua', 'vim', 'nvim', 'less', 'more', 'find', 'awk', 'gawk');
    foreach ($suid as $entry) {
        $parts = explode('|', $entry, 3);
        if (count($parts) !== 3 || !preg_match('/^[0-7]{3,4}$/D', $parts[1])) continue;
        $mode = octdec($parts[1]); $path = $parts[0]; $name = strtolower(basename($path)); $reasons = array();
        if ($mode & 0022) $reasons[] = 'binary writable by group or others';
        if (($mode & 04000) && $parts[2] === 'root' && in_array($name, $interpreterNames, true)) $reasons[] = 'root SUID interpreter or utility with command execution capability';
        if ($reasons) $riskyPrivilegeBinaries[] = array('path' => audit_clean_text($path, 260), 'mode' => $parts[1], 'owner' => audit_clean_text($parts[2], 80), 'reasons' => $reasons);
        elseif (strpos($path, '/usr/local/') === 0) $customPrivilegeBinaries[] = array('path' => audit_clean_text($path, 260), 'mode' => $parts[1], 'owner' => audit_clean_text($parts[2], 80));
    }
    $suidRiskStatus = $riskyPrivilegeBinaries ? 'fail' : ($customPrivilegeBinaries ? 'warn' : ($suid ? 'pass' : 'skipped'));
    audit_record($report, 'permissions.suid_risky', 'permissions', $suidRiskStatus, 'high', $riskyPrivilegeBinaries ? 'Se detectaron binarios privilegiados con una ruta de abuso probable' : ($customPrivilegeBinaries ? 'Hay binarios SUID/SGID personalizados que requieren revisión' : ($suid ? 'No se detectaron patrones SUID/SGID de alto riesgo en el alcance' : 'Riesgo SUID/SGID no verificado')), array('risky' => $riskyPrivilegeBinaries, 'custom' => $customPrivilegeBinaries, 'baseline_comparison' => false), 'Retire SUID/SGID innecesario, corrija escritura y compare cada binario con el paquete o baseline firmado de la distribución.');

    $capabilityLines = command_exists('getcap') ? audit_command_lines('getcap -r /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin 2>/dev/null | head -100', 100) : array();
    $dangerousCapabilities = array(); $reviewCapabilities = array(); $otherCapabilities = array();
    foreach ($capabilityLines as $entry) {
        $row = audit_clean_text($entry, 420);
        if (preg_match('/cap_(?:setuid|setgid|dac_override|dac_read_search|sys_admin|sys_ptrace|sys_module|chown)[+,=]/i', $row)) $dangerousCapabilities[] = $row;
        elseif (strpos($row, '/usr/local/') === 0) $reviewCapabilities[] = $row;
        else $otherCapabilities[] = $row;
    }
    $capabilityStatus = !command_exists('getcap') ? 'skipped' : ($dangerousCapabilities ? 'fail' : ($reviewCapabilities ? 'warn' : 'pass'));
    audit_record($report, 'permissions.file_capabilities', 'permissions', $capabilityStatus, 'high', !command_exists('getcap') ? 'Linux file capabilities no verificadas' : ($dangerousCapabilities ? 'Hay binarios con capacidades Linux de elevación o evasión de permisos' : ($reviewCapabilities ? 'Hay capacidades Linux personalizadas que requieren comparación con baseline' : 'No se detectaron file capabilities de alto riesgo en los directorios revisados')), array('dangerous' => array_slice($dangerousCapabilities, 0, 40), 'custom_review' => array_slice($reviewCapabilities, 0, 40), 'other_inventory' => array_slice($otherCapabilities, 0, 40), 'scope' => array('/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin')), 'Retire capacidades innecesarias con setcap -r y valide las restantes contra el paquete oficial y el principio de mínimo privilegio.');
}

function audit_collect_network(&$report)
{
    $networkMap = null;
    $networkInventorySkipReason = null;
    $networkAuditDiscoveryLock = null;
    $networkInventoryLockAcquired = false;
    if (!PANEL_STORAGE_READY || is_link(NETWORK_DISCOVERY_LOCK)) {
        $networkInventorySkipReason = 'discovery_lock_unavailable';
    } else {
        $networkAuditDiscoveryLock = @fopen(NETWORK_DISCOVERY_LOCK, 'c+');
        if (!$networkAuditDiscoveryLock) {
            $networkInventorySkipReason = 'discovery_lock_unavailable';
        } elseif (!@flock($networkAuditDiscoveryLock, LOCK_SH | LOCK_NB)) {
            @fclose($networkAuditDiscoveryLock);
            $networkAuditDiscoveryLock = null;
            $networkInventorySkipReason = 'active_discovery_in_progress';
        } else {
            @chmod(NETWORK_DISCOVERY_LOCK, 0600);
            $networkInventoryLockAcquired = true;
            try {
                $networkMap = collectNetworkMap(false);
                if (!$networkMap) $networkInventorySkipReason = 'collector_unavailable';
            } catch (Throwable $networkInventoryError) {
                $networkMap = null;
                $networkInventorySkipReason = 'collector_error';
            } finally {
                @flock($networkAuditDiscoveryLock, LOCK_UN);
                @fclose($networkAuditDiscoveryLock);
                $networkAuditDiscoveryLock = null;
            }
        }
    }

    $sourceStatus = function ($sourceId) use (&$networkMap) {
        if (!$networkMap || empty($networkMap['sources']) || !is_array($networkMap['sources'])) return 'missing';
        $rank = array('ok' => 0, 'partial' => 1, 'missing' => 2, 'denied' => 2, 'error' => 2);
        $found = false;
        $worst = 0;
        foreach ($networkMap['sources'] as $source) {
            if (!is_array($source) || !isset($source['id']) || $source['id'] !== $sourceId) continue;
            $found = true;
            $status = isset($source['status']) && isset($rank[$source['status']]) ? $source['status'] : 'partial';
            $worst = max($worst, $rank[$status]);
        }
        if (!$found) return 'missing';
        return $worst === 0 ? 'ok' : ($worst === 1 ? 'partial' : 'missing');
    };

    $ipv4Forwarding = null;
    $ipv6Forwarding = null;
    $readKernelSwitch = function ($path) {
        if (!is_file($path) || !is_readable($path)) return null;
        $value = @file_get_contents($path, false, null, 0, 32);
        if ($value === false) return null;
        $value = trim($value);
        if ($value === '0') return false;
        if ($value === '1') return true;
        return null;
    };
    $ipv4Forwarding = $readKernelSwitch('/proc/sys/net/ipv4/ip_forward');
    $ipv6Forwarding = $readKernelSwitch('/proc/sys/net/ipv6/conf/all/forwarding');

    if ($networkMap) {
        $eligibleNetworks = array_map(function ($scope) {
            return array(
                'cidr' => isset($scope['cidr']) ? audit_clean_text($scope['cidr'], 64) : null,
                'interface' => isset($scope['interface']) ? audit_clean_text($scope['interface'], 64) : null,
                'ifindex' => isset($scope['ifindex']) ? max(0, intval($scope['ifindex'])) : 0,
                'candidate_count' => isset($scope['candidate_count']) ? max(0, intval($scope['candidate_count'])) : 0,
                'sampled' => !empty($scope['sampled']),
                'active_allowed' => !empty($scope['active_allowed'])
            );
        }, isset($networkMap['eligible_networks']) && is_array($networkMap['eligible_networks']) ? array_slice($networkMap['eligible_networks'], 0, 64) : array());
        $report['inventory']['network'] = array(
            'namespace' => $networkMap['namespace'],
            'summary' => $networkMap['summary'],
            'interfaces' => $networkMap['interfaces'],
            'routes' => $networkMap['routes'],
            'rules' => isset($networkMap['rules']) && is_array($networkMap['rules']) ? $networkMap['rules'] : array(),
            'neighbors' => $networkMap['neighbors'],
            'eligible_networks' => $eligibleNetworks
        );
        $usableInterfaces = array_values(array_filter($networkMap['interfaces'], function ($interface) { return $interface['name'] !== 'lo'; }));
        $interfaceCoverage = $sourceStatus('interfaces');
        $routeCoverage = $sourceStatus('routes');
        $ruleCoverage = $sourceStatus('routing_rules');
        $neighborCoverage = $sourceStatus('neighbors');
        $duplicateAddresses = array();
        $addressOwners = array();
        $dadFailed = array();
        $tentativeAddresses = array();
        $deprecatedAddresses = array();
        foreach ($usableInterfaces as $interface) {
            foreach ($interface['addresses'] as $address) {
                $addressItem = array('interface' => $interface['name'], 'address' => $address['address']);
                $failedDad = !empty($address['dad_failed']);
                if ($failedDad) {
                    if (count($dadFailed) < 64) $dadFailed[] = $addressItem;
                } else {
                    if (!empty($address['tentative']) && count($tentativeAddresses) < 64) $tentativeAddresses[] = $addressItem;
                    if (!empty($address['deprecated']) && count($deprecatedAddresses) < 64) $deprecatedAddresses[] = $addressItem;
                }

                // Las direcciones link-local pertenecen a un scope de interfaz; repetirlas
                // en enlaces distintos no constituye por sí mismo un conflicto.
                if (isset($address['scope']) && $address['scope'] === 'link_local') continue;
                $key = $address['family'] . '|' . $address['address'];
                if (isset($addressOwners[$key]) && $addressOwners[$key] !== $interface['name']) $duplicateAddresses[] = array('address' => $address['address'], 'interfaces' => array($addressOwners[$key], $interface['name']));
                $addressOwners[$key] = $interface['name'];
            }
        }
        $promiscuous = array();
        foreach ($usableInterfaces as $interface) {
            if (empty($interface['promiscuity'])) continue;
            $promiscuous[] = array('interface' => $interface['name'], 'kind' => $interface['kind'], 'promiscuity' => max(0, intval($interface['promiscuity'])));
        }
        $addressStateCoverage = $interfaceCoverage;
        $promiscuityCoverage = $interfaceCoverage;

        $defaultRouteGroupsByKey = array();
        foreach ($networkMap['routes'] as $route) {
            if (!isset($route['destination']) || $route['destination'] !== 'default') continue;
            $family = isset($route['family']) ? $route['family'] : 'unknown';
            $table = isset($route['table']) ? $route['table'] : 'main';
            $groupKey = $family . '|' . $table;
            if (!isset($defaultRouteGroupsByKey[$groupKey])) $defaultRouteGroupsByKey[$groupKey] = array('family' => $family, 'table' => $table, 'count' => 0, 'routes' => array());
            $defaultRouteGroupsByKey[$groupKey]['count']++;
            if (count($defaultRouteGroupsByKey[$groupKey]['routes']) < 24) $defaultRouteGroupsByKey[$groupKey]['routes'][] = $route;
        }
        $defaultRouteGroups = array_values($defaultRouteGroupsByKey);
        $parallelDefaultGroups = array_values(array_filter($defaultRouteGroups, function ($group) { return $group['count'] > 1; }));

        $routingRules = isset($networkMap['rules']) && is_array($networkMap['rules']) ? $networkMap['rules'] : array();
        $policyRoutingRules = array();
        $policyRoutingRuleCount = 0;
        foreach ($routingRules as $rule) {
            $priority = isset($rule['priority']) ? intval($rule['priority']) : null;
            $table = isset($rule['table']) ? strtolower((string)$rule['table']) : '';
            $fromAll = !isset($rule['from']) || strtolower((string)$rule['from']) === 'all';
            $toAll = !isset($rule['to']) || strtolower((string)$rule['to']) === 'all';
            $plainSelector = $fromAll && $toAll && empty($rule['fwmark']) && empty($rule['iif']) && empty($rule['oif']);
            $action = isset($rule['action']) ? strtolower((string)$rule['action']) : 'lookup';
            $builtInLookup = $plainSelector && $action === 'lookup' && (($table === 'local' && $priority === 0) || ($table === 'main' && $priority === 32766) || ($table === 'default' && $priority === 32767));
            if (!$builtInLookup) {
                $policyRoutingRuleCount++;
                if (count($policyRoutingRules) < 80) $policyRoutingRules[] = $rule;
            }
        }
        $badNeighbors = array_values(array_filter($networkMap['neighbors'], function ($neighbor) { return strpos($neighbor['state'], 'failed') !== false || strpos($neighbor['state'], 'incomplete') !== false; }));
        $inventoryStatus = $usableInterfaces && $interfaceCoverage === 'ok' ? 'pass' : 'skipped';
        audit_record($report, 'network.interface_inventory', 'network', $inventoryStatus, 'info', $inventoryStatus === 'pass' ? count($usableInterfaces) . ' interfaz(es) de red inventariada(s)' : 'El inventario de interfaces es parcial o no está disponible', array('interfaces' => array_map(function ($interface) { return array('name' => $interface['name'], 'kind' => $interface['kind'], 'state' => $interface['state'], 'addresses' => count($interface['addresses'])); }, $usableInterfaces), 'namespace' => $networkMap['namespace'], 'source_status' => $interfaceCoverage), 'Revise que cada interfaz y dirección corresponda al diseño de red aprobado.');

        $duplicateStatus = $duplicateAddresses ? 'fail' : ($interfaceCoverage === 'ok' ? 'pass' : 'skipped');
        audit_record($report, 'network.duplicate_local_addresses', 'network', $duplicateStatus, 'high', $duplicateAddresses ? 'Una dirección no link-local aparece en varias interfaces' : ($duplicateStatus === 'pass' ? 'No se observaron direcciones globales duplicadas entre interfaces' : 'No se pudo descartar una dirección duplicada con cobertura suficiente'), array('duplicates' => $duplicateAddresses, 'link_local_excluded' => true, 'source_status' => $interfaceCoverage), 'Elimine direcciones duplicadas o documente explícitamente configuraciones anycast, VRF o HA.', $interfaceCoverage === 'ok' ? 'high' : 'medium');

        $dadStatus = $dadFailed ? 'fail' : ($addressStateCoverage === 'ok' ? 'pass' : 'skipped');
        audit_record($report, 'network.address_dad_failed', 'network', $dadStatus, 'high', $dadFailed ? 'Duplicate Address Detection reportó direcciones en conflicto' : ($dadStatus === 'pass' ? 'No se observaron direcciones con DADFAILED' : 'DADFAILED no pudo verificarse'), array('addresses' => $dadFailed, 'source_status' => $addressStateCoverage), 'Investigue el conflicto antes de mantener la dirección activa; revise anuncios, clones y configuración estática.', $addressStateCoverage === 'ok' ? 'high' : 'low');

        $transitionalAddresses = array('tentative' => $tentativeAddresses, 'deprecated' => $deprecatedAddresses);
        $transitionalFound = !empty($tentativeAddresses) || !empty($deprecatedAddresses);
        $transitionalStatus = $transitionalFound ? 'warn' : ($addressStateCoverage === 'ok' ? 'pass' : 'skipped');
        audit_record($report, 'network.address_transitional_state', 'network', $transitionalStatus, 'low', $transitionalFound ? 'Hay direcciones tentativas o deprecadas que requieren contexto temporal' : ($transitionalStatus === 'pass' ? 'No se observaron direcciones tentativas o deprecadas' : 'Los estados transitorios de direcciones no pudieron verificarse'), array('addresses' => $transitionalAddresses, 'dadfailed_separate' => true, 'source_status' => $addressStateCoverage), 'Confirme que estados tentative/deprecated desaparezcan tras DAD o la rotación normal de SLAAC; no los trate por sí solos como intrusión.', $addressStateCoverage === 'ok' ? 'medium' : 'low');

        $promiscuousStatus = $promiscuous ? 'warn' : ($promiscuityCoverage === 'ok' ? 'pass' : 'skipped');
        audit_record($report, 'network.promiscuous_interfaces', 'network', $promiscuousStatus, 'medium', $promiscuous ? 'Hay interfaces con contador promiscuity activo' : ($promiscuousStatus === 'pass' ? 'No se detectaron interfaces en modo promiscuo' : 'El modo promiscuo no pudo verificarse en todas las interfaces'), array('interfaces' => $promiscuous, 'source_status' => $promiscuityCoverage, 'context_required' => true), 'Confirme que el modo promiscuo sea necesario para bridge, captura o monitorización y limite quién puede activarlo.', $promiscuityCoverage === 'ok' ? 'high' : 'medium');

        $defaultStatus = $parallelDefaultGroups ? 'warn' : ($routeCoverage === 'ok' ? 'pass' : 'skipped');
        audit_record($report, 'network.default_routes', 'network', $defaultStatus, 'low', $parallelDefaultGroups ? 'Hay rutas por defecto paralelas dentro de una misma familia y tabla' : ($defaultStatus === 'pass' ? count($defaultRouteGroups) . ' contexto(s) familia/tabla con ruta por defecto inventariados' : 'Las rutas por defecto no pudieron verificarse completamente'), array('groups' => array_slice($defaultRouteGroups, 0, 32), 'parallel_groups' => array_slice($parallelDefaultGroups, 0, 16), 'grouping' => 'family+table', 'source_status' => $routeCoverage), 'Revise métricas, ECMP y failover dentro de cada tabla; rutas en tablas distintas deben interpretarse junto con las reglas de policy routing.', $routeCoverage === 'ok' ? 'medium' : 'low');

        $policyRoutingStatus = $policyRoutingRules ? 'warn' : ($ruleCoverage === 'ok' ? 'pass' : 'skipped');
        audit_record($report, 'network.policy_routing', 'network', $policyRoutingStatus, 'low', $policyRoutingRules ? $policyRoutingRuleCount . ' regla(s) de policy routing no predeterminada(s) requieren contexto' : ($policyRoutingStatus === 'pass' ? 'Solo se observaron reglas de routing predeterminadas' : 'Policy routing no pudo verificarse con cobertura completa'), array('rules' => $policyRoutingRules, 'custom_rule_count' => $policyRoutingRuleCount, 'sample_truncated' => $policyRoutingRuleCount > count($policyRoutingRules), 'total_rules' => count($routingRules), 'source_status' => $ruleCoverage, 'built_in_rules_excluded' => true), 'Documente selectores, marcas, interfaces y tablas personalizadas; confirme que no eludan segmentación, VPN o controles de egreso.', $ruleCoverage === 'ok' ? 'medium' : 'low');

        $neighborStatus = count($badNeighbors) > 10 ? 'warn' : ($neighborCoverage === 'ok' ? 'pass' : 'skipped');
        audit_record($report, 'network.neighbor_health', 'network', $neighborStatus, 'low', count($badNeighbors) > 10 ? count($badNeighbors) . ' vecinos fallidos o incompletos requieren revisión' : ($neighborStatus === 'pass' ? count($badNeighbors) . ' vecino(s) en estado fallido o incompleto' : 'La salud de vecinos no pudo verificarse con cobertura completa'), array('count' => count($badNeighbors), 'sample' => array_slice($badNeighbors, 0, 20), 'source_status' => $neighborCoverage), 'Investigue una acumulación persistente; STALE por sí solo no se considera una vulnerabilidad.', $neighborCoverage === 'ok' ? 'medium' : 'low');

        $allowedNetworks = network_configured_allowed_cidrs();
        $discoveryMisconfigured = ENABLE_NETWORK_DISCOVERY && !$allowedNetworks;
        audit_record($report, 'network.discovery_policy', 'network', $discoveryMisconfigured ? 'fail' : 'pass', 'high', $discoveryMisconfigured ? 'El descubrimiento activo está habilitado sin una allowlist válida' : (ENABLE_NETWORK_DISCOVERY ? 'El descubrimiento activo está acotado por allowlist y presupuesto' : 'El descubrimiento activo está deshabilitado por defecto'), array('enabled' => ENABLE_NETWORK_DISCOVERY, 'allowlisted_networks' => count($allowedNetworks), 'max_hosts' => NETWORK_DISCOVERY_MAX_HOSTS, 'deadline_seconds' => NETWORK_DISCOVERY_TIMEOUT, 'client_supplied_targets' => false), 'Mantenga PANEL_ENABLE_NETWORK_DISCOVERY=0 o configure únicamente CIDR privados y conectados en PANEL_NETWORK_ALLOWED_CIDRS.');
    } else {
        audit_record($report, 'network.interface_inventory', 'network', 'skipped', 'info', $networkInventorySkipReason === 'active_discovery_in_progress' ? 'Inventario omitido mientras hay un descubrimiento activo' : 'Inventario de interfaces, rutas y vecinos no disponible', array('reason' => $networkInventorySkipReason ?: 'collector_unavailable', 'shared_lock_acquired' => $networkInventoryLockAcquired), 'Reintente tras finalizar el descubrimiento; si persiste, revise el almacenamiento privado y el acceso de solo lectura a /sys y /proc.');
    }

    $listeners = array();
    $risky = array();
    $wildcard = array();
    $riskPorts = array(21 => 'FTP', 23 => 'Telnet', 111 => 'RPC', 2049 => 'NFS', 2375 => 'Docker API', 3306 => 'MySQL', 5432 => 'PostgreSQL', 6379 => 'Redis', 9200 => 'Elasticsearch', 11211 => 'Memcached', 27017 => 'MongoDB');
    $socketOutput = '';
    $listenerCoverage = 'missing';
    $ssBinary = network_find_binary(array('ss'));
    if ($ssBinary) {
        $socketResponse = network_run_fixed($ssBinary, array('-H', '-lntup'), 5, 1048576);
        $socketOutput = $socketResponse['stdout'];
        if ($socketResponse['available'] && $socketResponse['exit_code'] === 0 && !$socketResponse['timed_out'] && !$socketResponse['truncated']) $listenerCoverage = 'ok';
        elseif ($socketOutput !== '') $listenerCoverage = 'partial';
    }
    if ($socketOutput !== '' || $listenerCoverage === 'ok') {
        foreach (preg_split('/\R/', $socketOutput) as $line) {
            $parts = preg_split('/\s+/', trim($line), 7);
            if (count($parts) < 5) continue;
            $local = audit_clean_text($parts[4], 180);
            $process = isset($parts[6]) ? audit_clean_text($parts[6], 220) : '';
            $port = null;
            if (preg_match('/:(\d+)$/', $local, $match)) $port = intval($match[1]);
            $isWildcard = strpos($local, '0.0.0.0:') === 0 || strpos($local, '*:') === 0 || strpos($local, '[::]:') === 0 || strpos($local, ':::') === 0;
            $row = array('protocol' => audit_clean_text($parts[0], 12), 'local' => $local, 'port' => $port, 'wildcard' => $isWildcard, 'process' => $process);
            $listeners[] = $row;
            if ($isWildcard) $wildcard[] = $local;
            if ($isWildcard && isset($riskPorts[$port])) $risky[] = array('service' => $riskPorts[$port], 'endpoint' => $local, 'process' => $process);
        }
        $riskyListenerStatus = $risky ? 'fail' : ($listenerCoverage === 'ok' ? 'pass' : 'skipped');
        $wildcardStatus = count($wildcard) > 8 ? 'warn' : ($listenerCoverage === 'ok' ? 'pass' : 'skipped');
        audit_record($report, 'network.risky_listeners', 'network', $riskyListenerStatus, 'high', $risky ? 'Servicios sensibles escuchan en todas las interfaces' : ($riskyListenerStatus === 'pass' ? 'No se observaron puertos sensibles en bind global' : 'La fuente parcial no permite descartar listeners sensibles'), array('listeners' => $risky, 'source_status' => $listenerCoverage, 'reachability_confirmed' => false), 'Limite el bind a loopback/red privada y aplique firewall; confirme alcance desde otra zona.');
        audit_record($report, 'network.wildcard_listeners', 'network', $wildcardStatus, 'low', $wildcardStatus === 'skipped' ? 'La fuente parcial no permite completar el inventario de listeners wildcard' : count($wildcard) . ' listener(s) en direcciones wildcard', array('endpoints' => array_slice($wildcard, 0, 40), 'source_status' => $listenerCoverage, 'reachability_confirmed' => false), 'Revise necesidad, autenticación y segmentación de cada listener.');
    } else {
        audit_record($report, 'network.listeners', 'network', 'skipped', 'info', 'No se pudo inventariar sockets de escucha', array('tool' => 'ss', 'source_status' => $listenerCoverage), 'Instale iproute2 o habilite un colector equivalente de solo lectura.');
    }
    $report['inventory']['listeners'] = $listeners;

    // Una herramienta instalada o un daemon activo no prueban filtrado. Solo una
    // política base restrictiva (o una zona firewalld no-ACCEPT) cuenta como evidencia.
    $firewallEvidence = array();
    $firewallCoverageIssues = array();
    $policyEvidence = array(
        'ipv4' => array('input' => array(), 'forward' => array()),
        'ipv6' => array('input' => array(), 'forward' => array())
    );
    $recordPolicy = function ($backend, $family, $hook, $restrictive, $detail) use (&$policyEvidence, &$firewallEvidence) {
        if (!isset($policyEvidence[$family]) || !isset($policyEvidence[$family][$hook])) return;
        $policyEvidence[$family][$hook][] = array('backend' => $backend, 'restrictive' => $restrictive, 'detail' => audit_clean_text($detail, 180));
        if (!isset($firewallEvidence[$backend])) $firewallEvidence[$backend] = array();
    };

    $firewallCmd = network_find_binary(array('firewall-cmd'));
    if ($firewallCmd) {
        $stateResponse = network_run_fixed($firewallCmd, array('--state'), 4, 65536);
        $state = strtolower(trim($stateResponse['stdout']));
        $firewallEvidence['firewalld'] = array('state' => $state ?: 'unreadable', 'zones' => array());
        if ($state === 'running') {
            if (!$stateResponse['available'] || $stateResponse['exit_code'] !== 0 || $stateResponse['timed_out'] || $stateResponse['truncated']) $firewallCoverageIssues[] = 'firewalld_state_partial';
            $zones = array();
            $defaultResponse = network_run_fixed($firewallCmd, array('--get-default-zone'), 4, 65536);
            $defaultZone = trim($defaultResponse['stdout']);
            if ($defaultResponse['exit_code'] === 0 && !$defaultResponse['timed_out'] && !$defaultResponse['truncated'] && preg_match('/^[a-zA-Z0-9_-]{1,64}$/D', $defaultZone)) $zones[$defaultZone] = true;
            else $firewallCoverageIssues[] = 'firewalld_default_zone_unreadable';
            $activeResponse = network_run_fixed($firewallCmd, array('--get-active-zones'), 4, 131072);
            if ($activeResponse['exit_code'] === 0 && !$activeResponse['timed_out'] && !$activeResponse['truncated']) {
                foreach (preg_split('/\R/', $activeResponse['stdout']) as $line) {
                    $line = trim($line);
                    if (preg_match('/^([a-zA-Z0-9_-]{1,64})(?:\s+\(active\))?$/D', $line, $zoneMatch)) $zones[$zoneMatch[1]] = true;
                }
            } else {
                $firewallCoverageIssues[] = 'firewalld_active_zones_partial';
            }
            if (count($zones) > 32) $firewallCoverageIssues[] = 'firewalld_zone_limit_reached';
            foreach (array_slice(array_keys($zones), 0, 32) as $zone) {
                $targetResponse = network_run_fixed($firewallCmd, array('--zone=' . $zone, '--get-target'), 4, 65536);
                $target = strtoupper(trim($targetResponse['stdout']));
                if ($targetResponse['exit_code'] !== 0 || $targetResponse['timed_out'] || $targetResponse['truncated'] || !in_array($target, array('DEFAULT', 'ACCEPT', 'DROP', 'REJECT'), true)) {
                    $firewallCoverageIssues[] = 'firewalld_zone_target_partial:' . $zone;
                    continue;
                }
                $inputRestrictive = $target !== 'ACCEPT';
                $forwardResponse = network_run_fixed($firewallCmd, array('--zone=' . $zone, '--query-forward'), 4, 65536);
                $forwardAnswer = strtolower(trim($forwardResponse['stdout']));
                if ($forwardResponse['timed_out'] || $forwardResponse['truncated'] || !in_array($forwardAnswer, array('yes', 'no'), true)) $firewallCoverageIssues[] = 'firewalld_zone_forward_partial:' . $zone;
                $forwardRestrictive = $target === 'ACCEPT' ? false : ($forwardAnswer === 'no' ? true : ($forwardAnswer === 'yes' ? false : null));
                $firewallEvidence['firewalld']['zones'][] = array('zone' => $zone, 'target' => strtolower($target), 'intra_zone_forward' => $forwardAnswer ?: 'unknown');
                foreach (array('ipv4', 'ipv6') as $family) {
                    $recordPolicy('firewalld', $family, 'input', $inputRestrictive, $zone . ' target=' . strtolower($target));
                    $recordPolicy('firewalld', $family, 'forward', $forwardRestrictive, $zone . ' target=' . strtolower($target) . ', forward=' . ($forwardAnswer ?: 'unknown'));
                }
            }
        }
    }

    $ufw = network_find_binary(array('ufw'));
    if ($ufw) {
        $ufwResponse = network_run_fixed($ufw, array('status', 'verbose'), 5, 262144);
        $ufwOutput = $ufwResponse['stdout'] . "\n" . $ufwResponse['stderr'];
        $ufwActive = preg_match('/^Status:\s*active\s*$/mi', $ufwOutput) === 1;
        $firewallEvidence['ufw'] = array('state' => $ufwActive ? 'active' : 'inactive_or_unreadable', 'default' => 'unknown');
        $ufwDefaultsReadable = preg_match('/^Default:\s*([a-z]+)\s*\(incoming\).*?([a-z]+)\s*\(routed\)/mi', $ufwOutput, $ufwMatch) === 1;
        if ($ufwActive && ($ufwResponse['exit_code'] !== 0 || $ufwResponse['timed_out'] || $ufwResponse['truncated'] || !$ufwDefaultsReadable)) $firewallCoverageIssues[] = 'ufw_active_policy_partial';
        if ($ufwActive && $ufwDefaultsReadable) {
            $incoming = strtolower($ufwMatch[1]);
            $routed = strtolower($ufwMatch[2]);
            $firewallEvidence['ufw']['default'] = array('incoming' => $incoming, 'routed' => $routed);
            $ufwIpv6 = null;
            $ufwConfig = @file_get_contents('/etc/default/ufw', false, null, 0, 131072);
            if (is_string($ufwConfig) && preg_match('/^\s*IPV6\s*=\s*(yes|no)\s*$/mi', $ufwConfig, $ufwIpv6Match)) $ufwIpv6 = strtolower($ufwIpv6Match[1]) === 'yes';
            $families = $ufwIpv6 === true ? array('ipv4', 'ipv6') : array('ipv4');
            foreach ($families as $family) {
                $recordPolicy('ufw', $family, 'input', in_array($incoming, array('deny', 'reject'), true) ? true : ($incoming === 'allow' ? false : null), 'default incoming=' . $incoming);
                $recordPolicy('ufw', $family, 'forward', in_array($routed, array('deny', 'reject', 'disabled'), true) ? true : ($routed === 'allow' ? false : null), 'default routed=' . $routed);
            }
        }
    }

    $nft = network_find_binary(array('nft'));
    if ($nft) {
        $nftResponse = network_run_fixed($nft, array('-j', 'list', 'ruleset'), 6, 1048576);
        $nftJson = json_decode($nftResponse['stdout'], true);
        $nftReadable = $nftResponse['available'] && $nftResponse['exit_code'] === 0 && !$nftResponse['timed_out'] && !$nftResponse['truncated'] && is_array($nftJson) && isset($nftJson['nftables']) && is_array($nftJson['nftables']) && count($nftJson['nftables']) <= 4096;
        $firewallEvidence['nftables'] = array('state' => $nftReadable ? 'readable' : (($nftResponse['timed_out'] || $nftResponse['truncated'] || (is_array($nftJson) && isset($nftJson['nftables']) && is_array($nftJson['nftables']) && count($nftJson['nftables']) > 4096)) ? 'partial' : 'unreadable'), 'base_chains' => array());
        if ($nftReadable) {
            foreach (array_slice($nftJson['nftables'], 0, 4096) as $entry) {
                if (!isset($entry['chain']) || !is_array($entry['chain'])) continue;
                $chain = $entry['chain'];
                $hook = isset($chain['hook']) ? strtolower((string)$chain['hook']) : '';
                if (!in_array($hook, array('input', 'forward'), true)) continue;
                $nftFamily = isset($chain['family']) ? strtolower((string)$chain['family']) : '';
                $families = $nftFamily === 'inet' ? array('ipv4', 'ipv6') : ($nftFamily === 'ip' ? array('ipv4') : ($nftFamily === 'ip6' ? array('ipv6') : array()));
                if (!$families) continue;
                $policy = isset($chain['policy']) ? strtolower((string)$chain['policy']) : 'unknown';
                $chainName = isset($chain['name']) ? audit_clean_text($chain['name'], 80) : 'unnamed';
                $firewallEvidence['nftables']['base_chains'][] = array('family' => $nftFamily, 'hook' => $hook, 'chain' => $chainName, 'policy' => $policy);
                foreach ($families as $family) $recordPolicy('nftables', $family, $hook, $policy === 'drop' ? true : null, $nftFamily . '/' . $chainName . ' policy=' . $policy);
            }
        }
    }

    foreach (array('ipv4' => 'iptables', 'ipv6' => 'ip6tables') as $family => $binaryName) {
        $binary = network_find_binary(array($binaryName));
        if (!$binary) continue;
        $firewallEvidence[$binaryName] = array('state' => 'unreadable', 'policies' => array());
        foreach (array('INPUT' => 'input', 'FORWARD' => 'forward') as $chain => $hook) {
            $response = network_run_fixed($binary, array('-S', $chain), 5, 262144);
            if (!preg_match('/^-P\s+' . $chain . '\s+(ACCEPT|DROP|REJECT)\s*$/mi', $response['stdout'], $policyMatch)) continue;
            $policy = strtoupper($policyMatch[1]);
            $firewallEvidence[$binaryName]['state'] = 'readable';
            $firewallEvidence[$binaryName]['policies'][strtolower($chain)] = strtolower($policy);
            // ACCEPT no prueba ausencia de reglas terminales; queda unknown, nunca PASS.
            $recordPolicy($binaryName, $family, $hook, in_array($policy, array('DROP', 'REJECT'), true) ? true : null, $chain . ' policy=' . strtolower($policy));
        }
    }

    $resolvePolicy = function ($family, $hook) use (&$policyEvidence) {
        $entries = isset($policyEvidence[$family][$hook]) ? $policyEvidence[$family][$hook] : array();
        $restrictive = false;
        foreach ($entries as $entry) {
            if (isset($entry['restrictive']) && $entry['restrictive'] === false) return false;
            if (isset($entry['restrictive']) && $entry['restrictive'] === true) $restrictive = true;
        }
        return $restrictive ? true : null;
    };
    $firewallPosture = array(
        'ipv4' => array('input' => $resolvePolicy('ipv4', 'input'), 'forward' => $resolvePolicy('ipv4', 'forward')),
        'ipv6' => array('input' => $resolvePolicy('ipv6', 'input'), 'forward' => $resolvePolicy('ipv6', 'forward'))
    );

    $ipv6Disabled = $readKernelSwitch('/proc/sys/net/ipv6/conf/all/disable_ipv6');
    $relevantFamilies = array('ipv4');
    if ($ipv6Disabled !== true) $relevantFamilies[] = 'ipv6';
    $firewallWeak = false;
    $firewallUnknown = !empty($firewallCoverageIssues);
    foreach ($relevantFamilies as $family) {
        foreach (array('input', 'forward') as $hook) {
            if ($firewallPosture[$family][$hook] === false) $firewallWeak = true;
            elseif ($firewallPosture[$family][$hook] !== true) $firewallUnknown = true;
        }
    }
    $firewallStatus = $firewallWeak ? 'warn' : (!$firewallUnknown ? 'pass' : 'skipped');
    $firewallTitle = $firewallStatus === 'pass' ? 'Las políticas INPUT y FORWARD aplicables tienen una base restrictiva' : ($firewallStatus === 'warn' ? 'Se observó una política permisiva en tráfico de entrada o reenvío activo' : 'No se pudo demostrar una política INPUT/FORWARD restrictiva');
    audit_record($report, 'network.firewall', 'network', $firewallStatus, 'high', $firewallTitle, array('engines' => $firewallEvidence, 'posture' => $firewallPosture, 'coverage_issues' => array_slice(array_values(array_unique($firewallCoverageIssues)), 0, 40), 'forwarding' => array('ipv4' => $ipv4Forwarding, 'ipv6' => $ipv6Forwarding), 'external_controls_assessed' => false), 'Use una política base restrictiva en INPUT y FORWARD; verifique zonas firewalld/UFW y paridad IPv4/IPv6.', $firewallStatus === 'pass' ? 'high' : 'medium');

    if ($networkMap) {
        $publicAddresses = array();
        foreach ($networkMap['interfaces'] as $interface) foreach ($interface['addresses'] as $address) if ($address['scope'] === 'public') $publicAddresses[] = array('interface' => $interface['name'], 'address' => $address['address'], 'family' => $address['family']);
        $inputConfirmed = $firewallPosture['ipv4']['input'] === true && ($ipv6Disabled === true || $firewallPosture['ipv6']['input'] === true);
        $publicRisk = $publicAddresses && $wildcard && !$inputConfirmed;
        $publicCoverageComplete = $sourceStatus('interfaces') === 'ok' && $listenerCoverage === 'ok';
        $publicStatus = $publicRisk ? 'warn' : ($publicCoverageComplete && ($inputConfirmed || !$publicAddresses || !$wildcard) ? 'pass' : 'skipped');
        audit_record($report, 'network.public_address_context', 'network', $publicStatus, 'high', $publicRisk ? 'Direcciones públicas y listeners globales sin INPUT restrictivo confirmado requieren revisión' : ($publicStatus === 'pass' ? 'No se observó exposición pública local sin política INPUT restrictiva' : 'La exposición pública no pudo descartarse con cobertura suficiente'), array('public_addresses' => array_slice($publicAddresses, 0, 24), 'wildcard_listener_count' => count($wildcard), 'host_input_policy_restrictive' => $inputConfirmed, 'source_status' => array('interfaces' => $sourceStatus('interfaces'), 'listeners' => $listenerCoverage), 'internet_reachability_confirmed' => false), 'Valide desde el perímetro qué servicios son realmente alcanzables y aplique filtrado por interfaz, IPv4 e IPv6.');
    }

    $forwardingKnown = $ipv4Forwarding !== null && ($ipv6Disabled === true || $ipv6Forwarding !== null);
    $forwardingEnabled = $ipv4Forwarding === true || ($ipv6Disabled !== true && $ipv6Forwarding === true);
    $activeForwardPoliciesConfirmed = ($ipv4Forwarding !== true || $firewallPosture['ipv4']['forward'] === true) && ($ipv6Disabled === true || $ipv6Forwarding !== true || $firewallPosture['ipv6']['forward'] === true);
    $forwardPolicyConfirmed = $forwardingEnabled ? $activeForwardPoliciesConfirmed : null;
    $forwardingRisk = $forwardingEnabled && !$activeForwardPoliciesConfirmed;
    $forwardingStatus = $forwardingRisk ? 'warn' : (!$forwardingKnown ? 'skipped' : 'pass');
    audit_record($report, 'network.forwarding', 'network', $forwardingStatus, 'medium', $forwardingRisk ? 'El host reenvía tráfico sin política FORWARD restrictiva confirmada' : ($forwardingStatus === 'pass' ? ($forwardingEnabled ? 'El reenvío activo conserva una política FORWARD restrictiva' : 'El reenvío IP global está deshabilitado') : 'El estado de forwarding no pudo leerse'), array('ipv4' => $ipv4Forwarding, 'ipv6' => $ipv6Forwarding, 'forward_policy_confirmed' => $forwardPolicyConfirmed, 'router_context_required' => true), 'Si el host no es router, desactive forwarding; si lo es, aplique política FORWARD restrictiva y anti-spoofing.');
}

function audit_collect_host_protection(&$report)
{
    $selinux = command_exists('getenforce') ? strtolower(cmd('getenforce')) : '';
    $apparmor = audit_read_file('/sys/module/apparmor/parameters/enabled', 32);
    $apparmorEnabled = $apparmor !== false && strtoupper(trim($apparmor)) === 'Y';
    $macEnabled = $selinux === 'enforcing' || $apparmorEnabled;
    $macKnownDisabled = in_array($selinux, array('disabled', 'permissive'), true) || ($apparmor !== false && !$apparmorEnabled);
    audit_record($report, 'host.mandatory_access_control', 'host', $macEnabled ? 'pass' : ($macKnownDisabled ? 'warn' : 'skipped'), 'medium', $macEnabled ? 'El control de acceso obligatorio está activo' : ($macKnownDisabled ? 'SELinux/AppArmor no está en modo de protección' : 'No se pudo verificar SELinux/AppArmor'), array('selinux' => $selinux ?: 'not_available', 'apparmor' => $apparmor === false ? 'not_available' : trim($apparmor)), 'Active SELinux Enforcing o perfiles AppArmor adecuados para el servidor web y sus auxiliares.');

    $auditdState = '';
    if (command_exists('systemctl')) $auditdState = strtolower(cmd('systemctl is-active auditd'));
    if (!$auditdState && command_exists('pgrep')) $auditdState = cmd('pgrep -x auditd') ? 'active' : 'inactive';
    audit_record($report, 'host.auditd', 'host', $auditdState === 'active' ? 'pass' : ($auditdState ? 'warn' : 'skipped'), 'medium', $auditdState === 'active' ? 'auditd está activo' : 'No se confirmó auditd activo', array('state' => $auditdState ?: 'not_available'), 'Active auditd y reglas para identidad, privilegios, configuración y cambios del panel.');

    $failedUnits = command_exists('systemctl') ? audit_command_lines('systemctl --failed --no-legend --no-pager', 40) : array();
    audit_record($report, 'host.failed_services', 'host', $failedUnits ? 'warn' : 'pass', 'medium', $failedUnits ? 'Hay servicios del sistema en estado fallido' : 'No se detectaron unidades fallidas', array('units' => $failedUnits), 'Revise causa, dependencia y registros de cada unidad fallida.');

    $container = file_exists('/.dockerenv') || file_exists('/run/.containerenv');
    if (!$container) {
        $cgroup = audit_read_file('/proc/1/cgroup', 16384);
        $container = $cgroup !== false && preg_match('/docker|containerd|kubepods|lxc/i', $cgroup);
    }
    $report['target']['container'] = (bool)$container;
    $report['target']['security_module'] = $selinux === 'enforcing' ? 'SELinux' : ($apparmorEnabled ? 'AppArmor' : 'none_detected');
}

function audit_collect_panel_security(&$report)
{
    global $requestIsHttps, $PANEL_USERS, $PANEL_USERS_ERROR;
    $runningUser = function_exists('posix_geteuid') && function_exists('posix_getpwuid') ? posix_getpwuid(posix_geteuid()) : false;
    $runningName = is_array($runningUser) && isset($runningUser['name']) ? $runningUser['name'] : cmd('whoami', 'unknown');
    $isRoot = function_exists('posix_geteuid') ? posix_geteuid() === 0 : trim(cmd('id -u')) === '0';
    audit_record($report, 'panel.transport_https', 'panel', $requestIsHttps ? 'pass' : 'fail', 'high', $requestIsHttps ? 'La sesión actual usa HTTPS' : 'La sesión actual no usa HTTPS', array('https' => (bool)$requestIsHttps), 'Publique el panel exclusivamente tras TLS y no confíe en cabeceras proxy salvo proxies allowlisted.');
    audit_record($report, 'panel.embedded_credentials', 'credentials', USING_EMBEDDED_CREDENTIALS ? 'fail' : 'pass', 'high', USING_EMBEDDED_CREDENTIALS ? 'El panel conserva verificadores de credenciales embebidos' : 'Las credenciales provienen de configuración externa', array('embedded' => USING_EMBEDDED_CREDENTIALS, 'hashes_exposed' => false), 'Defina PANEL_USER_HASH y PANEL_PASSWORD_HASH fuera del document root y rote las credenciales predeterminadas.');
    $roleCounts = array('admin' => 0, 'operator' => 0, 'auditor' => 0);
    foreach ($PANEL_USERS as $userRecord) if ($userRecord['enabled'] && isset($roleCounts[$userRecord['role']])) $roleCounts[$userRecord['role']]++;
    $identityStatus = MULTI_USER_AUTH ? 'pass' : (PANEL_USERS_CONFIGURED ? 'fail' : 'warn');
    audit_record($report, 'panel.individual_identities', 'access_control', $identityStatus, PANEL_USERS_CONFIGURED && $PANEL_USERS_ERROR ? 'critical' : 'high', MULTI_USER_AUTH ? 'El panel usa identidades individuales y roles' : (PANEL_USERS_CONFIGURED ? 'La configuración multiusuario es inválida' : 'El panel usa una identidad administrativa compartida'), array('multi_user' => MULTI_USER_AUTH, 'enabled_user_count' => array_sum($roleCounts), 'roles' => $roleCounts, 'config_error' => $PANEL_USERS_ERROR ? true : false, 'hashes_exposed' => false), 'Configure PANEL_USERS_FILE fuera del webroot con usuarios nominativos y roles admin/operator/auditor.');
    audit_record($report, 'panel.root_runtime', 'panel', $isRoot ? 'fail' : 'pass', 'critical', $isRoot ? 'El proceso web puede ejecutar como root' : 'El panel no se ejecuta como root', array('runtime_user' => audit_clean_text($runningName, 80), 'uid_zero' => $isRoot), 'Ejecute PHP con una identidad dedicada y delegue solo acciones concretas a un helper privilegiado.');
    audit_record($report, 'panel.shell_capability', 'panel', ENABLE_SHELL ? 'fail' : 'pass', 'critical', ENABLE_SHELL ? 'La terminal y ejecución arbitraria están habilitadas' : 'La ejecución arbitraria está deshabilitada', array('enabled' => ENABLE_SHELL), 'Mantenga PANEL_ENABLE_SHELL=0; prefiera operaciones predefinidas y auditables.');
    audit_record($report, 'panel.file_write_capability', 'panel', ENABLE_FILE_WRITE ? 'warn' : 'pass', 'high', ENABLE_FILE_WRITE ? 'La escritura desde el explorador está habilitada' : 'La escritura desde el explorador está deshabilitada', array('enabled' => ENABLE_FILE_WRITE, 'scope' => ALLOWED_BASE_PATH), 'Mantenga PANEL_ENABLE_FILE_WRITE=0 o restrinja el alcance a un directorio dedicado sin ejecutables.');
    audit_record($report, 'panel.process_control', 'panel', ENABLE_PROCESS_CONTROL ? 'warn' : 'pass', 'high', ENABLE_PROCESS_CONTROL ? 'El panel puede terminar procesos' : 'El control destructivo de procesos está deshabilitado', array('enabled' => ENABLE_PROCESS_CONTROL), 'Habilite esta capacidad solo temporalmente y con identidad nominativa.');
    audit_record($report, 'panel.filesystem_scope', 'panel', ALLOWED_BASE_PATH === DIRECTORY_SEPARATOR ? 'fail' : 'pass', 'high', ALLOWED_BASE_PATH === DIRECTORY_SEPARATOR ? 'El explorador alcanza todo el sistema de archivos' : 'El explorador está restringido a un directorio', array('scope' => ALLOWED_BASE_PATH), 'Defina PANEL_ALLOWED_BASE_PATH al único árbol que deba administrarse.');
    $sourceView = env_bool('PANEL_ALLOW_SOURCE_VIEW', false);
    audit_record($report, 'panel.source_view', 'panel', $sourceView ? 'warn' : 'pass', 'high', $sourceView ? 'El visor permite leer código PHP' : 'El visor bloquea fuentes y credenciales sensibles', array('source_view_enabled' => $sourceView), 'Mantenga PANEL_ALLOW_SOURCE_VIEW=0 para evitar exponer secretos embebidos en código.');
    audit_record($report, 'panel.login_limits', 'access_control', 'pass', 'info', 'El panel aplica límites por IP, cuenta y volumen global', array('ip_attempts' => MAX_LOGIN_ATTEMPTS, 'account_attempts' => 10, 'global_attempts' => 50, 'window_seconds' => LOGIN_LOCKOUT_TIME), 'Mantenga además rate limiting en el proxy y alertas centralizadas.');
    audit_record($report, 'panel.session_limits', 'access_control', (SESSION_IDLE_TIMEOUT <= 1800 && SESSION_LIFETIME <= 28800) ? 'pass' : 'warn', 'medium', 'La sesión tiene expiración absoluta y por inactividad', array('idle_seconds' => SESSION_IDLE_TIMEOUT, 'absolute_seconds' => SESSION_LIFETIME), 'Mantenga sesiones administrativas cortas y exija reautenticación para acciones de alto impacto.');

    $scriptMode = audit_file_mode(__FILE__);
    audit_record($report, 'panel.source_permissions', 'panel', ($scriptMode !== null && ($scriptMode & 0022)) ? 'fail' : 'pass', 'high', ($scriptMode !== null && ($scriptMode & 0022)) ? 'El código del panel es modificable por grupo u otros' : 'El código del panel no es escribible por grupo/otros', array('path' => __FILE__, 'mode' => audit_mode_string($scriptMode)), 'Asigne propietario de despliegue y modo 0640/0644 sin escritura para el usuario web.');
    $phpSettings = array(
        'display_errors' => ini_get('display_errors'),
        'expose_php' => ini_get('expose_php'),
        'allow_url_include' => ini_get('allow_url_include'),
        'open_basedir' => ini_get('open_basedir') ?: 'not_set',
        'session.use_strict_mode' => ini_get('session.use_strict_mode'),
        'session.use_trans_sid' => ini_get('session.use_trans_sid'),
        'session.cookie_httponly' => ini_get('session.cookie_httponly'),
        'session.cookie_secure' => ini_get('session.cookie_secure')
    );
    $unsafePhp = filter_var($phpSettings['display_errors'], FILTER_VALIDATE_BOOLEAN) || filter_var($phpSettings['allow_url_include'], FILTER_VALIDATE_BOOLEAN) || $phpSettings['session.use_strict_mode'] != '1' || $phpSettings['session.use_trans_sid'] == '1';
    audit_record($report, 'panel.php_runtime', 'panel', $unsafePhp ? 'fail' : 'pass', 'high', $unsafePhp ? 'El runtime PHP contiene opciones inseguras' : 'El runtime PHP supera las comprobaciones principales', array('settings' => $phpSettings), 'Desactive display_errors, expose_php y allow_url_include; active sesiones estrictas y cookies seguras.');

    $env = function_exists('getenv') ? getenv() : array();
    $sensitiveNames = array();
    if (is_array($env)) foreach (array_keys($env) as $name) {
        if (preg_match('/pass|secret|token|credential|api[_-]?key|private[_-]?key|dsn|database_url/i', $name)) $sensitiveNames[] = audit_clean_text($name, 120);
    }
    audit_record($report, 'credentials.sensitive_environment', 'credentials', $sensitiveNames ? 'warn' : 'pass', 'medium', $sensitiveNames ? 'El proceso contiene variables con nombres sensibles' : 'No se detectaron nombres de variables sensibles', array('variable_names' => $sensitiveNames, 'values_redacted' => true), 'Use un gestor de secretos, limite el entorno del proceso y nunca muestre sus valores en la interfaz.');
}

function audit_finalize(&$report, $started)
{
    $counts = array('critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0);
    $coverage = array('total' => count($report['checks']), 'evaluated' => 0, 'passed' => 0, 'failed' => 0, 'warned' => 0, 'skipped' => 0, 'errors' => 0, 'percent' => 0);
    $weights = array('critical' => 25, 'high' => 10, 'medium' => 4, 'low' => 1, 'info' => 0);
    $risk = 0;
    $categories = array();
    foreach ($report['checks'] as $check) {
        $category = $check['category'];
        if (!isset($categories[$category])) $categories[$category] = array('checks' => 0, 'findings' => 0);
        $categories[$category]['checks']++;
        if ($check['status'] === 'skipped') { $coverage['skipped']++; continue; }
        if ($check['status'] === 'error') { $coverage['errors']++; continue; }
        $coverage['evaluated']++;
        if ($check['status'] === 'pass') $coverage['passed']++;
        elseif ($check['status'] === 'warn') { $coverage['warned']++; $categories[$category]['findings']++; $counts[$check['severity']]++; $risk += $weights[$check['severity']] * 0.6; }
        elseif ($check['status'] === 'fail') { $coverage['failed']++; $categories[$category]['findings']++; $counts[$check['severity']]++; $risk += $weights[$check['severity']]; }
    }
    if ($coverage['total'] > 0) $coverage['percent'] = round(($coverage['evaluated'] / $coverage['total']) * 100);
    $risk = min(100, round($risk));
    $score = max(0, 100 - $risk);
    $grade = $coverage['percent'] < 60 ? 'cobertura_insuficiente' : ($score >= 90 ? 'A' : ($score >= 75 ? 'B' : ($score >= 60 ? 'C' : ($score >= 40 ? 'D' : 'F'))));
    if ($counts['critical'] > 0 && $grade !== 'cobertura_insuficiente') $grade = 'F';
    $report['summary'] = array(
        'score' => $score,
        'risk_score' => $risk,
        'grade' => $grade,
        'risk_level' => $counts['critical'] ? 'critical' : ($counts['high'] ? 'high' : ($counts['medium'] ? 'medium' : 'low')),
        'counts' => $counts,
        'finding_count' => count($report['findings'])
    );
    $report['coverage'] = $coverage;
    $report['categories'] = $categories;
    $report['scan']['finished_at'] = gmdate('c');
    $report['scan']['duration_ms'] = round((microtime(true) - $started) * 1000);
}

function runSecurityAudit()
{
    $started = microtime(true);
    $report = array(
        'schema' => 'sentinelops.audit/1',
        'scan' => array(
            'id' => secure_random_hex(8),
            'engine_version' => '1.0.0',
            'profile' => 'full-local',
            'read_only' => true,
            'started_at' => gmdate('c'),
            'actor' => isset($_SESSION['principal']) ? audit_clean_text($_SESSION['principal'], 80) : 'panel-admin'
        ),
        'target' => array(
            'hostname' => audit_clean_text(cmd('hostname', 'unknown'), 180),
            'os' => audit_clean_text(cmd("grep PRETTY_NAME /etc/os-release | cut -d= -f2 | tr -d '\"'", 'Linux'), 220),
            'kernel' => audit_clean_text(cmd('uname -r', 'unknown'), 120)
        ),
        'checks' => array(),
        'findings' => array(),
        'inventory' => array(),
        'access' => array(),
        'coverage_notes' => array('Auditoría local sin explotación, cracking ni transmisión de secretos.')
    );
    audit_collect_accounts($report);
    audit_collect_privileges($report);
    audit_collect_access($report);
    audit_collect_ssh($report);
    audit_collect_permissions_and_secrets($report);
    audit_collect_network($report);
    audit_collect_host_protection($report);
    audit_collect_panel_security($report);
    audit_finalize($report, $started);
    return $report;
}

// ---------- File browser ----------
function validate_path($path) {
    if (!is_string($path) || $path === '' || strpos($path, "\0") !== false) return false;
    if (preg_match('#^[a-z][a-z0-9+.-]*://#i', $path)) return false;
    if ($path[0] !== DIRECTORY_SEPARATOR) return false;
    $real = realpath($path);
    if ($real === false) return false;
    $base = realpath(ALLOWED_BASE_PATH);
    if ($base === false) return false;
    if ($base !== DIRECTORY_SEPARATOR && $real !== $base && strpos($real, $base . DIRECTORY_SEPARATOR) !== 0) return false;
    return $real;
}

function is_sensitive_file_path($path)
{
    $normalized = str_replace('\\', '/', $path);
    $base = basename($normalized);
    $usersFile = getenv('PANEL_USERS_FILE');
    if ($usersFile && realpath($usersFile) === realpath($path)) return true;
    if (strtolower(pathinfo($base, PATHINFO_EXTENSION)) === 'php' && !env_bool('PANEL_ALLOW_SOURCE_VIEW', false)) return true;
    if (in_array($normalized, array('/etc/shadow', '/etc/gshadow'), true)) return true;
    if (preg_match('#/(?:\.git|\.aws|\.gnupg)/#i', $normalized)) return true;
    return (bool)preg_match('/(^\.env(?:\.|$)|^\.(?:bash|zsh|mysql|psql)_history$|id_(?:rsa|dsa|ecdsa|ed25519)$|ssh_host_.*_key$|\.key$|\.p(?:em|12|fx)$|credential|secret|^(?:wp-)?config\.php$|^database\.php$|^parameters\.ya?ml$)/i', $base);
}

function validate_new_entry_name($name)
{
    return is_string($name) && $name !== '' && $name !== '.' && $name !== '..' &&
        strlen($name) <= 180 && basename($name) === $name && !preg_match('/[\x00-\x1F\x7F]/', $name);
}

function fileBrowser($path)
{
    $path = validate_path($path);
    if (!$path || !is_dir($path))
        $path = ALLOWED_BASE_PATH;
    $items = array();
    if ($dh = @opendir($path)) {
        while (($f = readdir($dh)) !== false) {
            if ($f === '.')
                continue;
            $fp = $path . '/' . $f;
            $stat = @stat($fp);
            if (!is_array($stat)) continue;
            $items[] = array(
                'name' => $f,
                'path' => $fp,
                'dir' => is_dir($fp),
                'size' => is_file($fp) ? filesize($fp) : 0,
                'perms' => substr(sprintf('%o', fileperms($fp)), -4),
                'owner' => function_exists('posix_getpwuid') ? (isset($stat['uid']) && ($puid = posix_getpwuid($stat['uid'])) && isset($puid['name']) ? $puid['name'] : $stat['uid']) : $stat['uid'],
                'mtime' => date('Y-m-d H:i', isset($stat['mtime']) ? $stat['mtime'] : 0),
                'readable' => is_readable($fp),
                'writable' => is_writable($fp),
                'sensitive' => is_file($fp) && is_sensitive_file_path($fp),
            );
        }
        closedir($dh);
    }
    usort($items, function ($a, $b) {
        if ($a['name'] === '..')
            return -1;
        if ($b['name'] === '..')
            return 1;
        if ($a['dir'] !== $b['dir'])
            return $b['dir'] - $a['dir'];
        return strcasecmp($a['name'], $b['name']);
    });
    return array('path' => $path, 'items' => $items);
}

function readFileContent($path, $maxBytes = MAX_FILE_SIZE)
{
    $path = validate_path($path);
    if (!$path || !is_file($path) || !is_readable($path))
        return array('error' => 'File is outside the allowed scope or cannot be read');
    if (is_sensitive_file_path($path))
        return array('error' => 'Sensitive files are intentionally blocked; only metadata is audited');
    $size = filesize($path);
    $mime = mime_content_type($path) ?: 'application/octet-stream';
    $binary = (strpos($mime, 'text') === false && strpos($mime, 'json') === false && strpos($mime, 'xml') === false && strpos($mime, 'javascript') === false);
    if ($binary) {
        return array('path' => $path, 'size' => $size, 'mime' => $mime, 'binary' => true, 'content' => '[Binary file: ' . $mime . ' (' . $size . ' bytes)]');
    }
    $content = file_get_contents($path, false, null, 0, $maxBytes);
    return array('path' => $path, 'size' => $size, 'mime' => $mime, 'binary' => false, 'content' => $content, 'truncated' => $size > $maxBytes);
}

function downloadFile($path)
{
    $path = validate_path($path);
    if (!$path || !is_file($path) || !is_readable($path) || is_sensitive_file_path($path))
        return false;
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    $downloadName = preg_replace('/[^a-zA-Z0-9._-]/', '_', basename($path));
    header('Content-Disposition: attachment; filename="' . ($downloadName ?: 'download.bin') . '"');
    header('Expires: 0');
    header('Cache-Control: no-store, no-cache, must-revalidate');
    header('Pragma: no-cache');
    header('Content-Length: ' . filesize($path));
    readfile($path);
    exit;
}

function createDirectory($path, $name)
{
    $path = validate_path($path);
    if (!$path || !is_dir($path) || !validate_new_entry_name($name)) return false;
    $dir = $path . '/' . $name;
    if (!is_dir($dir)) {
        return @mkdir($dir, 0750);
    }
    return false;
}

function createFile($path, $name, $content = '')
{
    $path = validate_path($path);
    if (!$path || !is_dir($path) || !validate_new_entry_name($name) || !is_string($content) || strlen($content) > MAX_FILE_SIZE) return false;
    $file = $path . '/' . $name;
    if (!file_exists($file)) {
        $written = @file_put_contents($file, $content, LOCK_EX) !== false;
        if ($written) @chmod($file, 0640);
        return $written;
    }
    return false;
}

// ---------- API ----------
function json_response($payload, $status = 200)
{
    http_response_code($status);
    header('Content-Type: application/json; charset=UTF-8');
    $flags = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) $flags |= JSON_INVALID_UTF8_SUBSTITUTE;
    $json = json_encode($payload, $flags);
    if ($json === false) {
        http_response_code(500);
        $json = '{"error":"JSON encoding failed"}';
    }
    echo $json;
    exit;
}

if (isset($_GET['api'])) {
    if (empty($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
        json_response(array('error' => 'Authentication required'), 401);
    }
    $api = is_string($_GET['api']) ? $_GET['api'] : '';
    if (!preg_match('/^[a-z_]+$/D', $api)) json_response(array('error' => 'Invalid API route'), 400);
    $postApis = array('audit_run', 'network_map', 'network_discover', 'kill_process', 'exec', 'mkdir', 'touch', 'term_init', 'term_exec', 'term_kill');
    $method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper($_SERVER['REQUEST_METHOD']) : 'GET';
    if (in_array($api, $postApis, true)) {
        if ($method !== 'POST') json_response(array('error' => 'POST required'), 405);
        csrf_validate();
    } elseif ($method !== 'GET') {
        json_response(array('error' => 'GET required'), 405);
    }

    if (in_array($api, array('exec', 'term_init', 'term_exec', 'term_kill'), true) && !session_can_capability('shell')) {
        security_event('capability_denied', array('capability' => 'shell', 'api' => $api));
        json_response(array('error' => 'Shell capability is disabled by policy'), 403);
    }
    if (in_array($api, array('mkdir', 'touch'), true) && !session_can_capability('file_write')) {
        security_event('capability_denied', array('capability' => 'file_write', 'api' => $api));
        json_response(array('error' => 'File write capability is disabled by policy'), 403);
    }
    if ($api === 'kill_process' && !session_can_capability('process_control')) {
        security_event('capability_denied', array('capability' => 'process_control'));
        json_response(array('error' => 'Process control is disabled by policy'), 403);
    }
    if ($api === 'network_discover' && !session_can_capability('network_discovery')) {
        security_event('capability_denied', array('capability' => 'network_discovery'));
        $networkNamespace = network_namespace_info();
        $reason = !ENABLE_NETWORK_DISCOVERY ? 'Active network discovery is disabled by policy' : (!empty($networkNamespace['container']) && !ENABLE_CONTAINER_NETWORK_DISCOVERY ? 'Set PANEL_NETWORK_ALLOW_CONTAINER=1 only if scanning from this container namespace is intended' : (!network_configured_allowed_cidrs() ? 'Configure PANEL_NETWORK_ALLOWED_CIDRS with valid private networks before enabling discovery' : 'Network discovery is not allowed for this role'));
        json_response(array('error' => $reason), 403);
    }
    if (in_array($api, array('filebrowser', 'readfile', 'download'), true) && !session_can_capability('file_read')) {
        security_event('capability_denied', array('capability' => 'file_read', 'api' => $api));
        json_response(array('error' => 'File access is not allowed for this role'), 403);
    }
    if (in_array($api, array('logs', 'envvars', 'crontabs', 'lastlogins', 'connections'), true) && !session_can_capability('raw_observability')) {
        security_event('capability_denied', array('capability' => 'raw_observability', 'api' => $api));
        json_response(array('error' => 'Raw observability data is not allowed for this role'), 403);
    }

    if ($api === 'term_init') {
        $termId = wsGenId();
        if (!wsInit($termId)) json_response(array('error' => 'Unable to initialize terminal'), 500);
        if (empty($_SESSION['terminal_ids']) || !is_array($_SESSION['terminal_ids'])) $_SESSION['terminal_ids'] = array();
        while (count($_SESSION['terminal_ids']) >= 5) {
            $expiredTerm = array_shift($_SESSION['terminal_ids']);
            if (wsValidId($expiredTerm)) wsKill($expiredTerm);
        }
        $_SESSION['terminal_ids'][] = $termId;
        $_SESSION['terminal_ids'] = array_slice(array_unique($_SESSION['terminal_ids']), -5);
        security_event('terminal_init');
        json_response(array('status' => 'ok', 'term_id' => $termId, 'cwd' => wsGetCwd($termId), 'user' => cmd('whoami', 'user'), 'host' => cmd('hostname', 'localhost')));
    }
    if ($api === 'term_exec' || $api === 'term_kill') {
        $termId = isset($_POST['term_id']) && is_string($_POST['term_id']) ? $_POST['term_id'] : '';
        if (!wsValidId($termId) || empty($_SESSION['terminal_ids']) || !in_array($termId, $_SESSION['terminal_ids'], true)) {
            json_response(array('error' => 'Invalid terminal session'), 400);
        }
        if ($api === 'term_exec') {
            $command = isset($_POST['cmd']) && is_string($_POST['cmd']) ? $_POST['cmd'] : '';
            if ($command === '' || strlen($command) > 8192) json_response(array('error' => 'Invalid command length'), 422);
            security_event('terminal_exec', array('term' => $termId));
            $terminalResult = wsExec($termId, $command);
            security_event('terminal_completed', array('term' => $termId, 'exit_code' => isset($terminalResult['exit_code']) ? $terminalResult['exit_code'] : null, 'timed_out' => !empty($terminalResult['timed_out']) ? 'yes' : 'no'));
            json_response($terminalResult);
        }
        wsKill($termId);
        $_SESSION['terminal_ids'] = array_values(array_diff($_SESSION['terminal_ids'], array($termId)));
        security_event('terminal_kill', array('term' => $termId));
        json_response(array('status' => 'killed'));
    }

    switch ($api) {
        case 'csrf_token':
            json_response(array('token' => csrf_token()));
        case 'audit_run':
            $lastAudit = isset($_SESSION['last_audit_at']) ? intval($_SESSION['last_audit_at']) : 0;
            if (time() - $lastAudit < 10) json_response(array('error' => 'Wait before starting another audit', 'retry_after' => 10 - (time() - $lastAudit)), 429);
            $auditLockPath = PANEL_DATA_DIR . '/audit-run.lock';
            $auditLock = PANEL_STORAGE_READY && !is_link($auditLockPath) ? @fopen($auditLockPath, 'c+') : false;
            if (!$auditLock) json_response(array('error' => 'Audit lock storage unavailable'), 503);
            @chmod($auditLockPath, 0600);
            if (!flock($auditLock, LOCK_EX | LOCK_NB)) { fclose($auditLock); json_response(array('error' => 'Another audit is already running', 'retry_after' => 10), 429); }
            $_SESSION['last_audit_at'] = time();
            security_event('audit_started');
            try {
                $audit = runSecurityAudit();
            } catch (Throwable $error) {
                flock($auditLock, LOCK_UN);
                fclose($auditLock);
                security_event('audit_failed', array('error_type' => get_class($error)));
                json_response(array('error' => 'Audit failed safely; review server logs'), 500);
            }
            flock($auditLock, LOCK_UN);
            fclose($auditLock);
            security_event('audit_completed', array('scan_id' => $audit['scan']['id'], 'score' => $audit['summary']['score'], 'findings' => $audit['summary']['finding_count']));
            json_response($audit);
        case 'network_map':
            $inventoryError = null; $inventoryRetryAfter = 0;
            $inventoryHandles = network_inventory_guard_acquire($inventoryError, $inventoryRetryAfter);
            if (!$inventoryHandles) {
                security_event('network_inventory_denied', array('reason' => $inventoryRetryAfter ? 'rate_or_concurrency_limit' : 'storage_unavailable', 'retry_after' => max(0, intval($inventoryRetryAfter))));
                json_response(array('error' => $inventoryError ?: 'Inventario no disponible', 'retry_after' => max(1, intval($inventoryRetryAfter))), $inventoryRetryAfter ? 429 : 503);
            }
            try {
                $passiveMap = collectNetworkMap(false);
            } catch (Throwable $inventoryException) {
                network_inventory_guard_release($inventoryHandles);
                json_response(array('error' => 'El inventario de red falló de forma segura'), 500);
            }
            network_inventory_guard_release($inventoryHandles);
            security_event('network_inventory_viewed', array('interfaces' => $passiveMap['summary']['interfaces'], 'routes' => $passiveMap['summary']['routes'], 'neighbors' => $passiveMap['summary']['neighbors'], 'duration_ms' => $passiveMap['duration_ms']));
            json_response($passiveMap);
        case 'network_discover':
            $loginAt = isset($_SESSION['login_time']) ? intval($_SESSION['login_time']) : 0;
            if (!$loginAt || time() - $loginAt > 600) {
                security_event('network_discovery_denied', array('reason' => 'recent_auth_required'));
                json_response(array('error' => 'Vuelva a iniciar sesión para ejecutar un descubrimiento activo'), 403);
            }
            $selectedNetworkId = isset($_POST['network_id']) && is_string($_POST['network_id']) ? strtolower(trim($_POST['network_id'])) : '';
            if (!preg_match('/^[a-f0-9]{24}$/D', $selectedNetworkId)) {
                security_event('network_discovery_denied', array('reason' => 'invalid_scope'));
                json_response(array('error' => 'Seleccione una subred autorizada válida'), 422);
            }
            $networkLockError = null; $networkRetryAfter = 0;
            $networkLock = network_discovery_lock_acquire($networkLockError, $networkRetryAfter);
            if (!$networkLock) {
                security_event('network_discovery_denied', array('reason' => $networkRetryAfter ? 'rate_or_concurrency_limit' : 'rate_storage_unavailable', 'retry_after' => max(0, intval($networkRetryAfter))));
                json_response(array('error' => $networkLockError ?: 'No se pudo iniciar el descubrimiento', 'retry_after' => max(1, intval($networkRetryAfter))), $networkRetryAfter ? 429 : 503);
            }
            security_event('network_discovery_started', array('network_id' => $selectedNetworkId, 'max_hosts' => NETWORK_DISCOVERY_MAX_HOSTS, 'deadline_seconds' => NETWORK_DISCOVERY_TIMEOUT));
            try {
                $networkMap = collectNetworkMap(true, $selectedNetworkId, $networkLock);
            } catch (Throwable $networkError) {
                network_discovery_lock_release($networkLock);
                security_event('network_discovery_failed', array('error_type' => get_class($networkError)));
                $storageFailure = $networkError instanceof UnexpectedValueException;
                json_response(array('error' => $networkError instanceof RuntimeException ? $networkError->getMessage() : 'El descubrimiento falló de forma segura'), $storageFailure ? 503 : 422);
            }
            network_discovery_lock_release($networkLock);
            security_event('network_discovery_completed', array('scan_id' => $networkMap['discovery']['id'], 'network_id' => $selectedNetworkId, 'scope' => isset($networkMap['discovery']['scope']['cidr']) ? $networkMap['discovery']['scope']['cidr'] : 'unknown', 'interface' => isset($networkMap['discovery']['scope']['interface']) ? $networkMap['discovery']['scope']['interface'] : 'unknown', 'method' => $networkMap['discovery']['method'], 'probes_attempted' => $networkMap['discovery']['probes_attempted'], 'responded' => $networkMap['discovery']['responded'], 'probe_duration_ms' => $networkMap['discovery']['duration_ms'], 'operation_duration_ms' => $networkMap['duration_ms']));
            json_response($networkMap);
        case 'sysinfo':
            json_response(getSystemInfo());
        case 'processes':
            $count = max(1, min(100, intval(isset($_GET['count']) ? $_GET['count'] : 25)));
            json_response(getProcesses(isset($_GET['sort']) ? $_GET['sort'] : 'cpu', $count));
        case 'kill_process':
            $pid = isset($_POST['pid']) ? abs(intval($_POST['pid'])) : 0;
            if ($pid <= 1) json_response(array('error' => 'Invalid PID'), 422);
            $success = killProcess($pid);
            security_event('process_kill', array('pid' => $pid, 'outcome' => $success ? 'success' : 'failed'));
            json_response($success ? array('status' => 'ok') : array('error' => 'Unable to terminate process'), $success ? 200 : 500);
        case 'connections':
            json_response(getConnections());
        case 'crontabs':
            json_response(array('data' => getCrontabs()));
        case 'users':
            json_response(getUsers());
        case 'lastlogins':
            json_response(array('data' => getLastLogins()));
        case 'firewall':
            json_response(array('data' => getFirewall()));
        case 'filebrowser':
            json_response(fileBrowser(isset($_GET['path']) && is_string($_GET['path']) ? $_GET['path'] : ALLOWED_BASE_PATH));
        case 'readfile':
            $path = isset($_GET['path']) && is_string($_GET['path']) ? $_GET['path'] : '';
            $result = readFileContent($path);
            security_event('file_read', array('path' => $path, 'outcome' => isset($result['error']) ? 'denied' : 'success'));
            json_response($result, isset($result['error']) ? 403 : 200);
        case 'download':
            $path = isset($_GET['path']) && is_string($_GET['path']) ? $_GET['path'] : '';
            security_event('file_download', array('path' => $path));
            if (!downloadFile($path)) json_response(array('error' => 'Download denied'), 403);
            exit;
        case 'mkdir':
            $path = isset($_POST['path']) && is_string($_POST['path']) ? $_POST['path'] : '';
            $name = isset($_POST['name']) && is_string($_POST['name']) ? $_POST['name'] : '';
            $success = createDirectory($path, $name);
            security_event('file_write', array('operation' => 'mkdir', 'path' => $path, 'name' => $name, 'outcome' => $success ? 'success' : 'failed'));
            json_response($success ? array('status' => 'ok') : array('error' => 'Directory creation denied or failed'), $success ? 200 : 422);
        case 'touch':
            $path = isset($_POST['path']) && is_string($_POST['path']) ? $_POST['path'] : '';
            $name = isset($_POST['name']) && is_string($_POST['name']) ? $_POST['name'] : '';
            $content = isset($_POST['content']) && is_string($_POST['content']) ? $_POST['content'] : '';
            $success = createFile($path, $name, $content);
            security_event('file_write', array('operation' => 'create_file', 'path' => $path, 'name' => $name, 'outcome' => $success ? 'success' : 'failed'));
            json_response($success ? array('status' => 'ok') : array('error' => 'File creation denied or failed'), $success ? 200 : 422);
        case 'exec':
            $command = isset($_POST['cmd']) && is_string($_POST['cmd']) ? $_POST['cmd'] : '';
            $cwd = isset($_POST['cwd']) && is_string($_POST['cwd']) ? $_POST['cwd'] : ALLOWED_BASE_PATH;
            if ($command === '' || strlen($command) > 8192) json_response(array('error' => 'Invalid command length'), 422);
            security_event('shell_exec', array('cwd' => $cwd));
            $execution = run_shell_limited($command, $cwd, 30, 262144);
            security_event('shell_completed', array('cwd' => $cwd, 'exit_code' => $execution['exit_code'], 'timed_out' => $execution['timed_out'] ? 'yes' : 'no', 'truncated' => $execution['truncated'] ? 'yes' : 'no'));
            $output = rtrim($execution['stdout'] . ($execution['stderr'] ? "\n" . $execution['stderr'] : ''));
            json_response(array('output' => $output, 'exit_code' => $execution['exit_code'], 'timed_out' => $execution['timed_out'], 'truncated' => $execution['truncated']));
        case 'logs':
            $type = isset($_GET['type']) && is_string($_GET['type']) ? $_GET['type'] : 'messages';
            json_response(array('data' => getLogs($type), 'type' => $type));
        case 'envvars':
            json_response(array('data' => getEnvVars(), 'redacted' => true));
        case 'services':
            json_response(array('data' => getServices()));
        case 'selinux':
            json_response(getSelinux());
        case 'packages':
            json_response(getPackages());
        case 'updates':
            json_response(array('data' => getYumUpdates()));
        case 'repos':
            json_response(array('data' => getRepos()));
        case 'failed_services':
            json_response(array('data' => getFailedServices()));
        case 'centos_version':
            json_response(array('data' => getCentOSVersion()));
        default:
            json_response(array('error' => 'Unknown API'), 404);
    }
}

// ---------- Login ----------
if (empty($_SESSION['authenticated']) || $_SESSION['authenticated'] !== true) {
    $err = null;
    if (isset($_POST['login'])) {
        $submittedToken = isset($_POST['csrf_token']) && is_string($_POST['csrf_token']) ? $_POST['csrf_token'] : '';
        $csrfOk = !empty($_SESSION['csrf_token']) && $submittedToken !== '' && hash_equals($_SESSION['csrf_token'], $submittedToken);
        $u = isset($_POST['username']) && is_string($_POST['username']) ? trim($_POST['username']) : '';
        $p = isset($_POST['password']) && is_string($_POST['password']) ? $_POST['password'] : '';
        $validShape = $u !== '' && $p !== '' && strlen($u) <= 128 && strlen($p) <= 1024;
        if (PANEL_USERS_CONFIGURED && $PANEL_USERS_ERROR) {
            error_log('[sentinelops] Refusing login: ' . $PANEL_USERS_ERROR);
            http_response_code(503);
            $err = 'CONFIGURACIÓN DE IDENTIDADES INVÁLIDA';
        } elseif (!PANEL_STORAGE_READY) {
            error_log('[sentinelops] Refusing login: PANEL_DATA_DIR is not a private writable directory.');
            http_response_code(503);
            $err = 'ALMACENAMIENTO DE SEGURIDAD NO DISPONIBLE';

        } elseif (!$csrfOk) {
            security_event('csrf_rejected', array('route' => 'login'));
            $err = 'SOLICITUD DE AUTENTICACIÓN INVÁLIDA';
        } elseif (is_locked_out($u)) {
            security_event('login_locked');
            $err = "DEMASIADOS INTENTOS. ESPERE " . LOGIN_LOCKOUT_TIME . " SEGUNDOS.";
        } else {
            $role = 'admin';
            if (MULTI_USER_AUTH) {
                $record = isset($PANEL_USERS[$u]) ? $PANEL_USERS[$u] : null;
                $candidateHash = $record ? $record['password_hash'] : $defaultPassHash;
                $userOk = $record && $record['enabled'] === true;
                $passOk = password_verify($validShape ? $p : secure_random_hex(16), $candidateHash);
                if ($record) $role = $record['role'];
            } else {
                // Verificar siempre ambos valores para evitar un oráculo temporal del usuario.
                $userOk = password_verify($validShape ? $u : secure_random_hex(16), $HASH_USER);
                $passOk = password_verify($validShape ? $p : secure_random_hex(16), $HASH_PASS);
            }
            if ($validShape && $userOk && $passOk) {
                clear_failed_attempts($u);
                session_regenerate_id(true);
                $_SESSION['authenticated'] = true;
                $_SESSION['login_time'] = time();
                $_SESSION['last_activity'] = time();
                $_SESSION['ua_fingerprint'] = hash('sha256', isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '');
                $_SESSION['principal'] = substr($u, 0, 128);
                $_SESSION['role'] = $role;
                $_SESSION['csrf_token'] = secure_random_hex(32);
                security_event('login_success', array('principal' => $u, 'role' => $role));
                header('Location: ' . SELF_URL);
                exit;
            } else {
                record_failed_attempt($u);
                security_event('login_failed', array('principal' => $u ?: 'invalid'));
                usleep(mt_rand(250000, 650000));
                $err = "ACCESO DENEGADO";
            }
        }
    }
    showLogin($err);
    exit;
}

// ---------- Logout (ahora requiere POST + CSRF) ----------
if (isset($_POST['logout'])) {
    csrf_validate_or_die();
    security_event('logout', array('principal' => isset($_SESSION['principal']) ? $_SESSION['principal'] : 'panel-admin'));
    if (!empty($_SESSION['terminal_ids']) && is_array($_SESSION['terminal_ids'])) foreach ($_SESSION['terminal_ids'] as $termId) if (wsValidId($termId)) wsKill($termId);
    $_SESSION = array();
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
    }
    session_destroy();
    header('Location: ' . SELF_URL);
    exit;
}
// GET no muta estado: evita logout-CSRF.
if (isset($_GET['logout'])) {
    header('Location: ' . SELF_URL);
    exit;
}

// ---------- Terminal Window ----------
$isTerminalWindow = isset($_GET['terminal']) && $_GET['terminal'] == '1';
if ($isTerminalWindow) {
    if (!session_can_capability('shell')) {
        http_response_code(403);
        echo 'Terminal disabled by policy.';
        exit;
    }
    renderTerminalWindow();
    exit;
}

// ---------- Main Panel ----------
function showLogin($err = null) {
    $csrf = csrf_token();
    $errHtml = $err ? '<div class="login-error" role="alert">'.htmlspecialchars($err, ENT_QUOTES, 'UTF-8').'</div>' : '';
    echo '<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Acceso // SentinelOps</title>';
    echo '<style>
        *{box-sizing:border-box}:root{--accent:#38bdf8;--cyan:#67e8f9;--text:#eef5ff;--muted:#9aacbf;--bg:#070b12;--card:#0e1624;--border:#25334a;--danger:#fb7185}
        body{margin:0;min-height:100vh;background:radial-gradient(circle at 20% 0%,rgba(56,189,248,.16),transparent 35%),var(--bg);color:var(--text);font-family:Inter,ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif;display:grid;place-items:center;padding:20px}
        .login-box{width:min(100%,440px);border:1px solid var(--border);padding:30px;background:rgba(14,22,36,.94);border-radius:18px;box-shadow:0 30px 90px rgba(0,0,0,.45)}
        .brand{display:flex;align-items:center;gap:10px;color:var(--cyan);font-weight:900;letter-spacing:.08em;font-size:.78rem}.brand-dot{width:10px;height:10px;border-radius:50%;background:#34d399;box-shadow:0 0 18px #34d399}
        h1{margin:20px 0 8px;font-size:2rem;line-height:1.1}p{margin:0 0 24px;color:var(--muted);line-height:1.55;font-size:.9rem}
        label{display:block;color:#cbd5e1;font-size:.76rem;font-weight:750;margin:13px 0 6px}
        input{background:#08101b;color:var(--text);border:1px solid var(--border);border-radius:9px;padding:12px;width:100%;outline:none;font:inherit;min-height:46px}input:focus{border-color:var(--accent);box-shadow:0 0 0 3px rgba(56,189,248,.15)}
        button{margin-top:18px;background:linear-gradient(135deg,var(--accent),var(--cyan));color:#04111c;border:0;border-radius:9px;padding:12px 15px;cursor:pointer;font-weight:800;width:100%;min-height:46px}button:hover{filter:brightness(1.08)}
        .login-error{padding:10px 12px;margin:14px 0;border:1px solid rgba(251,113,133,.45);background:rgba(251,113,133,.09);color:#fecdd3;border-radius:8px;font-size:.78rem}
        .security-note{margin-top:18px;padding-top:16px;border-top:1px solid var(--border);color:var(--muted);font-size:.72rem;line-height:1.5}
    </style></head><body>';
    echo '<div class="login-box">';
    echo '<div class="brand"><span class="brand-dot"></span>SENTINELOPS // CONTROL CENTER</div>';
    echo '<h1>Acceso administrativo</h1><p>Identidad protegida, sesión acotada y trazabilidad de acciones sensibles.</p>';
    echo $errHtml;
    echo '<form method="POST">';
    echo '<input type="hidden" name="csrf_token" value="'.htmlspecialchars($csrf, ENT_QUOTES, 'UTF-8').'">';
    echo '<label for="username">Usuario</label><input id="username" type="text" name="username" autocomplete="username" maxlength="128" required autofocus>';
    echo '<label for="password">Contraseña</label><input id="password" type="password" name="password" autocomplete="current-password" maxlength="1024" required>';
    echo '<button type="submit" name="login" value="1">Iniciar sesión segura</button>';
    echo '</form><div class="security-note">Bloqueo tras intentos fallidos · cookies HttpOnly/SameSite · cierre automático por inactividad</div></div></body></html>';
}

function renderTerminalWindow() {
    echo '<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"><title>Terminal // SentinelOps</title>';
    echo '<style>
        :root{--c1:#67e8f9;--bg:#070b12;}
        body{background:var(--bg);color:var(--c1);font-family:"Courier New",monospace;margin:0;padding:10px;}
        #out{white-space:pre-wrap;margin-bottom:10px;font-size:14px;}
        .input-row {display:flex; align-items:center;}
        input{background:transparent;color:var(--c1);border:none;outline:none;flex:1;font-family:"Courier New",monospace;font-size:14px;margin-left:5px;}
    </style></head><body>';
    echo '<div id="out"></div>';
    echo '<div class="input-row"><span>$&nbsp;</span><input type="text" id="cmd" autofocus autocomplete="off"></div>';
    echo '<script nonce="'.htmlspecialchars($GLOBALS['cspNonce'], ENT_QUOTES, 'UTF-8').'">
        const API = window.location.pathname;
        const out = document.getElementById("out");
        const cmd = document.getElementById("cmd");
        cmd.addEventListener("keypress", async function(e) {
            if (e.key === "Enter") {
                const c = cmd.value; cmd.value = "";
                if (!c.trim()) return;
                const commandLine = document.createElement("div");
                const prompt = document.createElement("span");
                prompt.style.color = "#fb7185"; prompt.textContent = "$ ";
                commandLine.append(prompt, document.createTextNode(c)); out.appendChild(commandLine);
                const fd = new FormData(); 
                fd.append("csrf_token", "'.htmlspecialchars(csrf_token()).'"); 
                fd.append("cmd", c); 
                fd.append("cwd", '.json_encode(ALLOWED_BASE_PATH, JSON_UNESCAPED_SLASHES).');
                try {
                    const res = await fetch(API + "?api=exec", {method:"POST", body:fd});
                    const data = await res.json();
                    if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
                    if (data.output) { const line = document.createElement("div"); line.textContent = data.output; out.appendChild(line); }
                } catch(err) {
                    const line = document.createElement("div"); line.style.color = "#fb7185"; line.textContent = "Error: " + err.message; out.appendChild(line);
                }
                window.scrollTo(0, document.body.scrollHeight);
            }
        });
    </script></body></html>';
}

$SI = getSystemInfo();
?>
<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=yes">
    <title><?php echo htmlspecialchars($SI['host']); ?> // SentinelOps</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box
        }

        :root {
            --c1: #38bdf8;
            --c2: #22d3ee;
            --c3: #217ca3;
            --bg: #070b12;
            --bg2: #0e1624;
            --bg3: #141f30;
            --bg4: #1a2940;
            --red: #fb7185;
            --cyan: #67e8f9;
            --orange: #fbbf24;
            --purple: #c084fc;
            --yellow: #fde047;
            --green: #34d399;
            --text: #eef5ff;
            --muted: #9aacbf;
            --border: #25334a;
            --font: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            --mono: "SFMono-Regular", Consolas, "Liberation Mono", monospace;
        }

        @keyframes flicker {

            0%,
            100% {
                opacity: 1
            }

            50% {
                opacity: .97
            }
        }

        @keyframes scanline-move {
            0% {
                top: -100%
            }

            100% {
                top: 100%
            }
        }

        @keyframes pulse-glow {

            0%,
            100% {
                box-shadow: 0 0 5px rgba(0, 255, 65, .2)
            }

            50% {
                box-shadow: 0 0 20px rgba(0, 255, 65, .4)
            }
        }

        @keyframes data-stream {
            0% {
                background-position: 0 0
            }

            100% {
                background-position: 0 100%
            }
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(-10px)
            }

            to {
                opacity: 1;
                transform: translateY(0)
            }
        }

        body {
            background: var(--bg);
            color: var(--text);
            font-family: var(--font);
            font-size: 14px;
            overflow-x: hidden;
            min-height: 100vh;
        }

        body::after {
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            pointer-events: none;
            background: radial-gradient(circle at 10% 0%, rgba(56,189,248,.055), transparent 34%);
            z-index: 9999;
        }

        .hud-header {
            background: linear-gradient(180deg, var(--bg3), var(--bg));
            border-bottom: 1px solid var(--c3);
            padding: 12px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
            backdrop-filter: blur(10px);
            flex-wrap: wrap;
            gap: 10px;
        }

        .hud-logo {
            font-size: 1.4rem;
            font-weight: bold;
            text-shadow: 0 0 16px rgba(56,189,248,.35);
            letter-spacing: .8px;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .hud-logo .pulse-dot {
            width: 8px;
            height: 8px;
            background: var(--c1);
            border-radius: 50%;
            animation: pulse-glow 2s infinite;
            box-shadow: 0 0 10px var(--c1);
        }

        .skip-link{position:fixed;left:12px;top:-80px;z-index:10000;background:var(--c1);color:#03111b;padding:10px 14px;border-radius:8px;font-weight:800;text-decoration:none}
        .skip-link:focus{top:12px}
        :focus-visible{outline:3px solid var(--yellow);outline-offset:3px}
        .mono{font-family:var(--mono)}
        .muted{color:var(--muted)}

        .hud-stats {
            display: flex;
            gap: 18px;
            align-items: center;
            font-size: .8rem;
            flex-wrap: wrap;
        }

        .hud-stat {
            display: flex;
            flex-direction: column;
            align-items: center;
            gap: 2px;
            opacity: .9;
        }

        .hud-stat-val {
            color: var(--c1);
            text-shadow: 0 0 5px var(--c1);
        }

        .hud-stat-label {
            font-size: .65rem;
            opacity: .5;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .hud-clock {
            font-size: 1rem;
            text-shadow: 0 0 8px var(--cyan);
            color: var(--cyan);
            font-weight: bold;
        }

        .btn-logout {
            background: transparent;
            border: 1px solid var(--red);
            color: var(--red);
            padding: 6px 14px;
            font-family: var(--font);
            font-size: .75rem;
            cursor: pointer;
            transition: all .3s;
            text-transform: uppercase;
            letter-spacing: 1px;
        }

        .btn-logout:hover {
            background: var(--red);
            color: #000;
            box-shadow: 0 0 15px rgba(255, 0, 64, .5);
        }

        .nav-bar {
            display: flex;
            gap: 2px;
            padding: 8px 15px;
            background: var(--bg2);
            border-bottom: 1px solid var(--border);
            overflow-x: auto;
            flex-wrap: wrap;
        }

        .nav-btn {
            background: transparent;
            border: 1px solid transparent;
            color: var(--muted);
            padding: 8px 16px;
            font-family: var(--font);
            font-size: .75rem;
            cursor: pointer;
            transition: all .3s;
            text-transform: uppercase;
            letter-spacing: 1px;
            white-space: nowrap;
            position: relative;
        }

        .nav-btn:hover {
            color: var(--c1);
            border-color: var(--c3);
        }

        .nav-btn.active {
            color: var(--c1);
            border-color: var(--c1);
            text-shadow: 0 0 8px var(--c1);
            background: rgba(0, 255, 65, .05);
        }

        .nav-btn.audit-nav{color:var(--cyan);border-color:rgba(103,232,249,.35);font-weight:800}
        .capability-badge{display:inline-flex;align-items:center;gap:6px;padding:5px 9px;border:1px solid var(--border);border-radius:999px;color:var(--muted);font-size:.68rem}
        .capability-badge.safe{color:var(--green);border-color:rgba(52,211,153,.4)}
        .header-audit{background:linear-gradient(135deg,var(--c1),var(--cyan));color:#04111c;border:0;border-radius:8px;padding:8px 13px;font:700 .72rem var(--font);cursor:pointer}

        .nav-btn.active::after {
            content: '';
            position: absolute;
            bottom: -1px;
            left: 20%;
            right: 20%;
            height: 2px;
            background: var(--c1);
            box-shadow: 0 0 8px var(--c1);
        }

        .main-content {
            padding: 15px;
            min-height: calc(100vh - 100px);
        }

        .section {
            display: none;
            animation: slideIn .3s ease;
        }

        .section.active {
            display: block;
        }

        .dash-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 12px;
            margin-bottom: 15px;
        }

        .dash-grid-wide {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 12px;
        }

        .panel {
            background: var(--bg2);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
            transition: all .3s;
        }

        .panel:hover {
            border-color: var(--c3);
            box-shadow: 0 0 15px rgba(0, 255, 65, .08);
        }

        .panel-head {
            background: var(--bg3);
            padding: 10px 14px;
            border-bottom: 1px solid var(--border);
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }

        .panel-title {
            font-size: .85rem;
            display: flex;
            align-items: center;
            gap: 8px;
            color:var(--text);
            text-shadow: none;
        }

        .panel-badge {
            background: var(--c1);
            color: #000;
            padding: 1px 8px;
            font-size: .7rem;
            font-weight: bold;
            border-radius: 2px;
        }

        .panel-badge.warn {
            background: var(--orange);
        }

        .panel-badge.crit {
            background: var(--red);
        }

        .panel-body {
            padding: 14px;
            overflow-x: auto;
        }

        .gauge-wrap {
            display: flex;
            justify-content: center;
            margin-bottom: 12px;
        }

        .gauge-svg-wrap {
            position: relative;
            width: 110px;
            height: 110px;
        }

        .gauge-svg-wrap svg {
            width: 100%;
            height: 100%;
            transform: rotate(-90deg);
        }

        .gauge-center-text {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }

        .gauge-pct {
            font-size: 1.4rem;
            font-weight: bold;
            text-shadow: 0 0 10px var(--c1);
        }

        .gauge-sub {
            font-size: .6rem;
            opacity: .5;
            text-transform: uppercase;
        }

        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 5px 0;
            border-bottom: 1px solid rgba(255, 255, 255, .03);
            font-size: .8rem;
            flex-wrap: wrap;
            gap: 8px;
        }

        .info-row:last-child {
            border: none;
        }

        .info-key {
            opacity: .5;
        }

        .info-val {
            text-align: right;
            word-break: break-word;
            max-width: 70%;
        }

        .tbl {
            width: 100%;
            border-collapse: collapse;
            font-size: .78rem;
        }

        .tbl th {
            background: var(--bg3);
            padding: 8px 10px;
            text-align: left;
            border-bottom: 1px solid var(--c3);
            font-size: .7rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            opacity: .7;
            position: sticky;
            top: 0;
        }

        .tbl td {
            padding: 7px 10px;
            border-bottom: 1px solid var(--border);
            max-width: 200px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .tbl tr:hover {
            background: rgba(0, 255, 65, .03);
        }

        .tbl .col-cpu {
            color: var(--red);
        }

        .tbl .col-mem {
            color: var(--orange);
        }

        .tbl .col-pid {
            color: var(--cyan);
        }

        .btn {
            background: transparent;
            border: 1px solid var(--c3);
            color: var(--c1);
            padding: 5px 12px;
            font-family: var(--font);
            font-size: .72rem;
            cursor: pointer;
            transition: all .2s;
            text-transform: uppercase;
        }

        .btn:hover {
            background: var(--c1);
            color: #000;
            box-shadow: 0 0 10px rgba(0, 255, 65, .3);
        }

        .btn:disabled{opacity:.45;cursor:not-allowed;background:transparent;color:var(--muted);box-shadow:none}

        .btn-sm {
            padding: 3px 8px;
            font-size: .68rem;
        }

        .btn-danger {
            border-color: var(--red);
            color: var(--red);
        }

        .btn-danger:hover {
            background: var(--red);
            color: #000;
        }

        .btn-cyan {
            border-color: var(--cyan);
            color: var(--cyan);
        }

        .btn-cyan:hover {
            background: var(--cyan);
            color: #000;
        }

        .qcmd-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(130px, 1fr));
            gap: 6px;
        }

        .iface {
            padding: 8px 12px;
            margin: 4px 0;
            background: var(--bg3);
            border-left: 3px solid var(--c1);
            display: flex;
            justify-content: space-between;
            font-size: .8rem;
            transition: all .2s;
            flex-wrap: wrap;
        }

        .iface:hover {
            border-left-color: var(--cyan);
            background: var(--bg4);
        }

        .network-hero{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;padding:20px;border:1px solid var(--border);border-radius:14px;background:linear-gradient(135deg,rgba(20,31,48,.98),rgba(7,11,18,.96));margin-bottom:12px}
        .network-heading{max-width:760px}.network-heading h1{font-size:clamp(1.35rem,3vw,2.15rem);margin:4px 0 8px;color:var(--text)}.network-heading p{color:var(--muted);line-height:1.55;margin:0}
        .network-actions{display:flex;gap:8px;flex-wrap:wrap;justify-content:flex-end;align-items:flex-end}.network-scope-select-wrap{display:grid;gap:4px;min-width:min(290px,100%)}.network-scope-select-wrap label{font:650 .64rem var(--mono);color:var(--muted);letter-spacing:.04em;text-transform:uppercase}.network-scope-select{min-height:42px;max-width:340px;border:1px solid var(--border);border-radius:8px;padding:0 34px 0 10px;background:var(--bg3);color:var(--text);font:650 .72rem var(--mono)}.network-scope-select:focus-visible{outline:2px solid var(--c1);outline-offset:2px}.network-primary-btn,.network-secondary-btn{min-height:42px;border-radius:8px;padding:0 14px;font:750 .74rem var(--font);cursor:pointer}.network-primary-btn{border:0;background:linear-gradient(135deg,var(--c1),var(--cyan));color:#04111c}.network-secondary-btn{border:1px solid var(--border);background:var(--bg3);color:var(--text)}.network-primary-btn:disabled,.network-secondary-btn:disabled,.network-scope-select:disabled{opacity:.48;cursor:not-allowed}
        .network-status{display:flex;align-items:center;gap:9px;padding:10px 13px;border:1px solid rgba(56,189,248,.28);border-radius:9px;background:rgba(56,189,248,.07);color:#bae6fd;font-size:.76rem;margin:10px 0}.network-status::before{content:"";width:8px;height:8px;border-radius:50%;background:var(--cyan);flex:none}.network-status.active::before,.network-status.partial::before{background:var(--orange)}.network-status.complete::before{background:var(--green)}.network-status.error{border-color:rgba(251,113,133,.42);background:rgba(251,113,133,.08);color:#fecdd3}.network-status.error::before{background:var(--red)}
        .network-summary{display:grid;grid-template-columns:repeat(8,minmax(82px,1fr));gap:8px;margin:12px 0}.network-stat{border:1px solid var(--border);border-radius:10px;background:var(--bg2);padding:12px}.network-stat strong{display:block;color:var(--text);font-size:1.3rem}.network-stat span{display:block;margin-top:2px;color:var(--muted);font-size:.64rem;text-transform:uppercase;letter-spacing:.07em}
        .network-scope-bar{display:flex;gap:7px;flex-wrap:wrap;margin:10px 0}.network-scope-pill{padding:7px 10px;border:1px solid rgba(52,211,153,.3);border-radius:999px;background:rgba(52,211,153,.07);color:#a7f3d0;font: .68rem var(--mono)}
        .network-layout{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:12px;margin-top:12px}.network-map-card,.network-detail-card,.network-section-card{border:1px solid var(--border);border-radius:12px;background:var(--bg2);min-width:0}.network-map-head,.network-section-head{padding:13px 15px;border-bottom:1px solid var(--border)}.network-map-head h2,.network-section-head h2{font-size:.92rem;margin:0}.network-map-head p,.network-section-head p{font-size:.7rem;color:var(--muted);margin:5px 0 0;line-height:1.45}
        .network-canvas{height:620px;position:relative;overflow:hidden;background:radial-gradient(circle at center,rgba(56,189,248,.09),transparent 48%),linear-gradient(rgba(37,51,74,.2) 1px,transparent 1px),linear-gradient(90deg,rgba(37,51,74,.2) 1px,transparent 1px);background-size:auto,36px 36px,36px 36px}.network-links,.network-node-layer{position:absolute;inset:0;width:100%;height:100%}.network-links{pointer-events:none}.network-link{stroke:#33445e;stroke-width:1.5;vector-effect:non-scaling-stroke}.network-link.gateway{stroke:#fbbf24;stroke-dasharray:6 4}.network-link.responded{stroke:#34d399}.network-link.interface{stroke:#38bdf8;stroke-width:2}
        .network-node{position:absolute;transform:translate(-50%,-50%);border:1px solid var(--border);background:#101b2b;color:var(--text);box-shadow:0 8px 20px rgba(0,0,0,.3);font-family:var(--font);cursor:pointer;z-index:2}.network-node:focus-visible{outline:3px solid var(--cyan);outline-offset:3px}.network-node[aria-pressed="true"]{border-color:var(--cyan);box-shadow:0 0 0 3px rgba(56,189,248,.18)}.network-node.local{width:116px;min-height:70px;border-radius:16px;border-color:rgba(56,189,248,.7);background:linear-gradient(145deg,#13243a,#0b1421);font-weight:850}.network-node.interface{width:104px;min-height:54px;border-radius:12px;border-color:rgba(103,232,249,.48)}.network-node.host{width:44px;height:44px;border:0;border-radius:50%;padding:0;background:transparent;box-shadow:none}.network-node.host::before{content:"";position:absolute;left:50%;top:50%;width:14px;height:14px;transform:translate(-50%,-50%);border-radius:50%;border:1px solid #60728d;background:#25344a;box-shadow:0 4px 10px rgba(0,0,0,.35)}.network-node.host.responded::before{background:#34d399;border-color:#a7f3d0}.network-node.host.gateway::before{width:25px;height:25px;border-radius:7px;transform:translate(-50%,-50%) rotate(45deg);background:#fbbf24;border-color:#fde68a}.network-node.host .network-node-sub{display:none}
        .network-node-label{display:block;font-size:.7rem;line-height:1.15;overflow-wrap:anywhere}.network-node-sub{display:block;color:var(--muted);font: .58rem var(--mono);margin-top:3px}.network-node.host .network-node-label{position:absolute;left:50%;top:38px;transform:translateX(-50%);display:none;max-width:150px;overflow:hidden;text-overflow:ellipsis;background:#07101c;color:var(--text);border:1px solid var(--border);border-radius:6px;padding:4px 6px;white-space:nowrap;z-index:5}.network-node.host:hover .network-node-label,.network-node.host:focus-visible .network-node-label,.network-node.host[aria-pressed="true"] .network-node-label{display:block}.network-map-overflow{position:absolute;left:50%;bottom:12px;transform:translateX(-50%);padding:6px 10px;border-radius:999px;background:rgba(7,11,18,.9);border:1px solid var(--border);color:var(--muted);font-size:.66rem;z-index:3}
        .network-detail-card{padding:16px;align-self:stretch}.network-detail-card h2{font-size:1rem;margin:0 0 5px}.network-detail-kind{color:var(--cyan);font:700 .65rem var(--mono);text-transform:uppercase;letter-spacing:.09em;margin-bottom:13px}.network-detail-row{display:grid;grid-template-columns:92px minmax(0,1fr);gap:8px;padding:7px 0;border-bottom:1px solid var(--border);font-size:.72rem}.network-detail-row span:first-child{color:var(--muted)}.network-detail-row span:last-child{color:var(--text);overflow-wrap:anywhere;text-align:right}.network-detail-note{margin-top:13px;color:var(--muted);font-size:.69rem;line-height:1.5}
        .network-interface-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(245px,1fr));gap:9px;padding:12px}.network-interface-card{border:1px solid var(--border);border-radius:9px;background:rgba(255,255,255,.018);padding:12px}.network-interface-title{display:flex;justify-content:space-between;gap:8px;align-items:center;margin-bottom:9px}.network-interface-title strong{font-size:.84rem}.network-state-pill{padding:3px 7px;border-radius:999px;border:1px solid var(--border);font-size:.61rem;text-transform:uppercase;color:var(--muted)}.network-state-pill.up{color:#a7f3d0;border-color:rgba(52,211,153,.35)}.network-address{font: .68rem/1.5 var(--mono);overflow-wrap:anywhere;color:#cbd5e1}.network-interface-meta{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px;color:var(--muted);font-size:.63rem}
        .network-sections{display:grid;gap:12px;margin-top:12px}.network-table-wrap{overflow:auto;max-height:420px}.network-table{width:100%;border-collapse:collapse;font-size:.72rem}.network-table caption{text-align:left;padding:10px 14px;color:var(--muted);font-size:.68rem}.network-table th,.network-table td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);white-space:nowrap}.network-table th{position:sticky;top:0;background:var(--bg3);z-index:1;color:var(--muted);font-size:.63rem;text-transform:uppercase;letter-spacing:.06em}.network-table td{color:#dbe8f8}.network-table tr:hover td{background:rgba(56,189,248,.035)}.network-table-filter-label{display:block;margin:12px 12px 0;color:var(--muted);font-size:.72rem;font-weight:750}.network-table-search{margin:7px 12px 12px;width:calc(100% - 24px);min-height:40px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--text);padding:0 11px}.network-warning-list{display:grid;gap:6px;margin:10px 0}.network-warning{padding:8px 11px;border-left:3px solid var(--orange);background:rgba(251,191,36,.06);color:#fde68a;font-size:.7rem;line-height:1.45}
        .network-legend{display:flex;gap:13px;flex-wrap:wrap;padding:10px 15px;border-top:1px solid var(--border);color:var(--muted);font-size:.65rem}.network-legend span{display:inline-flex;align-items:center;gap:5px}.network-legend i{width:9px;height:9px;border-radius:50%;background:#60728d}.network-legend .legend-live{background:#34d399}.network-legend .legend-gateway{background:#fbbf24;border-radius:2px}.network-legend .legend-interface{background:#38bdf8}

        .disk-bar-bg {
            background: var(--bg);
            border: 1px solid var(--border);
            height: 18px;
            border-radius: 2px;
            overflow: hidden;
            margin: 3px 0;
        }

        .disk-bar-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--c3), var(--c1));
            transition: width .5s;
            box-shadow: 0 0 8px rgba(0, 255, 65, .3);
        }

        .disk-bar-fill.warn {
            background: linear-gradient(90deg, var(--orange), #ff6600);
        }

        .disk-bar-fill.crit {
            background: linear-gradient(90deg, var(--red), #cc0000);
        }

        .fb-path {
            background: var(--bg);
            padding: 8px 12px;
            margin-bottom: 10px;
            border: 1px solid var(--border);
            font-size: .8rem;
            display: flex;
            align-items: center;
            gap: 8px;
            flex-wrap: wrap;
        }

        .fb-path input {
            flex: 1;
            background: transparent;
            border: none;
            color: var(--c1);
            font-family: var(--font);
            font-size: .8rem;
            outline: none;
            min-width: 120px;
        }

        .fb-item {
            display: flex;
            align-items: center;
            padding: 6px 10px;
            border-bottom: 1px solid var(--border);
            font-size: .78rem;
            cursor: pointer;
            transition: all .2s;
            gap: 10px;
            flex-wrap: wrap;
        }

        .fb-item:hover {
            background: rgba(0, 255, 65, .05);
        }

        .fb-item.dir {
            color: var(--cyan);
        }

        .fb-item .fb-name {
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
        }

        .fb-item .fb-size {
            width: 70px;
            text-align: right;
            opacity: .5;
        }

        .fb-item .fb-perms {
            width: 50px;
            opacity: .4;
            font-size: .7rem;
        }

        .fb-item .fb-date {
            width: 120px;
            opacity: .4;
        }

        .file-viewer {
            background: #000;
            color: var(--c1);
            padding: 15px;
            font-size: .8rem;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 60vh;
            overflow-y: auto;
            border: 1px solid var(--border);
            position: relative;
        }

        .file-viewer .line-num {
            color: var(--c3);
            opacity: .4;
            display: inline-block;
            width: 40px;
            text-align: right;
            margin-right: 10px;
            user-select: none;
        }

        .log-viewer {
            background: #000;
            color: var(--c2);
            padding: 12px;
            font-size: .78rem;
            white-space: pre-wrap;
            word-break: break-all;
            max-height: 500px;
            overflow-y: auto;
            border: 1px solid var(--border);
        }

        .log-tabs {
            display: flex;
            gap: 4px;
            margin-bottom: 10px;
            flex-wrap: wrap;
        }

        .log-tab {
            background: transparent;
            border: 1px solid var(--border);
            color: var(--c3);
            padding: 5px 12px;
            font-family: var(--font);
            font-size: .7rem;
            cursor: pointer;
            transition: all .2s;
        }

        .log-tab.active {
            border-color: var(--c1);
            color: var(--c1);
            text-shadow: 0 0 5px var(--c1);
        }

        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, .9);
            z-index: 3000;
            display: none;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }

        .modal-overlay.active {
            display: flex;
        }

        .modal-box {
            background: var(--bg2);
            border: 1px solid var(--c1);
            width: 100%;
            max-width: 900px;
            max-height: 80vh;
            display: flex;
            flex-direction: column;
            border-radius: 4px;
            box-shadow: 0 0 30px rgba(0, 255, 65, .2);
        }

        .modal-box-head {
            background: var(--bg3);
            padding: 10px 16px;
            border-bottom: 1px solid var(--c3);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .modal-box-body {
            flex: 1;
            overflow-y: auto;
            padding: 0;
        }

        .cmd-output {
            background: #000;
            color: var(--c1);
            padding: 16px;
            font-size: .85rem;
            white-space: pre-wrap;
            word-break: break-all;
            min-height: 200px;
        }

        .error-box,.notice-box{padding:16px 18px;border-radius:10px;border:1px solid rgba(251,113,133,.45);background:rgba(251,113,133,.08);color:#fecdd3}
        .notice-box{border-color:rgba(56,189,248,.4);background:rgba(56,189,248,.08);color:#bae6fd}
        .audit-intro{max-width:980px;margin:22px auto;padding:28px;border:1px solid var(--border);border-radius:16px;background:linear-gradient(145deg,rgba(20,31,48,.95),rgba(9,15,25,.95));box-shadow:0 24px 60px rgba(0,0,0,.28)}
        .audit-kicker{font:700 .72rem var(--mono);letter-spacing:.16em;color:var(--cyan);text-transform:uppercase}
        .audit-intro h1{font-size:clamp(1.7rem,4vw,3rem);line-height:1.08;margin:10px 0;color:var(--text)}
        .audit-intro p{color:var(--muted);max-width:760px;line-height:1.65}
        .audit-actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:20px}
        .audit-run-btn{min-height:44px;padding:0 18px;border:0;border-radius:9px;background:linear-gradient(135deg,var(--c1),var(--cyan));color:#04111c;font-weight:850;cursor:pointer}
        .audit-run-btn:disabled{opacity:.55;cursor:wait}
        .audit-outline-btn{min-height:42px;padding:0 15px;border:1px solid var(--border);border-radius:9px;background:var(--bg3);color:var(--text);font-weight:700;cursor:pointer}
        .audit-scope{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:9px;margin-top:22px}
        .audit-scope span{padding:11px 12px;border:1px solid var(--border);background:rgba(255,255,255,.02);border-radius:8px;color:var(--muted);font-size:.78rem}
        .audit-progress{max-width:760px;margin:70px auto;text-align:center}
        .audit-progress-ring{width:58px;height:58px;margin:0 auto 18px;border:4px solid var(--border);border-top-color:var(--c1);border-radius:50%;animation:auditSpin .85s linear infinite}
        @keyframes auditSpin{to{transform:rotate(360deg)}}
        .audit-progress h2{margin-bottom:8px}.audit-progress p{color:var(--muted)}
        .audit-hero{display:grid;grid-template-columns:minmax(190px,260px) 1fr;gap:18px;margin-bottom:16px}
        .score-card,.audit-summary-card{border:1px solid var(--border);border-radius:14px;background:var(--bg2);padding:20px}
        .score-card{display:flex;align-items:center;gap:18px}
        .score-ring{--score:0;width:112px;height:112px;border-radius:50%;background:conic-gradient(var(--score-color,var(--c1)) calc(var(--score)*1%),var(--border) 0);display:grid;place-items:center;position:relative;flex:none}
        .score-ring::before{content:"";position:absolute;inset:10px;background:var(--bg2);border-radius:50%}
        .score-value{position:relative;font-size:1.85rem;font-weight:900;color:var(--text)}
        .score-copy strong{display:block;font-size:1.25rem}.score-copy span{display:block;color:var(--muted);font-size:.75rem;margin-top:4px}
        .audit-summary-card h1{font-size:1.35rem;margin-bottom:7px}.audit-summary-card>p{color:var(--muted);line-height:1.5}
        .audit-meta{display:flex;gap:12px;flex-wrap:wrap;margin-top:14px;color:var(--muted);font: .72rem var(--mono)}
        .audit-metrics{display:grid;grid-template-columns:repeat(6,minmax(110px,1fr));gap:9px;margin:14px 0}
        .audit-metric{padding:14px;border-radius:10px;border:1px solid var(--border);background:var(--bg2)}
        .audit-metric strong{display:block;font-size:1.45rem;color:var(--text)}.audit-metric span{font-size:.69rem;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}
        .audit-metric.critical{border-top:3px solid #fb7185}.audit-metric.high{border-top:3px solid #f97316}.audit-metric.medium{border-top:3px solid #fbbf24}.audit-metric.low{border-top:3px solid #38bdf8}.audit-metric.pass{border-top:3px solid #34d399}.audit-metric.skipped{border-top:3px solid #94a3b8}
        .audit-toolbar{display:grid;grid-template-columns:minmax(220px,1fr) repeat(3,minmax(135px,190px));gap:9px;padding:12px;border:1px solid var(--border);border-radius:11px;background:var(--bg2);margin:14px 0}
        .audit-toolbar input,.audit-toolbar select{width:100%;min-height:42px;border:1px solid var(--border);border-radius:8px;background:var(--bg);color:var(--text);padding:0 11px;font-family:var(--font)}
        .audit-result-count{margin:10px 2px;color:var(--muted);font-size:.78rem}
        .finding-list{display:grid;gap:9px}
        .finding{border:1px solid var(--border);border-left:4px solid var(--muted);border-radius:10px;background:var(--bg2);overflow:hidden}
        .finding[data-severity="critical"]{border-left-color:#fb7185}.finding[data-severity="high"]{border-left-color:#f97316}.finding[data-severity="medium"]{border-left-color:#fbbf24}.finding[data-severity="low"]{border-left-color:#38bdf8}.finding[data-status="pass"]{border-left-color:#34d399}
        .finding summary{list-style:none;cursor:pointer;padding:14px 16px;display:grid;grid-template-columns:95px 1fr auto;gap:12px;align-items:center}.finding summary::-webkit-details-marker{display:none}
        .finding-title{font-weight:780;color:var(--text)}.finding-id{font: .68rem var(--mono);color:var(--muted)}
        .severity-pill{display:inline-flex;justify-content:center;padding:5px 8px;border-radius:999px;background:rgba(148,163,184,.12);font-size:.66rem;font-weight:850;text-transform:uppercase;letter-spacing:.05em}
        .finding-body{border-top:1px solid var(--border);padding:14px 16px;display:grid;grid-template-columns:1fr 1fr;gap:12px}.finding-body h4{font-size:.7rem;text-transform:uppercase;color:var(--muted);letter-spacing:.08em;margin-bottom:7px}.finding-body pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:11px;color:#cbd5e1;max-height:260px;overflow:auto;font: .72rem/1.55 var(--mono)}.finding-body p{color:#dbe8f8;line-height:1.55}
        .audit-data-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:18px}.audit-data-card{border:1px solid var(--border);border-radius:12px;background:var(--bg2);padding:15px;min-width:0}.audit-data-card h2{font-size:.95rem;margin-bottom:9px}.audit-data-card pre{font: .7rem/1.55 var(--mono);white-space:pre-wrap;word-break:break-word;color:#cbd5e1;max-height:280px;overflow:auto;background:var(--bg);padding:10px;border-radius:8px}
        .audit-account-table{width:100%;border-collapse:collapse;font-size:.74rem}.audit-account-table th,.audit-account-table td{padding:8px;border-bottom:1px solid var(--border);text-align:left}.audit-account-table th{color:var(--muted);font-size:.66rem;text-transform:uppercase}.audit-table-wrap{overflow:auto;max-height:350px}
        .audit-disclaimer{margin-top:14px;padding:11px 13px;border:1px solid rgba(56,189,248,.28);border-radius:8px;color:var(--muted);font-size:.74rem;line-height:1.5}

        /* ── Shell interactiva (estilo kitty): ventana contigua con paneles 1/2/4 ── */
        .shellkit-ws{display:flex;flex-direction:column;gap:8px;height:calc(100vh - 175px);min-height:360px}
        .shellkit-toolbar{display:flex;align-items:center;gap:7px;padding:8px 10px;border:1px solid var(--border);border-radius:11px;background:var(--bg2);flex-wrap:wrap}
        .shellkit-title{font-size:.7rem;font-weight:850;letter-spacing:.14em;color:var(--cyan)}
        .shellkit-msg{font:.66rem var(--mono);color:var(--muted);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:34%}
        .shellkit-spacer{flex:1}
        .shellkit-btn{background:rgba(148,163,184,.08);color:var(--text);border:1px solid var(--border);border-radius:8px;padding:6px 10px;font:600 .7rem var(--font);cursor:pointer;white-space:nowrap}
        .shellkit-btn:hover{background:rgba(56,189,248,.16);border-color:var(--c3);color:var(--cyan)}
        .shellkit-btn.danger:hover{background:rgba(251,113,133,.14);border-color:#fb7185;color:#fb7185}
        .shellkit-btn:disabled{opacity:.35;cursor:not-allowed}
        .shellkit-grid{flex:1;min-height:0;display:flex;border:1px solid var(--border);border-radius:11px;background:var(--bg);padding:6px}
        .shellkit-row{display:flex;flex:1 1 0;gap:6px;min-width:0;min-height:0}
        .shellkit-col{display:flex;flex-direction:column;flex:1 1 0;gap:6px;min-width:0;min-height:0}
        .shellkit-pane{flex:1 1 0;display:flex;flex-direction:column;min-width:0;min-height:0;border:1px solid var(--border);border-radius:9px;background:#04060c;overflow:hidden;cursor:text}
        .shellkit-pane.shellkit-active{border-color:var(--c3);box-shadow:0 0 0 1px rgba(56,189,248,.35),0 0 18px rgba(56,189,248,.12)}
        .shellkit-pane-head{display:flex;gap:8px;align-items:center;padding:5px 9px;background:rgba(148,163,184,.07);border-bottom:1px solid var(--border);font:.62rem var(--mono);color:var(--muted);white-space:nowrap}
        .shellkit-pane-head .shellkit-path{flex:1;overflow:hidden;text-overflow:ellipsis;color:#7dd3fc}
        .shellkit-pane-head .shellkit-num{color:var(--c3)}
        .shellkit-out{flex:1;min-height:0;overflow:auto;padding:8px 10px;font:.72rem/1.5 var(--mono);color:#cbd5e1;white-space:pre-wrap;word-break:break-word;scrollbar-width:thin}
        .shellkit-input-row{display:flex;align-items:center;gap:7px;padding:6px 10px;border-top:1px solid var(--border);background:rgba(0,0,0,.35)}
        .shellkit-prompt{font:.72rem var(--mono);color:var(--green);white-space:nowrap;flex:none;max-width:58%;overflow:hidden;text-overflow:ellipsis}
        .shellkit-input{flex:1;min-width:0;background:transparent;border:0;outline:0;color:var(--text);font:.72rem var(--mono);padding:3px 0}
        .shellkit-input:disabled{color:var(--muted)}
        .shellkit-hint{color:var(--muted);font-size:.66rem;text-align:center;padding:2px 0}

        @media print{.hud-header,.nav-bar,.audit-actions,.audit-toolbar{display:none!important}.main-content{padding:0}.finding{break-inside:avoid}body{background:#fff;color:#111}.score-card,.audit-summary-card,.finding,.audit-data-card{background:#fff;border-color:#bbb}.finding-title,.score-value,.score-copy strong,.audit-summary-card h1{color:#111}}

        @media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;animation-iteration-count:1!important;scroll-behavior:auto!important}}

        @media(max-width:980px){.network-layout{grid-template-columns:1fr}.network-detail-card{min-height:180px}.network-summary{grid-template-columns:repeat(4,1fr)}}

        @media(max-width:768px) {
            .hud-header {
                flex-direction: column;
                align-items: stretch
            }

            .hud-stats {
                justify-content: space-between
            }

            .nav-bar {
                padding: 6px 8px
            }

            .nav-btn {
                padding: 6px 10px;
                font-size: .7rem
            }

            .dash-grid,
            .dash-grid-wide {
                grid-template-columns: 1fr
            }

            .main-content {
                padding: 8px
            }

            .qcmd-grid {
                grid-template-columns: repeat(2, 1fr)
            }

            .tbl td,
            .tbl th {
                padding: 5px 6px;
                font-size: .7rem
            }

            .info-val {
                max-width: 100%;
                text-align: left
            }

            .audit-hero,.audit-data-grid{grid-template-columns:1fr}
            .audit-metrics{grid-template-columns:repeat(2,1fr)}
            .audit-toolbar{grid-template-columns:1fr 1fr}
            .finding summary{grid-template-columns:82px 1fr}.finding-id{grid-column:2}.finding-body{grid-template-columns:1fr}
            .network-hero{flex-direction:column}.network-actions{justify-content:flex-start}.network-summary{grid-template-columns:repeat(2,1fr)}
            .network-canvas{height:auto;min-height:0;padding:12px}.network-links{display:none}.network-node-layer{position:relative;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.network-node,.network-node.local,.network-node.interface,.network-node.host,.network-node.host.gateway{position:static!important;transform:none!important;width:auto;height:auto;min-height:48px;border:1px solid var(--border);border-radius:9px;padding:8px;text-align:left;background:#101b2b;color:var(--text);box-shadow:none}.network-node.host::before{position:static;display:inline-block;width:10px;height:10px;transform:none;margin-right:7px}.network-node.host.gateway::before{width:10px;height:10px;border-radius:2px;transform:rotate(45deg)}.network-node.host .network-node-label{display:inline;position:static;transform:none;background:transparent;border:0;padding:0;white-space:normal;color:var(--text)}.network-map-overflow{position:static;transform:none;text-align:center;margin-top:8px}.network-interface-grid{grid-template-columns:1fr}
        }

        @media(max-width:480px) {
            .hud-logo {
                font-size: 1rem
            }

            .hud-stats {
                gap: 6px
            }

            .nav-btn {
                padding: 5px 8px;
                font-size: .65rem
            }
            .network-node-layer{grid-template-columns:1fr}.network-detail-row{grid-template-columns:78px minmax(0,1fr)}
        }
    </style>
</head>

<body>
    <a class="skip-link" href="#main-content">Saltar al contenido</a>
    <header class="hud-header">
        <div class="hud-logo"><span class="pulse-dot"></span> SENTINELOPS <span
                style="font-size:.6rem;opacity:.55">CONTROL CENTER 6.0</span></div>
        <div class="hud-stats">
            <div class="hud-stat"><span class="hud-stat-val" id="hud-cpu">--</span><span
                    class="hud-stat-label">CPU</span></div>
            <div class="hud-stat"><span class="hud-stat-val" id="hud-mem">--</span><span
                    class="hud-stat-label">MEM</span></div>
            <div class="hud-stat"><span class="hud-stat-val"
                    id="hud-host"><?php echo htmlspecialchars($SI['host']); ?></span><span
                    class="hud-stat-label">HOST</span></div>
            <div class="hud-stat"><span class="hud-stat-val"
                    id="hud-user"><?php echo htmlspecialchars(isset($_SESSION['principal']) ? $_SESSION['principal'] : $SI['user']); ?></span><span
                    class="hud-stat-label">ACTOR</span></div>
            <div class="hud-stat"><span class="hud-clock" id="hud-clock">--:--:--</span><span
                    class="hud-stat-label">TIME</span></div>
            <span class="capability-badge <?php echo (!session_can_capability('shell') && !session_can_capability('file_write') && !session_can_capability('process_control')) ? 'safe' : ''; ?>">
                <?php echo (!session_can_capability('shell') && !session_can_capability('file_write') && !session_can_capability('process_control')) ? '● MODO PROTEGIDO' : '▲ CAPACIDADES ELEVADAS'; ?>
            </span>
            <button type="button" class="header-audit" id="quickAuditBtn">Ejecutar auditoría</button>
            <form method="POST" action="<?php echo htmlspecialchars(SELF_URL); ?>" style="display:inline;">
                <input type="hidden" name="csrf_token" value="<?php echo csrf_token(); ?>">
                <input type="hidden" name="logout" value="1">
                <button type="submit" class="btn-logout">Cerrar sesión</button>
            </form>
        </div>
    </header>

    <nav class="nav-bar" aria-label="Módulos del panel">
        <button class="nav-btn active" data-section="dashboard">Resumen</button>
        <button class="nav-btn audit-nav" data-section="audit">Escudo · Auditoría</button>
        <button class="nav-btn" data-section="users">Cuentas</button>
        <button class="nav-btn" data-section="network">Red · Mapa</button>
        <button class="nav-btn" data-section="processes">Procesos</button>
        <button class="nav-btn" data-section="disks">Discos</button>
        <?php if (session_can_capability('file_read')): ?>
        <button class="nav-btn" data-section="files">Archivos</button>
        <?php endif; ?>
        <?php if (session_can_capability('raw_observability')): ?>
        <button class="nav-btn" data-section="logs">Registros</button>
        <?php endif; ?>
        <button class="nav-btn" data-section="services">Servicios</button>
        <button class="nav-btn" data-section="centos">Plataforma</button>
        <?php if (session_can_capability('raw_observability')): ?>
        <button class="nav-btn" data-section="env">Entorno seguro</button>
        <?php endif; ?>
        <?php if (session_can_capability('shell')): ?>
        <button class="nav-btn" data-section="recon">Comandos</button>
        <button class="nav-btn" data-section="shellkit">Shell interactiva</button>
        <button class="nav-btn" id="terminalBtn">Nueva terminal</button>
        <?php endif; ?>
    </nav>

    <main class="main-content" id="main-content" aria-busy="false"></main>

    <script nonce="<?php echo htmlspecialchars($cspNonce, ENT_QUOTES, 'UTF-8'); ?>">
        const API = window.location.pathname;
        let currentSection = 'dashboard';
        let refreshTimer = null;
        let currentPath = <?php echo json_encode(ALLOWED_BASE_PATH, JSON_UNESCAPED_SLASHES); ?>;
        let csrfToken = <?php echo json_encode(csrf_token()); ?>;
        const capabilities = <?php echo json_encode(array('shell' => session_can_capability('shell'), 'fileWrite' => session_can_capability('file_write'), 'processControl' => session_can_capability('process_control'), 'networkDiscovery' => session_can_capability('network_discovery'), 'fileRead' => session_can_capability('file_read'), 'rawObservability' => session_can_capability('raw_observability'), 'role' => isset($_SESSION['role']) ? $_SESSION['role'] : 'admin')); ?>;
        let auditState = { report: null, running: false };
        let networkState = { data: null, connections: [], loading: false, scanning: false, request: 0, selected: null, selectedScope: null };

        function escapeHtml(unsafe) {
            if (unsafe === undefined || unsafe === null) return '';
            return unsafe
                .toString()
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#039;");
        }

        // Helper: crear FormData con CSRF token incluido
        function createSecureFormData(data = {}) {
            const fd = new FormData();
            fd.append('csrf_token', csrfToken);
            for (const [key, val] of Object.entries(data)) {
                fd.append(key, val);
            }
            return fd;
        }

        async function apiFetch(url, options = {}) {
            const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store', ...options });
            let data = null;
            try { data = await response.json(); } catch (error) { data = { error: 'Respuesta inválida del servidor' }; }
            if (response.status === 401) {
                window.location.reload();
                throw new Error('La sesión expiró');
            }
            if (!response.ok) {
                const requestError = new Error(data && data.error ? data.error : `Error HTTP ${response.status}`);
                requestError.status = response.status;
                requestError.retryAfter = Math.max(0, Number(data?.retry_after) || 0);
                throw requestError;
            }
            return data;
        }

        function makeElement(tag, className, text) {
            const element = document.createElement(tag);
            if (className) element.className = className;
            if (text !== undefined && text !== null) element.textContent = String(text);
            return element;
        }

        function openNewTerminal() {
            const terminalWindow = window.open(API + '?terminal=1', '_blank', 'noopener,width=800,height=600,resizable=yes,scrollbars=yes');
            if (terminalWindow) terminalWindow.opener = null;
        }

        function showLoading() {
            const main = document.querySelector('.main-content');
            main.setAttribute('aria-busy', 'true');
            main.innerHTML = '<div class="audit-progress"><div class="audit-progress-ring"></div><h2>Cargando módulo</h2><p>Consultando el estado del host…</p></div>';
        }

        async function loadSection(section) {
            if (refreshTimer) clearInterval(refreshTimer);
            if (section !== 'shellkit') shellkitCleanup();
            currentSection = section;
            setActiveBtn(section);
            showLoading();

            try {
                if (section === 'dashboard') {
                    await updateDashboard();
                    if (currentSection === 'dashboard') {
                        refreshTimer = setInterval(updateDashboard, 5000);
                    }
                } else if (section === 'audit') {
                    loadAuditLanding();
                } else if (section === 'processes') {
                    await loadProcesses();
                } else if (section === 'network') {
                    await loadNetworkView();
                } else if (section === 'disks') {
                    await loadDisks();
                } else if (section === 'files') {
                    await loadFileBrowser(currentPath);
                } else if (section === 'logs') {
                    await loadLogs('messages');
                } else if (section === 'users') {
                    await loadUsers();
                } else if (section === 'services') {
                    await loadServices();
                } else if (section === 'centos') {
                    await loadCentos();
                } else if (section === 'env') {
                    await loadEnv();
                } else if (section === 'recon') {
                    if (capabilities.shell) await loadRecon(); else throw new Error('La ejecución de comandos está deshabilitada');
                } else if (section === 'shellkit') {
                    if (capabilities.shell) await loadInteractiveShell(); else throw new Error('La shell interactiva está deshabilitada');
                }
            } catch (e) {
                const main = document.querySelector('.main-content');
                main.replaceChildren(makeElement('div', 'error-box', `No se pudo cargar el módulo: ${e.message}`));
            } finally {
                document.querySelector('.main-content').setAttribute('aria-busy', 'false');
            }
        }

        function setActiveBtn(section) {
            document.querySelectorAll('.nav-btn').forEach(btn => { btn.classList.remove('active'); btn.removeAttribute('aria-current'); });
            const btn = document.querySelector(`.nav-btn[data-section="${section}"]`);
            if (btn) { btn.classList.add('active'); btn.setAttribute('aria-current', 'page'); }
        }

        async function updateDashboard() {
            try {
                const [data, se, ver, fail] = await Promise.all([
                    apiFetch(`${API}?api=sysinfo`),
                    apiFetch(`${API}?api=selinux`),
                    apiFetch(`${API}?api=centos_version`),
                    apiFetch(`${API}?api=failed_services`)
                ]);
                if (currentSection !== 'dashboard') return;
                document.getElementById('hud-cpu').innerText = data.cpu.usage + '%';
                document.getElementById('hud-mem').innerText = data.mem.pct + '%';

                const loadAvg = data.cpu.load.map(l => l.toFixed(2)).join(', ');
                const gpuInfo = data.gpu.name !== 'No GPU' ? `<br>GPU: ${escapeHtml(data.gpu.name)} (${Number(data.gpu.usage)}% @ ${Number(data.gpu.temp)}C)` : '';
                const interfaces = data.net.map(n => `<div class="iface"><span>${escapeHtml(n.n)}${n.family ? ` · ${escapeHtml(n.family)}` : ''}${n.state ? ` · ${escapeHtml(n.state)}` : ''}</span><span>${escapeHtml(n.ip)}${n.prefix !== null && n.prefix !== undefined && Number.isInteger(Number(n.prefix)) ? `/${Number(n.prefix)}` : ''}</span></div>`).join('');
                const disks = data.disks.map(d => `<div><span>${escapeHtml(d.dev)} (${escapeHtml(d.mount)})</span><div class="disk-bar-bg"><div class="disk-bar-fill ${d.pct > 90 ? 'crit' : (d.pct > 75 ? 'warn' : '')}" style="width:${Math.max(0, Math.min(100, Number(d.pct) || 0))}%"></div></div><span>${escapeHtml(d.size)} usado ${Number(d.pct)}%</span></div>`).join('');
                const seColor = se.enforce === 'Enforcing' ? '#34d399' : (se.enforce === 'Permissive' ? '#fbbf24' : '#fb7185');
                const failLines = (fail.data || '').split('\\n').filter(l => l.includes('failed')).length;

                document.querySelector('.main-content').innerHTML = `
                    <div style="margin-bottom:12px;padding:10px 14px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
                        <span style="color:var(--orange);font-weight:bold;">[CENTOS] ${escapeHtml(ver.data || data.os)}</span>
                        <span style="font-size:.8rem;">SELinux: <span style="color:${seColor};font-weight:bold;">${escapeHtml(se.enforce)}</span> | Failed Units: <span style="color:${failLines > 0 ? 'var(--red)' : 'var(--c1)'};">${failLines}</span></span>
                    </div>
                    <div class="dash-grid">
                        <div class="panel">
                            <div class="panel-head"><div class="panel-title">[#] SYSTEM LOAD</div></div>
                            <div class="panel-body">
                                <div class="gauge-wrap"><div class="gauge-svg-wrap"><svg viewBox="0 0 36 36"><path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#25334a" stroke-width="3"/><path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831" fill="none" stroke="#38bdf8" stroke-width="3" stroke-dasharray="${data.cpu.usage}, 100"/></svg><div class="gauge-center-text"><div class="gauge-pct">${data.cpu.usage}%</div><div class="gauge-sub">CPU</div></div></div></div>
                                <div class="info-row"><span class="info-key">Load Average:</span><span class="info-val">${loadAvg}</span></div>
                                <div class="info-row"><span class="info-key">Modelo:</span><span class="info-val">${escapeHtml(data.cpu.model).substring(0, 80)}</span></div>
                                <div class="info-row"><span class="info-key">Cores:</span><span class="info-val">${data.cpu.cores}</span></div>
                                <div class="info-row"><span class="info-key">Frecuencia:</span><span class="info-val">${escapeHtml(data.cpu.freq)}</span></div>
                            </div>
                        </div>
                        <div class="panel">
                            <div class="panel-head"><div class="panel-title">[=] MEMORY & SWAP</div></div>
                            <div class="panel-body">
                                <div class="gauge-wrap"><div class="gauge-svg-wrap"><svg viewBox="0 0 36 36"><path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" fill="none" stroke="#25334a" stroke-width="3"/><path d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831" fill="none" stroke="#38bdf8" stroke-width="3" stroke-dasharray="${data.mem.pct}, 100"/></svg><div class="gauge-center-text"><div class="gauge-pct">${data.mem.pct}%</div><div class="gauge-sub">RAM</div></div></div></div>
                                <div class="info-row"><span class="info-key">Total RAM:</span><span class="info-val">${data.mem.total} MB</span></div>
                                <div class="info-row"><span class="info-key">Used RAM:</span><span class="info-val">${data.mem.used} MB</span></div>
                                <div class="info-row"><span class="info-key">Swap Used:</span><span class="info-val">${data.swap.used} MB (${data.swap.pct}%)</span></div>
                            </div>
                        </div>
                        <div class="panel">
                            <div class="panel-head"><div class="panel-title">[>] GPU & SYSTEM</div></div>
                            <div class="panel-body">
                                ${gpuInfo}
                                <div class="info-row"><span class="info-key">OS:</span><span class="info-val">${escapeHtml(data.os)}</span></div>
                                <div class="info-row"><span class="info-key">Kernel:</span><span class="info-val">${escapeHtml(data.kern)}</span></div>
                                <div class="info-row"><span class="info-key">Actividad:</span><span class="info-val">${escapeHtml(data.up)}</span></div>
                                <div class="info-row"><span class="info-key">Hostname:</span><span class="info-val">${escapeHtml(data.host)}</span></div>
                                <div class="info-row"><span class="info-key">Arquitectura:</span><span class="info-val">${escapeHtml(data.arch)}</span></div>
                                <div class="info-row"><span class="info-key">Privilegios:</span><span class="info-val" style="font-size:.7rem;">${escapeHtml(data.priv)}</span></div>
                            </div>
                        </div>
                    </div>
                    <div class="dash-grid-wide">
                        <div class="panel">
                            <div class="panel-head"><div class="panel-title">[~] NETWORK INTERFACES</div></div>
                            <div class="panel-body">${interfaces || 'No interfaces found'}</div>
                        </div>
                        <div class="panel">
                            <div class="panel-head"><div class="panel-title">[*] DISK USAGE</div></div>
                            <div class="panel-body">${disks || 'No disks found'}</div>
                        </div>
                    </div>
                `;
            } catch (e) { console.error(e); }
        }

        async function loadProcesses() {
            const data = await apiFetch(`${API}?api=processes&sort=cpu&count=30`);
            if (!data.length) {
                document.querySelector('.main-content').innerHTML = '<div class="error-box">[!] No processes data</div>';
                return;
            }
            let html = `<table class="tbl"><thead><tr><th>Usuario</th><th>PID</th><th>%CPU</th><th>%MEM</th><th>VSZ</th><th>RSS</th><th>Estado</th><th>Inicio</th><th>Tiempo</th><th>Comando</th><th></th></tr></thead><tbody>`;
            data.forEach(p => {
                html += `<tr>
                    <td>${escapeHtml(p.u)}</td>
                    <td class="col-pid">${p.pid}</td>
                    <td class="col-cpu">${p.cpu}</td>
                    <td class="col-mem">${p.mem}</td>
                    <td>${escapeHtml(p.vsz)}</td>
                    <td>${escapeHtml(p.rss)}</td>
                    <td>${escapeHtml(p.stat)}</td>
                    <td>${escapeHtml(p.start)}</td>
                    <td>${escapeHtml(p.time)}</td>
                    <td>${escapeHtml(p.cmd).substring(0, 60)}</td>
                    <td>${capabilities.processControl ? `<button class="btn btn-sm btn-danger kill-process-btn" data-pid="${Number(p.pid)}">Terminar</button>` : '<span class="muted">Solo lectura</span>'}</td>
                </tr>`;
            });
            html += `</tbody></table>`;
            document.querySelector('.main-content').innerHTML = html;
            document.querySelectorAll('.kill-process-btn').forEach(button => button.addEventListener('click', () => killProcess(Number(button.dataset.pid))));
        }

        window.killProcess = async function (pid) {
            if (!confirm(`Are you sure you want to kill process ${pid}?`)) return;
            try {
                const fd = createSecureFormData({ pid: pid });
                await apiFetch(`${API}?api=kill_process`, { method: 'POST', body: fd });
                loadProcesses();
            } catch (e) { alert('Error killing process'); }
        };

        function networkFormatBytes(value) {
            let bytes = Math.max(0, Number(value) || 0);
            const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
            let unit = 0;
            while (bytes >= 1024 && unit < units.length - 1) { bytes /= 1024; unit++; }
            return `${bytes >= 10 || unit === 0 ? Math.round(bytes) : bytes.toFixed(1)} ${units[unit]}`;
        }

        function networkHuman(value) {
            if (value === null || value === undefined || value === '') return '—';
            const labels = {
                up: 'activa', down: 'inactiva', unknown: 'desconocido', private: 'privada', public: 'pública', loopback: 'loopback', link_local: 'enlace local', shared_cgnat: 'CGNAT compartida', documentation: 'documentación', benchmark: 'pruebas', multicast: 'multicast', multicast_or_reserved: 'multicast/reservada',
                reachable: 'alcanzable', stale: 'en caché', delay: 'en espera', probe: 'sondeando', failed: 'fallido', incomplete: 'incompleto', permanent: 'permanente', reachable_or_cached: 'alcanzable/en caché', responded: 'respondió', observed: 'observado', gateway: 'gateway',
                local_interface: 'interfaz local', route_gateway: 'ruta de gateway', kernel_cache: 'caché del kernel', proc_arp: 'caché ARP', active_icmp: 'respuesta ICMP', ok: 'completa', partial: 'parcial', missing: 'ausente', denied: 'sin permiso', error: 'error', passive: 'pasivo', 'fping-icmp': 'fping · ICMP', 'ping-fallback': 'ping · fallback'
            };
            return String(value).split(',').map(part => labels[part.trim().toLowerCase()] || part.trim()).join(', ');
        }

        function networkReasonText(reason) {
            return ({
                disabled_by_policy: 'El descubrimiento ICMP está apagado. Para habilitarlo use PANEL_ENABLE_NETWORK_DISCOVERY=1 y una allowlist privada.',
                container_opt_in_required: 'PHP está dentro de un contenedor. El sondeo activo requiere PANEL_NETWORK_ALLOW_CONTAINER=1 para confirmar que este namespace es el alcance deseado.',
                allowlist_missing: 'Configure PANEL_NETWORK_ALLOWED_CIDRS con subredes privadas conectadas antes de habilitar el sondeo.',
                role_denied: 'Su rol puede consultar el inventario pasivo, pero no iniciar tráfico de descubrimiento.',
                no_eligible_networks: 'Ninguna ruta privada conectada coincide con la allowlist configurada.',
                recent_auth_required: 'Vuelva a iniciar sesión para sondear: la autorización activa dura 10 minutos.',
                tool_missing: 'No hay una herramienta ICMP segura disponible; instale fping o ping.',
                cooldown: 'El cooldown del descubrimiento está activo; el inventario pasivo sigue disponible.',
                ready: 'Descubrimiento activo disponible dentro de los alcances aprobados.'
            })[reason] || 'Estado de descubrimiento no disponible.';
        }

        function setNetworkStatus(message, kind = '') {
            const status = document.getElementById('networkStatus');
            if (!status) return;
            status.className = `network-status${kind ? ` ${kind}` : ''}`;
            status.textContent = message;
        }

        async function loadNetworkView() {
            if (networkState.loading || networkState.scanning) return;
            networkState.loading = true;
            const requestId = ++networkState.request;
            document.querySelectorAll('[data-network-refresh]').forEach(button => { button.disabled = true; });
            try {
                const mapPromise = apiFetch(`${API}?api=network_map`, { method: 'POST', body: createSecureFormData() });
                const connectionsPromise = capabilities.rawObservability ? apiFetch(`${API}?api=connections`).catch(() => []) : Promise.resolve([]);
                const data = await mapPromise;
                const connections = await connectionsPromise;
                if (currentSection !== 'network' || requestId !== networkState.request) return;
                const previousScope = networkState.selectedScope;
                networkState.data = data;
                networkState.connections = connections;
                networkState.selected = null;
                const eligibleScopes = data.eligible_networks || [];
                networkState.selectedScope = eligibleScopes.some(scope => scope.network_id === previousScope) ? previousScope : (eligibleScopes[0]?.network_id || null);
                networkState.loading = false;
                renderNetworkView(networkState.data, networkState.connections);
            } finally {
                networkState.loading = false;
                document.querySelectorAll('[data-network-refresh]').forEach(button => { button.disabled = false; });
            }
        }

        async function runNetworkDiscovery() {
            if (networkState.scanning || !networkState.data || !networkState.data.capabilities.active_enabled || !networkState.selectedScope) return;
            const scope = (networkState.data.eligible_networks || []).find(item => item.network_id === networkState.selectedScope);
            if (!scope) { setNetworkStatus('La subred seleccionada dejó de estar disponible; actualice el inventario.', 'error'); return; }
            const confirmed = window.confirm(`Se enviará como máximo un ping por dirección, sin puertos ni DNS, dentro de ${scope.cidr} por ${scope.interface} (${scope.planned_count}/${scope.candidate_count} objetivos presupuestados). ¿Continuar?`);
            if (!confirmed) return;
            networkState.scanning = true;
            networkState.request++;
            setNetworkStatus('Descubrimiento ICMP en curso dentro de las subredes autorizadas…', 'active');
            document.querySelectorAll('[data-network-discover]').forEach(button => { button.disabled = true; });
            document.querySelectorAll('[data-network-refresh]').forEach(button => { button.disabled = true; });
            try {
                const data = await apiFetch(`${API}?api=network_discover`, { method: 'POST', body: createSecureFormData({ network_id: scope.network_id }) });
                networkState.data = data;
                networkState.selected = null;
                networkState.selectedScope = data.discovery.network_id || scope.network_id;
                if (capabilities.rawObservability) {
                    try { networkState.connections = await apiFetch(`${API}?api=connections`); } catch (ignored) { networkState.connections = []; }
                }
                networkState.scanning = false;
                if (currentSection === 'network') renderNetworkView(data, networkState.connections);
            } catch (error) {
                if (error.retryAfter > 0 && networkState.data?.capabilities) {
                    networkState.data.capabilities.active_enabled = false;
                    networkState.data.capabilities.reason = 'cooldown';
                    networkState.data.capabilities.cooldown_remaining = error.retryAfter;
                }
                setNetworkStatus(`No se pudo completar el descubrimiento: ${error.message}${error.retryAfter > 0 ? ` · reintente en ${error.retryAfter} s` : ''}`, 'error');
            } finally {
                networkState.scanning = false;
                document.querySelectorAll('[data-network-discover]').forEach(button => { button.disabled = !networkState.data?.capabilities?.active_enabled || !networkState.selectedScope; });
                document.querySelectorAll('[data-network-refresh]').forEach(button => { button.disabled = false; });
            }
        }

        function networkDetailRow(label, value) {
            const row = makeElement('div', 'network-detail-row');
            row.append(makeElement('span', '', label), makeElement('span', '', value === null || value === undefined || value === '' ? '—' : value));
            return row;
        }

        function renderNetworkDetails(details, selection, data) {
            details.replaceChildren();
            let title = data.host.hostname || 'Host local';
            let kind = 'Host observado';
            const rows = [];
            if (!selection || selection.type === 'local') {
                kind = 'Núcleo del mapa';
                rows.push(['Namespace', data.namespace.inode], ['Entorno', data.namespace.container ? 'Contenedor / namespace aislado' : 'Host / no detectado'], ['Interfaces', data.summary.interfaces], ['Direcciones', data.summary.addresses], ['Rutas', data.summary.routes], ['Reglas de ruta', data.summary.routing_rules], ['Vecinos', data.summary.neighbors]);
            } else if (selection.type === 'interface') {
                const item = selection.item;
                title = item.name; kind = 'Interfaz de red';
                rows.push(['Estado', networkHuman(item.state)], ['Tipo', item.kind], ['Ifindex', item.ifindex], ['MAC', item.mac], ['MTU', item.mtu], ['Carrier', item.carrier ? 'activo' : 'no confirmado'], ['RX', networkFormatBytes(item.stats?.rx_bytes)], ['TX', networkFormatBytes(item.stats?.tx_bytes)], ['Direcciones', (item.addresses || []).map(address => address.cidr).join('\n') || 'Sin direcciones']);
            } else if (selection.type === 'host') {
                const item = selection.item;
                title = item.address; kind = item.is_gateway ? 'Puerta de enlace' : (item.responded ? 'Respondió a ICMP' : 'Vecino observado');
                rows.push(['Familia', item.family], ['Estado', networkHuman(item.state)], ['MAC', item.mac], ['Interfaces', (item.interfaces || []).join(', ')], ['Fuentes', (item.sources || []).map(networkHuman).join(', ')], ['Respuesta ICMP', item.responded ? 'sí' : 'no evaluada'], ['Latencia', item.latency_ms === null ? null : `${item.latency_ms} ms`]);
            }
            details.append(makeElement('h2', '', title), makeElement('div', 'network-detail-kind', kind));
            rows.forEach(([label, value]) => details.appendChild(networkDetailRow(label, value)));
            details.appendChild(makeElement('p', 'network-detail-note', 'Los nodos representan observaciones desde este servidor. Un vecino en caché puede no estar conectado ahora y la ausencia de ICMP no confirma que esté apagado.'));
        }

        function renderNetworkTopology(data, canvas, details) {
            const width = 1000, height = 620, center = { x: 500, y: 310 };
            const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
            svg.classList.add('network-links'); svg.setAttribute('viewBox', `0 0 ${width} ${height}`); svg.setAttribute('preserveAspectRatio', 'none'); svg.setAttribute('aria-hidden', 'true');
            const layer = makeElement('div', 'network-node-layer');
            const positions = new Map();
            const addLine = (from, to, type) => {
                const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
                line.setAttribute('x1', String(from.x)); line.setAttribute('y1', String(from.y)); line.setAttribute('x2', String(to.x)); line.setAttribute('y2', String(to.y));
                line.setAttribute('class', `network-link ${['gateway', 'responded', 'interface'].includes(type) ? type : ''}`); svg.appendChild(line);
            };
            const addNode = (type, item, point, label, sublabel, extraClass = '') => {
                const button = makeElement('button', `network-node ${type}${extraClass ? ` ${extraClass}` : ''}`);
                button.type = 'button'; button.style.left = `${Math.max(0, Math.min(100, point.x / width * 100))}%`; button.style.top = `${Math.max(0, Math.min(100, point.y / height * 100))}%`;
                button.append(makeElement('span', 'network-node-label', label), makeElement('span', 'network-node-sub', sublabel));
                const spokenType = type === 'local' ? 'host local' : (type === 'interface' ? 'interfaz' : (item.is_gateway ? 'gateway' : 'host observado'));
                button.setAttribute('aria-label', `${spokenType}: ${label}${sublabel ? `, ${sublabel}` : ''}`); button.setAttribute('aria-pressed', 'false'); button.setAttribute('aria-controls', 'networkNodeDetails'); button.dataset.networkNode = 'true';
                button.addEventListener('click', () => {
                    layer.querySelectorAll('[data-network-node]').forEach(node => node.setAttribute('aria-pressed', 'false'));
                    button.setAttribute('aria-pressed', 'true');
                    networkState.selected = { type, item }; renderNetworkDetails(details, networkState.selected, data);
                });
                layer.appendChild(button); return button;
            };

            const localButton = addNode('local', data.host, center, data.host.hostname || 'Host local', `${data.summary.interfaces} interfaz(es)`); localButton.setAttribute('aria-pressed', 'true');
            const allMapInterfaces = (data.interfaces || []).filter(item => item.name !== 'lo');
            const interfaces = allMapInterfaces.slice(0, 16);
            interfaces.forEach((item, index) => {
                const angle = (Math.PI * 2 * index / Math.max(1, interfaces.length)) - Math.PI / 2;
                const point = { x: center.x + Math.cos(angle) * 220, y: center.y + Math.sin(angle) * 155 };
                positions.set(item.name, point); addLine(center, point, 'interface');
                const primaryAddress = (item.addresses || []).find(address => address.family === 'ipv4') || (item.addresses || [])[0];
                addNode('interface', item, point, item.name, primaryAddress ? primaryAddress.cidr : networkHuman(item.state));
            });

            const visibleHosts = (data.hosts || []).filter(host => !host.is_self).sort((left, right) => Number(right.is_gateway) - Number(left.is_gateway) || Number(right.responded) - Number(left.responded)).slice(0, 32);
            visibleHosts.forEach((item, index) => {
                const angle = (Math.PI * 2 * index / Math.max(1, visibleHosts.length)) - Math.PI / 2;
                const point = { x: center.x + Math.cos(angle) * 405, y: center.y + Math.sin(angle) * 265 };
                const interfacePoint = (item.interfaces || []).map(name => positions.get(name)).find(Boolean) || center;
                addLine(interfacePoint, point, item.is_gateway ? 'gateway' : (item.responded ? 'responded' : 'host'));
                addNode('host', item, point, item.address, item.is_gateway ? 'gateway' : (item.responded ? 'ICMP' : networkHuman(item.state)), `${item.is_gateway ? 'gateway' : ''}${item.responded ? ' responded' : ''}`.trim());
            });
            canvas.append(svg, layer);
            const hiddenHosts = Math.max(0, (data.hosts || []).filter(host => !host.is_self).length - visibleHosts.length);
            const hiddenInterfaces = Math.max(0, allMapInterfaces.length - interfaces.length);
            if (hiddenHosts || hiddenInterfaces) canvas.appendChild(makeElement('div', 'network-map-overflow', `${hiddenHosts ? `+${hiddenHosts} host(s)` : ''}${hiddenHosts && hiddenInterfaces ? ' · ' : ''}${hiddenInterfaces ? `+${hiddenInterfaces} interfaz(es)` : ''} adicionales en las tablas`));
            renderNetworkDetails(details, null, data);
        }

        function createNetworkTable(captionText, headers, rows) {
            const wrap = makeElement('div', 'network-table-wrap');
            wrap.tabIndex = 0; wrap.setAttribute('role', 'region'); wrap.setAttribute('aria-label', captionText);
            const table = makeElement('table', 'network-table');
            table.appendChild(makeElement('caption', '', captionText));
            const head = document.createElement('thead'); const headRow = document.createElement('tr');
            headers.forEach(header => { const cell = makeElement('th', '', header); cell.scope = 'col'; headRow.appendChild(cell); }); head.appendChild(headRow); table.appendChild(head);
            const body = document.createElement('tbody');
            rows.forEach(values => { const row = document.createElement('tr'); values.forEach(value => row.appendChild(makeElement('td', '', value === null || value === undefined || value === '' ? '—' : value))); body.appendChild(row); });
            table.appendChild(body); wrap.appendChild(table); return wrap;
        }

        function createNetworkSection(title, description) {
            const card = makeElement('section', 'network-section-card'); const head = makeElement('div', 'network-section-head');
            head.append(makeElement('h2', '', title), makeElement('p', '', description)); card.appendChild(head); return card;
        }

        function renderNetworkView(data, connections = []) {
            if (currentSection !== 'network') return;
            const main = document.querySelector('.main-content'); main.replaceChildren();
            const hero = makeElement('section', 'network-hero');
            const heading = makeElement('div', 'network-heading'); heading.append(makeElement('div', 'audit-kicker', 'Topología lógica · observación local'), makeElement('h1', '', 'Mapa de red e interfaces'), makeElement('p', '', 'Detecta interfaces IPv4/IPv6, rutas, puertas de enlace y vecinos ARP/ND. El sondeo activo es independiente, no revisa puertos y nunca recibe objetivos arbitrarios desde el navegador.'));
            const actions = makeElement('div', 'network-actions');
            const scopes = data.eligible_networks || [];
            if (!networkState.selectedScope || !scopes.some(scope => scope.network_id === networkState.selectedScope)) networkState.selectedScope = scopes[0]?.network_id || null;
            const scopeWrap = makeElement('div', 'network-scope-select-wrap');
            const scopeLabel = makeElement('label', '', 'Subred autorizada para ICMP'); scopeLabel.htmlFor = 'networkScopeSelect';
            const scopeSelect = makeElement('select', 'network-scope-select'); scopeSelect.id = 'networkScopeSelect';
            if (!scopes.length) { const option = makeElement('option', '', 'Sin alcances elegibles'); option.value = ''; scopeSelect.appendChild(option); }
            scopes.forEach(scope => { const option = makeElement('option', '', `${scope.interface} · ${scope.cidr} · ${scope.planned_count}/${scope.candidate_count}`); option.value = scope.network_id; scopeSelect.appendChild(option); });
            scopeSelect.value = networkState.selectedScope || ''; scopeSelect.disabled = networkState.scanning || !scopes.length;
            scopeSelect.addEventListener('change', () => { networkState.selectedScope = scopeSelect.value || null; discover.disabled = networkState.scanning || !data.capabilities.active_enabled || !networkState.selectedScope; });
            scopeWrap.append(scopeLabel, scopeSelect);
            const refresh = makeElement('button', 'network-secondary-btn', 'Actualizar inventario'); refresh.type = 'button'; refresh.dataset.networkRefresh = 'true'; refresh.disabled = networkState.loading || networkState.scanning; refresh.addEventListener('click', async () => { setNetworkStatus('Actualizando datos pasivos…', 'active'); try { await loadNetworkView(); } catch (error) { setNetworkStatus(`Error al actualizar: ${error.message}`, 'error'); } });
            const discover = makeElement('button', 'network-primary-btn', networkState.scanning ? 'Sondeando…' : 'Sondear subred elegida (ICMP)'); discover.type = 'button'; discover.dataset.networkDiscover = 'true'; discover.disabled = networkState.scanning || !data.capabilities.active_enabled || !networkState.selectedScope; discover.addEventListener('click', runNetworkDiscovery);
            actions.append(scopeWrap, refresh, discover); hero.append(heading, actions); main.appendChild(hero);

            const observedAt = (() => { try { return new Intl.DateTimeFormat('es-PE', { dateStyle: 'medium', timeStyle: 'medium' }).format(new Date(data.generated_at)); } catch (ignored) { return data.generated_at; } })();
            const attempted = data.discovery.probes_attempted === null ? 'cantidad desconocida' : data.discovery.probes_attempted;
            const partialSources = (data.sources || []).filter(source => source.status !== 'ok');
            const coverageNote = partialSources.length ? ` Cobertura parcial: ${partialSources.map(source => source.id).join(', ')}.` : '';
            const statusMessage = data.discovery.active ? `Sondeo ${networkHuman(data.discovery.method)}: ${data.discovery.responded} respuesta(s), ${attempted} intento(s), ${data.discovery.duration_ms} ms${data.discovery.partial ? ' · resultado parcial' : ''}.` : `Inventario pasivo actualizado ${observedAt}. ${networkReasonText(data.capabilities.reason)}${coverageNote}`;
            const statusKind = data.discovery.active ? (data.discovery.partial ? 'partial' : 'complete') : (partialSources.length ? 'partial' : '');
            const status = makeElement('div', `network-status${statusKind ? ` ${statusKind}` : ''}`, statusMessage); status.id = 'networkStatus'; status.setAttribute('role', 'status'); status.setAttribute('aria-live', 'polite'); main.appendChild(status);

            const summary = makeElement('section', 'network-summary');
            [['Interfaces', data.summary.interfaces], ['Direcciones', data.summary.addresses], ['Rutas', data.summary.routes], ['Reglas de ruta', data.summary.routing_rules], ['Gateways', data.summary.gateways], ['Caché ARP/ND', data.summary.neighbors], ['Hosts vistos', data.summary.hosts_observed], ['Respondieron', data.summary.hosts_responded]].forEach(([label, value]) => { const stat = makeElement('div', 'network-stat'); stat.append(makeElement('strong', '', value), makeElement('span', '', label)); summary.appendChild(stat); }); main.appendChild(summary);

            const scopeBar = makeElement('div', 'network-scope-bar');
            (data.eligible_networks || []).forEach(scope => scopeBar.appendChild(makeElement('span', 'network-scope-pill', `${scope.interface} · ${scope.cidr} · ${scope.planned_count}/${scope.candidate_count} objetivos`)));
            if (!scopeBar.children.length) scopeBar.appendChild(makeElement('span', 'network-scope-pill', 'Sin subred activa autorizada · el mapa pasivo sigue disponible'));
            main.appendChild(scopeBar);
            const warnings = makeElement('div', 'network-warning-list'); (data.warnings || []).forEach(warning => warnings.appendChild(makeElement('div', 'network-warning', warning))); main.appendChild(warnings);

            const layout = makeElement('section', 'network-layout');
            const mapCard = makeElement('article', 'network-map-card'); const mapHead = makeElement('div', 'network-map-head'); mapHead.append(makeElement('h2', '', 'Topología observada'), makeElement('p', '', 'Seleccione un nodo para inspeccionarlo. Las líneas representan asociación lógica, no cableado físico ni alcance externo.')); mapCard.appendChild(mapHead);
            const canvas = makeElement('div', 'network-canvas'); const details = makeElement('aside', 'network-detail-card'); details.id = 'networkNodeDetails'; details.setAttribute('aria-label', 'Detalle del nodo seleccionado'); details.setAttribute('aria-live', 'polite'); renderNetworkTopology(data, canvas, details); mapCard.appendChild(canvas);
            const legend = makeElement('div', 'network-legend'); [['legend-interface', 'Interfaz'], ['legend-gateway', 'Gateway'], ['legend-live', 'Respondió ICMP'], ['', 'Vecino en caché']].forEach(([kind, label]) => { const entry = makeElement('span'); entry.append(makeElement('i', kind), document.createTextNode(label)); legend.appendChild(entry); }); mapCard.appendChild(legend); layout.append(mapCard, details); main.appendChild(layout);

            const sections = makeElement('div', 'network-sections');
            const interfaceSection = createNetworkSection(`Interfaces detectadas (${data.interfaces.length})`, 'Todas las direcciones se mantienen separadas por interfaz, incluida IPv6.');
            const interfaceGrid = makeElement('div', 'network-interface-grid'); (data.interfaces || []).forEach(item => { const card = makeElement('article', 'network-interface-card'); const title = makeElement('div', 'network-interface-title'); title.append(makeElement('strong', '', item.name), makeElement('span', `network-state-pill${item.state === 'up' ? ' up' : ''}`, networkHuman(item.state))); card.appendChild(title); (item.addresses || []).forEach(address => card.appendChild(makeElement('div', 'network-address', `${address.cidr} · ${networkHuman(address.scope)}`))); if (!(item.addresses || []).length) card.appendChild(makeElement('div', 'network-address', 'Sin dirección asignada')); const meta = makeElement('div', 'network-interface-meta'); [`${item.kind}`, `MTU ${item.mtu || '—'}`, `MAC ${item.mac || '—'}`, `RX ${networkFormatBytes(item.stats?.rx_bytes)}`, `TX ${networkFormatBytes(item.stats?.tx_bytes)}`].forEach(value => meta.appendChild(makeElement('span', '', value))); card.appendChild(meta); interfaceGrid.appendChild(card); }); interfaceSection.appendChild(interfaceGrid); sections.appendChild(interfaceSection);

            const hostSection = createNetworkSection(`Activos y vecinos (${data.hosts.length})`, 'Incluye direcciones locales, gateways, caché ARP/ND y respuestas del descubrimiento. No se realizan consultas DNS.');
            const searchLabel = makeElement('label', 'network-table-filter-label', 'Filtrar esta tabla de activos'); searchLabel.htmlFor = 'networkHostFilter';
            const search = makeElement('input', 'network-table-search'); search.id = 'networkHostFilter'; search.type = 'search'; search.placeholder = 'IP, MAC, interfaz, estado o fuente…'; hostSection.append(searchLabel, search);
            const allHostRows = (data.hosts || []).map(item => [item.address, item.family, item.is_self ? 'Local' : (item.is_gateway ? 'Gateway' : (item.responded ? 'ICMP' : 'Vecino')), item.mac, (item.interfaces || []).join(', '), networkHuman(item.state), (item.sources || []).map(networkHuman).join(', ')]);
            const hostRows = allHostRows.slice(0, 256);
            const hostTable = createNetworkTable(allHostRows.length > hostRows.length ? `Inventario de direcciones y activos observados · mostrando 256 de ${allHostRows.length}` : 'Inventario de direcciones y activos observados', ['Dirección', 'Familia', 'Tipo', 'MAC', 'Interfaz', 'Estado', 'Fuente'], hostRows); hostSection.appendChild(hostTable);
            const filterCount = makeElement('div', 'audit-result-count', `${hostRows.length} fila(s) visibles`); hostSection.appendChild(filterCount);
            search.addEventListener('input', () => { const query = search.value.trim().toLowerCase(); let visible = 0; hostTable.querySelectorAll('tbody tr').forEach(row => { row.hidden = query !== '' && !row.textContent.toLowerCase().includes(query); if (!row.hidden) visible++; }); filterCount.textContent = `${visible} fila(s) visibles`; }); sections.appendChild(hostSection);

            const routeSection = createNetworkSection(`Rutas del namespace (${data.routes.length})`, 'Las rutas sin gateway y scope link determinan qué redes pueden ser elegibles; la allowlist del servidor restringe aún más el sondeo.');
            const routeRows = (data.routes || []).slice(0, 256).map(route => [route.family, route.table, route.destination, route.gateway, route.device, route.scope, route.protocol, route.metric]);
            routeSection.appendChild(createNetworkTable((data.routes || []).length > routeRows.length ? `Rutas IPv4 e IPv6 · mostrando 256 de ${data.routes.length}` : 'Rutas IPv4 e IPv6 de todas las tablas', ['Familia', 'Tabla', 'Destino', 'Gateway', 'Interfaz', 'Scope', 'Protocolo', 'Métrica'], routeRows)); sections.appendChild(routeSection);

            const routingRuleRows = (data.rules || []).slice(0, 256).map(rule => [rule.family, rule.priority, rule.from, rule.to, rule.table, rule.fwmark, rule.iif, rule.oif, rule.action]);
            const routingRuleSection = createNetworkSection(`Policy routing (${(data.rules || []).length})`, 'Reglas que pueden seleccionar tablas distintas de main en servidores multihomed, VRF o VPN.');
            routingRuleSection.appendChild(createNetworkTable('Reglas de selección de ruta IPv4 e IPv6', ['Familia', 'Prioridad', 'Desde', 'Hacia', 'Tabla', 'Marca', 'Entrada', 'Salida', 'Acción'], routingRuleRows)); sections.appendChild(routingRuleSection);

            const neighborRows = (data.neighbors || []).slice(0, 256).map(item => [item.address, item.family, item.mac, item.device, networkHuman(item.state), item.router ? 'sí' : 'no', networkHuman(item.source)]);
            const neighborSection = createNetworkSection(`Vecinos ARP/ND (${data.neighbors.length})`, 'Estado crudo de la caché del kernel. FAILED o INCOMPLETE se conserva para diagnóstico; STALE no se considera por sí solo una vulnerabilidad.');
            neighborSection.appendChild(createNetworkTable((data.neighbors || []).length > neighborRows.length ? `Caché de vecinos · mostrando 256 de ${data.neighbors.length}` : 'Caché de vecinos del namespace', ['Dirección', 'Familia', 'MAC', 'Interfaz', 'Estado', 'Router', 'Fuente'], neighborRows)); sections.appendChild(neighborSection);

            if (capabilities.rawObservability) {
                const connectionSection = createNetworkSection(`Sockets observados (${connections.length})`, 'Datos locales de ss; una conexión o bind global no confirma exposición desde Internet.');
                connectionSection.appendChild(createNetworkTable('Conexiones y listeners visibles al proceso PHP', ['Protocolo', 'Estado', 'Local', 'Remoto', 'Proceso'], (connections || []).map(item => [item.proto, item.state, item.local, item.foreign, item.proc]))); sections.appendChild(connectionSection);
            }
            const sourceSection = createNetworkSection('Cobertura de fuentes', 'Una fuente parcial o ausente no se interpreta como red vacía.');
            sourceSection.appendChild(createNetworkTable('Colectores utilizados', ['Fuente', 'Estado', 'Método', 'Registros'], (data.sources || []).map(source => [source.id, networkHuman(source.status), source.method, source.count]))); sections.appendChild(sourceSection);
            main.appendChild(sections);
        }

        async function loadDisks() {
            const data = await apiFetch(`${API}?api=sysinfo`);
            if (!data.disks.length) {
                document.querySelector('.main-content').innerHTML = '<div class="error-box">[!] No disk data</div>';
                return;
            }
            let html = `<table class="tbl"><thead><tr><th>Device</th><th>Size</th><th>Used</th><th>Avail</th><th>Use%</th><th>Mount</th></tr></thead><tbody>`;
            data.disks.forEach(d => {
                html += `<tr><td>${escapeHtml(d.dev)}</td><td>${escapeHtml(d.size)}</td><td>${escapeHtml(d.used)}</td><td>${escapeHtml(d.avail)}</td><td>${Number(d.pct)}%</td><td>${escapeHtml(d.mount)}</td></tr>`;
            });
            html += `</tbody></table>`;
            document.querySelector('.main-content').innerHTML = html;
        }

        async function loadFileBrowser(path) {
            const data = await apiFetch(`${API}?api=filebrowser&path=${encodeURIComponent(path)}`);
            currentPath = data.path;
            if (currentSection !== 'files') return;
            const main = document.querySelector('.main-content');
            const pathBar = makeElement('div', 'fb-path');
            pathBar.appendChild(makeElement('strong', '', 'RUTA'));
            const input = makeElement('input');
            input.id = 'pathInput';
            input.value = data.path;
            input.setAttribute('aria-label', 'Ruta del explorador');
            input.addEventListener('keydown', event => { if (event.key === 'Enter') loadFileBrowser(input.value); });
            pathBar.appendChild(input);
            const go = makeElement('button', 'btn btn-sm', 'Abrir');
            go.type = 'button';
            go.addEventListener('click', () => loadFileBrowser(input.value));
            pathBar.appendChild(go);
            if (capabilities.fileWrite) {
                const folder = makeElement('button', 'btn btn-sm btn-cyan', 'Nueva carpeta');
                folder.type = 'button';
                folder.addEventListener('click', () => createBrowserEntry('mkdir'));
                pathBar.appendChild(folder);
                const file = makeElement('button', 'btn btn-sm btn-cyan', 'Nuevo archivo');
                file.type = 'button';
                file.addEventListener('click', () => createBrowserEntry('touch'));
                pathBar.appendChild(file);
            }

            const wrapper = makeElement('div', 'audit-table-wrap');
            const table = makeElement('table', 'tbl');
            const caption = makeElement('caption', 'muted', `Contenido de ${data.path}`);
            caption.style.textAlign = 'left';
            caption.style.padding = '8px';
            table.appendChild(caption);
            const thead = document.createElement('thead');
            const headRow = document.createElement('tr');
            ['Nombre', 'Tamaño', 'Propietario', 'Permisos', 'Modificado', 'Acción'].forEach(label => {
                const th = makeElement('th', '', label); th.scope = 'col'; headRow.appendChild(th);
            });
            thead.appendChild(headRow);
            table.appendChild(thead);
            const tbody = document.createElement('tbody');
            data.items.forEach(item => {
                const row = document.createElement('tr');
                const nameCell = document.createElement('td');
                const target = item.dir && item.name === '..' ? (data.path.substring(0, data.path.lastIndexOf('/')) || data.path) : item.path;
                const open = makeElement('button', 'btn btn-sm', `${item.dir ? '◇' : '□'} ${item.name}`);
                open.type = 'button';
                if (item.sensitive) { open.disabled = true; open.title = 'Contenido protegido por política'; }
                else open.addEventListener('click', () => item.dir ? loadFileBrowser(target) : viewFile(item.path));
                nameCell.appendChild(open);
                row.appendChild(nameCell);
                [item.dir ? '-' : formatBytes(Number(item.size) || 0), item.owner, item.perms, item.mtime].forEach(value => row.appendChild(makeElement('td', '', value)));
                const actionCell = document.createElement('td');
                if (!item.dir && !item.sensitive) {
                    const download = makeElement('button', 'btn btn-sm', 'Descargar');
                    download.type = 'button';
                    download.addEventListener('click', () => downloadFile(item.path));
                    actionCell.appendChild(download);
                } else if (item.sensitive) {
                    actionCell.appendChild(makeElement('span', 'muted', 'Protegido'));
                }
                row.appendChild(actionCell);
                tbody.appendChild(row);
            });
            table.appendChild(tbody);
            wrapper.appendChild(table);
            main.replaceChildren(pathBar, wrapper);
        }

        function formatBytes(bytes) {
            if (bytes >= 1073741824) return (bytes / 1073741824).toFixed(2) + 'G';
            if (bytes >= 1048576) return (bytes / 1048576).toFixed(2) + 'M';
            if (bytes >= 1024) return (bytes / 1024).toFixed(2) + 'K';
            return bytes + 'B';
        }

        window.viewFile = async function (path) {
            let data;
            try { data = await apiFetch(`${API}?api=readfile&path=${encodeURIComponent(path)}`); }
            catch (error) { window.alert(error.message); return; }
            const main = document.querySelector('.main-content');
            const back = makeElement('button', 'btn btn-sm', 'Volver');
            back.type = 'button'; back.style.marginBottom = '10px';
            back.addEventListener('click', () => loadFileBrowser(currentPath));
            const panel = makeElement('section', 'panel');
            const head = makeElement('div', 'panel-head');
            head.appendChild(makeElement('div', 'panel-title mono', path));
            const viewer = makeElement('div', 'file-viewer');
            viewer.appendChild(makeElement('pre', '', data.content || ''));
            panel.append(head, viewer);
            main.replaceChildren(back, panel);
        };

        window.downloadFile = function (path) {
            window.location.href = `${API}?api=download&path=${encodeURIComponent(path)}`;
        };

        async function createBrowserEntry(type) {
            if (!capabilities.fileWrite) return;
            const name = window.prompt(type === 'mkdir' ? 'Nombre de la carpeta' : 'Nombre del archivo');
            if (!name) return;
            try {
                await apiFetch(`${API}?api=${type}`, { method: 'POST', body: createSecureFormData({ path: currentPath, name }) });
                await loadFileBrowser(currentPath);
            } catch (error) { window.alert(error.message); }
        }

        async function loadLogs(type) {
            const data = await apiFetch(`${API}?api=logs&type=${encodeURIComponent(type)}`);
            const logTypes = ['messages', 'secure', 'yum', 'audit', 'cron', 'dmesg', 'journal'];
            const tabs = logTypes.map(t => `<button class="log-tab ${t === type ? 'active' : ''}" data-log-type="${t}">${t.toUpperCase()}</button>`).join('');
            document.querySelector('.main-content').innerHTML = `
                <div class="log-tabs">${tabs}</div>
                <div class="log-viewer"><pre>${escapeHtml(data.data)}</pre></div>
            `;
            document.querySelectorAll('.log-tab').forEach(button => button.addEventListener('click', () => loadLogs(button.dataset.logType)));
        }

        async function loadUsers() {
            const data = await apiFetch(`${API}?api=users`);
            if (!data.length) {
                document.querySelector('.main-content').innerHTML = '<div class="error-box">[!] No user data</div>';
                return;
            }
            let html = `<table class="tbl"><thead><tr><th>Name</th><th>UID</th><th>GID</th><th>Home</th><th>Shell</th></tr></thead><tbody>`;
            data.forEach(u => {
                html += `<tr><td>${escapeHtml(u.name)}</td><td>${Number(u.uid)}</td><td>${Number(u.gid)}</td><td>${escapeHtml(u.home)}</td><td>${escapeHtml(u.shell)}</td></tr>`;
            });
            html += `</tbody></table>`;
            document.querySelector('.main-content').innerHTML = html;
        }

        async function loadServices() {
            const data = await apiFetch(`${API}?api=services`);
            document.querySelector('.main-content').innerHTML = `<div class="log-viewer"><pre>${escapeHtml(data.data)}</pre></div>`;
        }

        async function loadEnv() {
            const data = await apiFetch(`${API}?api=envvars`);
            document.querySelector('.main-content').innerHTML = `<div class="log-viewer"><pre>${escapeHtml(data.data)}</pre></div>`;
        }

        async function loadRecon() {
            document.querySelector('.main-content').innerHTML = `
                <div class="panel">
                    <div class="panel-head"><div class="panel-title">EJECUCIÓN PRIVILEGIADA</div></div>
                    <div class="panel-body">
                        <div style="display:flex; gap:10px; margin-bottom:10px;">
                            <input type="text" id="cmdInput" placeholder="Comando de shell…" style="flex:1; background:rgba(0,0,0,0.5); color:var(--cyan); border:1px solid var(--c3); padding:8px; font-family:var(--mono);">
                            <button id="execReconBtn" class="btn">Ejecutar</button>
                        </div>
                        <pre id="cmdOutput" class="cmd-output" style="min-height:200px; background:#000;"></pre>
                    </div>
                </div>
            `;
            document.getElementById('execReconBtn').addEventListener('click', execReconCmd);
        }

        window.execReconCmd = async function () {
            const cmd = document.getElementById('cmdInput').value;
            const out = document.getElementById('cmdOutput');
            out.innerText = 'Executing...';
            try {
                const fd = createSecureFormData({ cmd: cmd, cwd: '/tmp' });
                const data = await apiFetch(`${API}?api=exec`, { method: 'POST', body: fd });
                out.innerText = data.output || 'No output';
            } catch (e) { out.innerText = 'Error: ' + e.message; }
        };

        // ══════════════════════════════════════════════════════════════════
        // Shell interactiva (estilo kitty): ventana contigua con paneles de
        // terminal dividibles en 1 / 2 / 4 sesiones independientes.
        // ══════════════════════════════════════════════════════════════════
        const shellkitState = {
            tree: null,
            panes: [],
            focus: 0,
            maxPanes: 4
        };
        let shellkitLock = false;

        function shellkitLeafCount(node) {
            if (!node) return 0;
            if (node.k === 'pane') return 1;
            return shellkitLeafCount(node.a) + shellkitLeafCount(node.b);
        }

        function shellkitCollect(node, out) {
            if (!node) return;
            if (node.k === 'pane') { out.push(node.i); return; }
            shellkitCollect(node.a, out);
            shellkitCollect(node.b, out);
        }

        function shellkitReplaceLeaf(node, targetI, replacement) {
            if (node.k === 'pane') return node.i === targetI ? replacement : node;
            node.a = shellkitReplaceLeaf(node.a, targetI, replacement);
            node.b = shellkitReplaceLeaf(node.b, targetI, replacement);
            return node;
        }

        function shellkitRemoveLeaf(node, idx) {
            if (node.k === 'pane') return node.i === idx ? null : node;
            const a = shellkitRemoveLeaf(node.a, idx);
            const b = shellkitRemoveLeaf(node.b, idx);
            if (!a) return b;
            if (!b) return a;
            return { k: 'split', d: node.d, a, b };
        }

        function shellkitShift(node, idx) {
            if (node.k === 'pane') { if (node.i > idx) node.i -= 1; return; }
            shellkitShift(node.a, idx);
            shellkitShift(node.b, idx);
        }

        function shellkitPaneEl(i) {
            return document.querySelector(`.shellkit-pane[data-pane="${i}"]`);
        }

        function shellkitPromptText(pane) {
            return `${pane.user}@${pane.host}:${pane.path} $`;
        }

        function shellkitLog(text) {
            const el = document.getElementById('shellkitMsg');
            if (el) el.textContent = text;
        }

        function shellkitUpdateBadge() {
            const btn = document.getElementById('shellkitQuadBtn');
            if (btn) btn.disabled = shellkitLeafCount(shellkitState.tree) >= shellkitState.maxPanes;
        }

        function shellkitSetFocus(i) {
            shellkitState.focus = i;
            document.querySelectorAll('.shellkit-pane').forEach(el => {
                el.classList.toggle('shellkit-active', Number(el.dataset.pane) === i);
            });
            const el = shellkitPaneEl(i);
            if (el) {
                const input = el.querySelector('.shellkit-input');
                if (input && !input.disabled) input.focus();
            }
            shellkitUpdateBadge();
        }

        async function shellkitNewPane() {
            const data = await apiFetch(`${API}?api=term_init`, { method: 'POST', body: createSecureFormData() });
            if (!data || !data.term_id) throw new Error('No se pudo inicializar la sesión de terminal');
            const pane = {
                i: shellkitState.panes.length,
                termId: data.term_id,
                path: data.cwd || currentPath || '/',
                user: data.user || 'user',
                host: data.host || 'host',
                buffer: '',
                draft: '',
                history: [],
                histIdx: -1,
                busy: false,
                alive: true
            };
            shellkitState.panes.push(pane);
            return pane;
        }

        async function shellkitExec(pane, input) {
            if (!pane || pane.busy || !pane.alive) return;
            const cmd = input.value;
            if (!cmd.trim()) { input.focus(); return; }
            pane.history.push(cmd);
            pane.histIdx = pane.history.length;
            pane.draft = '';
            pane.buffer += `\n$ ${cmd}`;
            input.value = '';
            pane.busy = true;
            input.disabled = true;
            shellkitRefreshPane(pane);
            try {
                const fd = createSecureFormData({ term_id: pane.termId, cmd: cmd });
                const data = await apiFetch(`${API}?api=term_exec`, { method: 'POST', body: fd });
                if (data.output === '__CLEAR__') {
                    pane.buffer = '';
                } else {
                    if (data.output) pane.buffer += '\n' + data.output;
                    if (data.active === false) {
                        pane.alive = false;
                        pane.buffer += '\n[sesión de shell finalizada]';
                    } else if (data.cwd) {
                        pane.path = data.cwd;
                    }
                }
            } catch (e) {
                pane.buffer += `\n[error] ${e.message}`;
            } finally {
                pane.busy = false;
                input.disabled = !pane.alive;
                shellkitRefreshPane(pane);
                if (pane.alive) input.focus();
            }
        }

        function shellkitRefreshPane(pane) {
            const el = shellkitPaneEl(pane.i);
            if (!el) return;
            const head = el.querySelector('.shellkit-pane-head');
            if (head) head.innerHTML = `<span>${escapeHtml(pane.user)}@${escapeHtml(pane.host)}</span><span class="shellkit-path">${escapeHtml(pane.path)}</span><span class="shellkit-num">${pane.i + 1}/${shellkitState.panes.length}</span>`;
            const out = el.querySelector('.shellkit-out');
            if (out) {
                out.textContent = pane.buffer.replace(/^\n/, '');
                out.scrollTop = out.scrollHeight;
            }
            const prompt = el.querySelector('.shellkit-prompt');
            if (prompt) prompt.textContent = shellkitPromptText(pane);
        }

        function shellkitBindPane(el, pane, input) {
            el.addEventListener('mousedown', ev => { if (ev.target !== input) ev.preventDefault(); });
            el.addEventListener('click', () => shellkitSetFocus(pane.i));
            input.addEventListener('focus', () => shellkitSetFocus(pane.i));
            input.addEventListener('input', () => { pane.draft = input.value; });
            input.addEventListener('keydown', ev => {
                if (ev.key === 'Enter') {
                    ev.preventDefault();
                    shellkitExec(pane, input);
                } else if (ev.key === 'ArrowUp') {
                    ev.preventDefault();
                    if (pane.history.length && pane.histIdx > 0) {
                        if (pane.histIdx === pane.history.length) pane.draft = input.value;
                        pane.histIdx -= 1;
                        input.value = pane.history[pane.histIdx];
                    }
                } else if (ev.key === 'ArrowDown') {
                    ev.preventDefault();
                    if (pane.histIdx < pane.history.length) {
                        pane.histIdx += 1;
                        input.value = pane.histIdx === pane.history.length ? pane.draft : pane.history[pane.histIdx];
                    }
                } else if (ev.key === 'Tab') {
                    ev.preventDefault();
                } else if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'l') {
                    ev.preventDefault();
                    input.value = 'clear';
                    shellkitExec(pane, input);
                }
            });
        }

        function shellkitRenderNode(node, container) {
            if (node.k === 'split') {
                const box = document.createElement('div');
                box.className = node.d === 'row' ? 'shellkit-row' : 'shellkit-col';
                shellkitRenderNode(node.a, box);
                shellkitRenderNode(node.b, box);
                container.appendChild(box);
                return;
            }
            const pane = shellkitState.panes[node.i];
            if (!pane) return;
            const el = document.createElement('div');
            el.className = 'shellkit-pane' + (node.i === shellkitState.focus ? ' shellkit-active' : '');
            el.dataset.pane = String(node.i);
            const head = document.createElement('div');
            head.className = 'shellkit-pane-head';
            head.innerHTML = `<span>${escapeHtml(pane.user)}@${escapeHtml(pane.host)}</span><span class="shellkit-path">${escapeHtml(pane.path)}</span><span class="shellkit-num">${node.i + 1}/${shellkitState.panes.length}</span>`;
            const out = document.createElement('div');
            out.className = 'shellkit-out';
            out.textContent = pane.buffer.replace(/^\n/, '');
            const row = document.createElement('div');
            row.className = 'shellkit-input-row';
            const prompt = document.createElement('span');
            prompt.className = 'shellkit-prompt';
            prompt.textContent = shellkitPromptText(pane);
            const input = document.createElement('input');
            input.type = 'text';
            input.className = 'shellkit-input';
            input.autocomplete = 'off';
            input.autocapitalize = 'off';
            input.spellcheck = false;
            input.placeholder = pane.alive ? 'Escribe un comando y pulsa Enter…' : 'Sesión terminada — cierra o reinicia el panel';
            input.disabled = !pane.alive;
            input.value = pane.draft;
            row.append(prompt, input);
            el.append(head, out, row);
            container.appendChild(el);
            shellkitBindPane(el, pane, input);
            out.scrollTop = out.scrollHeight;
        }

        function shellkitRender() {
            const grid = document.getElementById('shellkitGrid');
            if (!grid) return;
            grid.replaceChildren();
            if (shellkitState.tree) shellkitRenderNode(shellkitState.tree, grid);
            const el = shellkitPaneEl(shellkitState.focus);
            if (el) {
                const input = el.querySelector('.shellkit-input');
                if (input && !input.disabled) input.focus();
            }
            shellkitUpdateBadge();
        }

        async function shellkitSplit(dir) {
            if (shellkitLock) return;
            shellkitLock = true;
            try {
                if (shellkitLeafCount(shellkitState.tree) >= shellkitState.maxPanes) {
                    shellkitLog(`Máximo de ${shellkitState.maxPanes} paneles alcanzado`);
                    return;
                }
                const pane = await shellkitNewPane();
                shellkitState.tree = shellkitReplaceLeaf(shellkitState.tree, shellkitState.focus, {
                    k: 'split', d: dir,
                    a: { k: 'pane', i: shellkitState.focus },
                    b: { k: 'pane', i: pane.i }
                });
                shellkitState.focus = pane.i;
                shellkitLog(dir === 'row' ? 'Panel dividido en 2 columnas' : 'Panel dividido en 2 filas');
                shellkitRender();
            } catch (e) {
                shellkitLog(`Error al dividir: ${e.message}`);
            } finally {
                shellkitLock = false;
            }
        }

        async function shellkitQuad() {
            if (shellkitLock) return;
            shellkitLock = true;
            try {
                const current = shellkitLeafCount(shellkitState.tree);
                if (current >= shellkitState.maxPanes) { shellkitLog(`Ya hay ${current} paneles`); return; }
                if (current === 1) {
                    const leaves = [];
                    shellkitCollect(shellkitState.tree, leaves);
                    const root = leaves[0];
                    const n1 = await shellkitNewPane();
                    const n2 = await shellkitNewPane();
                    const n3 = await shellkitNewPane();
                    shellkitState.tree = {
                        k: 'split', d: 'row',
                        a: { k: 'split', d: 'col', a: { k: 'pane', i: root }, b: { k: 'pane', i: n1.i } },
                        b: { k: 'split', d: 'col', a: { k: 'pane', i: n2.i }, b: { k: 'pane', i: n3.i } }
                    };
                    shellkitState.focus = n3.i;
                } else if (current === 2) {
                    const n1 = await shellkitNewPane();
                    const n2 = await shellkitNewPane();
                    const leaves = [];
                    shellkitCollect(shellkitState.tree, leaves);
                    const [i0, i1] = leaves;
                    shellkitState.tree = shellkitReplaceLeaf(shellkitState.tree, i0, { k: 'split', d: 'col', a: { k: 'pane', i: i0 }, b: { k: 'pane', i: n1.i } });
                    shellkitState.tree = shellkitReplaceLeaf(shellkitState.tree, i1, { k: 'split', d: 'col', a: { k: 'pane', i: i1 }, b: { k: 'pane', i: n2.i } });
                    shellkitState.focus = n2.i;
                } else {
                    await shellkitSplit('col');
                    return;
                }
                shellkitLog('Cuadrícula de 4 paneles activada');
                shellkitRender();
            } catch (e) {
                shellkitLog(`Error al crear la cuadrícula: ${e.message}`);
            } finally {
                shellkitLock = false;
            }
        }

        async function shellkitKillPane(pane) {
            if (!pane || !pane.termId) return;
            pane.alive = false;
            try {
                await apiFetch(`${API}?api=term_kill`, { method: 'POST', body: createSecureFormData({ term_id: pane.termId }) });
            } catch (e) { /* sesión ya no válida */ }
        }

        async function shellkitKillAll() {
            const pending = shellkitState.panes.filter(p => p.alive).map(p => p.termId);
            shellkitState.panes.forEach(p => { p.alive = false; });
            for (const termId of pending) {
                try { await apiFetch(`${API}?api=term_kill`, { method: 'POST', body: createSecureFormData({ term_id: termId }) }); } catch (e) { /* ignorar */ }
            }
        }

        function shellkitCleanup() {
            if (!shellkitState.tree && !shellkitState.panes.length) return;
            shellkitState.tree = null;
            const panes = shellkitState.panes.slice();
            shellkitState.panes = [];
            shellkitState.focus = 0;
            panes.forEach(p => {
                if (p && p.alive && p.termId) {
                    apiFetch(`${API}?api=term_kill`, { method: 'POST', body: createSecureFormData({ term_id: p.termId }) }).catch(() => { });
                }
            });
        }

        async function shellkitClosePane() {
            if (shellkitLock) return;
            shellkitLock = true;
            try {
                const idx = shellkitState.focus;
                const pane = shellkitState.panes[idx];
                if (!pane) return;
                await shellkitKillPane(pane);
                if (shellkitState.panes.length === 1) {
                    shellkitState.tree = null;
                    shellkitState.panes = [];
                    shellkitState.focus = 0;
                    await shellkitNewPane();
                    shellkitState.tree = { k: 'pane', i: 0 };
                    shellkitState.focus = 0;
                    shellkitLog('Panel único restaurado');
                } else {
                    shellkitState.panes.splice(idx, 1);
                    shellkitState.tree = shellkitRemoveLeaf(shellkitState.tree, idx);
                    shellkitShift(shellkitState.tree, idx);
                    shellkitState.focus = Math.min(idx, shellkitState.panes.length - 1);
                    shellkitLog('Panel cerrado');
                }
                shellkitRender();
            } catch (e) {
                shellkitLog(`Error al cerrar: ${e.message}`);
            } finally {
                shellkitLock = false;
            }
        }

        async function shellkitReset() {
            if (shellkitLock) return;
            shellkitLock = true;
            try {
                await shellkitKillAll();
                shellkitState.tree = null;
                shellkitState.panes = [];
                shellkitState.focus = 0;
                await shellkitNewPane();
                shellkitState.tree = { k: 'pane', i: 0 };
                shellkitState.focus = 0;
                shellkitLog('Workspace reiniciado');
                shellkitRender();
            } catch (e) {
                shellkitLog(`Error al reiniciar: ${e.message}`);
            } finally {
                shellkitLock = false;
            }
        }

        async function loadInteractiveShell() {
            shellkitCleanup();
            const main = document.querySelector('.main-content');
            main.innerHTML = `
                <div class="shellkit-ws">
                    <div class="shellkit-toolbar">
                        <span class="shellkit-title">SHELL INTERACTIVA</span>
                        <span class="shellkit-msg" id="shellkitMsg">Inicializando…</span>
                        <span class="shellkit-spacer"></span>
                        <button type="button" class="shellkit-btn" data-split="row" title="Dividir en 2 columnas (izquierda/derecha)">▐▌ 2 columnas</button>
                        <button type="button" class="shellkit-btn" data-split="col" title="Dividir en 2 filas (arriba/abajo)">▬ 2 filas</button>
                        <button type="button" class="shellkit-btn" id="shellkitQuadBtn" title="Cuadrícula de 4 paneles">▦ 4 paneles</button>
                        <button type="button" class="shellkit-btn danger" id="shellkitCloseBtn" title="Cerrar el panel activo">✕ Cerrar panel</button>
                        <button type="button" class="shellkit-btn" id="shellkitResetBtn" title="Restablecer a un único panel">⟳ Reiniciar</button>
                    </div>
                    <div class="shellkit-grid" id="shellkitGrid"></div>
                    <div class="shellkit-hint">Enter ejecuta · ↑/↓ historial por panel · Ctrl+L limpia · clic activa un panel · hasta ${shellkitState.maxPanes} paneles simultáneos</div>
                </div>`;
            document.querySelectorAll('.shellkit-btn[data-split]').forEach(btn => {
                btn.addEventListener('click', () => shellkitSplit(btn.dataset.split));
            });
            document.getElementById('shellkitQuadBtn').addEventListener('click', shellkitQuad);
            document.getElementById('shellkitCloseBtn').addEventListener('click', shellkitClosePane);
            document.getElementById('shellkitResetBtn').addEventListener('click', shellkitReset);
            shellkitState.tree = null;
            shellkitState.panes = [];
            shellkitState.focus = 0;
            try {
                await shellkitNewPane();
                shellkitState.tree = { k: 'pane', i: 0 };
                shellkitState.focus = 0;
                shellkitLog('Listo — usa los botones para dividir');
                shellkitRender();
            } catch (e) {
                main.replaceChildren(makeElement('div', 'error-box', `No se pudo inicializar la shell interactiva: ${e.message}`));
            }
        }

        function loadAuditLanding() {
            if (auditState.report) {
                renderAuditReport(auditState.report);
                return;
            }
            const main = document.querySelector('.main-content');
            const intro = makeElement('section', 'audit-intro');
            intro.appendChild(makeElement('div', 'audit-kicker', 'Postura de seguridad · análisis local'));
            intro.appendChild(makeElement('h1', '', 'Auditoría profunda, evidencia redactada.'));
            intro.appendChild(makeElement('p', '', 'Analiza cuentas y sesiones, contraseñas vacías o débiles, secretos expuestos, privilegios, permisos, SSH, límites de acceso, servicios, red, firewall y la propia configuración del panel. No rompe hashes, no explota servicios y no envía secretos fuera del servidor.'));
            const actions = makeElement('div', 'audit-actions');
            const run = makeElement('button', 'audit-run-btn', 'Ejecutar auditoría ahora');
            run.type = 'button'; run.addEventListener('click', runAudit);
            actions.appendChild(run);
            intro.appendChild(actions);
            const scope = makeElement('div', 'audit-scope');
            ['Cuentas y actividad', 'Contraseñas y secretos', 'Privilegios y permisos', 'SSH y acceso sin límites', 'Red y servicios expuestos', 'Protección del host y PHP'].forEach(label => scope.appendChild(makeElement('span', '', label)));
            intro.appendChild(scope);
            const note = makeElement('div', 'audit-disclaimer', 'Un control sin permisos suficientes se marca como no verificado. Para comprobar hashes de /etc/shadow sin exponerlos, use un colector local privilegiado; el panel nunca devuelve el hash.');
            intro.appendChild(note);
            main.replaceChildren(intro);
        }

        async function runAudit() {
            if (auditState.running) return;
            auditState.running = true;
            currentSection = 'audit';
            setActiveBtn('audit');
            const main = document.querySelector('.main-content');
            main.setAttribute('aria-busy', 'true');
            main.innerHTML = '<div class="audit-progress"><div class="audit-progress-ring"></div><h2>Analizando la postura del host</h2><p>Cuentas · accesos · secretos · permisos · SSH · red · servicios</p></div>';
            try {
                const report = await apiFetch(`${API}?api=audit_run`, { method: 'POST', body: createSecureFormData() });
                auditState.report = report;
                if (currentSection === 'audit') renderAuditReport(report);
            } catch (error) {
                if (auditState.report) {
                    renderAuditReport(auditState.report);
                    const warning = makeElement('div', 'error-box', `No se pudo repetir la auditoría: ${error.message}`);
                    main.prepend(warning);
                } else {
                    main.replaceChildren(makeElement('div', 'error-box', `La auditoría no pudo completarse: ${error.message}`));
                }
            } finally {
                auditState.running = false;
                main.setAttribute('aria-busy', 'false');
            }
        }

        function auditSeverityLabel(value) {
            return ({ critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja', info: 'Info' })[value] || 'Info';
        }

        function auditStatusLabel(value) {
            return ({ pass: 'Aprobado', fail: 'Fallo', warn: 'Advertencia', skipped: 'No verificado', error: 'Error' })[value] || value;
        }

        function auditCategoryLabel(value) {
            return ({ accounts: 'Cuentas', credentials: 'Credenciales', privileges: 'Privilegios', permissions: 'Permisos', access_control: 'Accesos', network: 'Red', host: 'Host', panel: 'Panel' })[value] || value;
        }

        function renderAuditReport(report) {
            const main = document.querySelector('.main-content');
            main.replaceChildren();
            const hero = makeElement('section', 'audit-hero');
            const scoreCard = makeElement('div', 'score-card');
            const score = Math.max(0, Math.min(100, Number(report.summary.score) || 0));
            const ring = makeElement('div', 'score-ring');
            ring.style.setProperty('--score', score);
            ring.style.setProperty('--score-color', score >= 80 ? 'var(--green)' : (score >= 60 ? 'var(--orange)' : 'var(--red)'));
            ring.appendChild(makeElement('span', 'score-value', score));
            const scoreCopy = makeElement('div', 'score-copy');
            scoreCopy.appendChild(makeElement('strong', '', `Grado ${report.summary.grade}`));
            scoreCopy.appendChild(makeElement('span', '', 'Puntuación de postura / 100'));
            ring.setAttribute('aria-label', `Puntuación ${score} de 100`);
            scoreCard.append(ring, scoreCopy);
            const summary = makeElement('div', 'audit-summary-card');
            summary.appendChild(makeElement('div', 'audit-kicker', `Riesgo ${String(report.summary.risk_level).toUpperCase()}`));
            summary.appendChild(makeElement('h1', '', `${report.summary.finding_count} hallazgo(s) · ${report.coverage.percent}% de cobertura`));
            summary.appendChild(makeElement('p', '', 'Priorice los controles críticos y altos. La cobertura se muestra por separado para que un chequeo omitido nunca parezca seguro.'));
            const meta = makeElement('div', 'audit-meta');
            meta.appendChild(makeElement('span', '', `ID ${report.scan.id}`));
            meta.appendChild(makeElement('span', '', `${report.scan.duration_ms} ms`));
            meta.appendChild(makeElement('span', '', report.scan.finished_at));
            meta.appendChild(makeElement('span', '', `Solo lectura: ${report.scan.read_only ? 'sí' : 'no'}`));
            summary.appendChild(meta);
            const actions = makeElement('div', 'audit-actions');
            const rerun = makeElement('button', 'audit-run-btn', 'Volver a analizar'); rerun.type = 'button'; rerun.addEventListener('click', runAudit);
            const download = makeElement('button', 'audit-outline-btn', 'Exportar JSON'); download.type = 'button'; download.addEventListener('click', exportAuditReport);
            const print = makeElement('button', 'audit-outline-btn', 'Imprimir informe'); print.type = 'button'; print.addEventListener('click', () => window.print());
            actions.append(rerun, download, print); summary.appendChild(actions);
            hero.append(scoreCard, summary); main.appendChild(hero);

            const metrics = makeElement('section', 'audit-metrics');
            const metricData = [
                ['critical', report.summary.counts.critical, 'Críticas'], ['high', report.summary.counts.high, 'Altas'],
                ['medium', report.summary.counts.medium, 'Medias'], ['low', report.summary.counts.low, 'Bajas'],
                ['pass', report.coverage.passed, 'Aprobados'], ['skipped', report.coverage.skipped + report.coverage.errors, 'No verificados']
            ];
            metricData.forEach(([kind, value, label]) => {
                const card = makeElement('div', `audit-metric ${kind}`); card.append(makeElement('strong', '', value), makeElement('span', '', label)); metrics.appendChild(card);
            });
            main.appendChild(metrics);

            const toolbar = makeElement('section', 'audit-toolbar');
            const search = makeElement('input'); search.type = 'search'; search.id = 'auditSearch'; search.placeholder = 'Buscar usuario, ruta, IP o control…'; search.setAttribute('aria-label', 'Buscar hallazgos');
            const severity = makeElement('select'); severity.id = 'auditSeverity'; severity.setAttribute('aria-label', 'Filtrar por severidad');
            [['', 'Todas las severidades'], ['critical', 'Crítica'], ['high', 'Alta'], ['medium', 'Media'], ['low', 'Baja'], ['info', 'Informativa']].forEach(([value, label]) => { const option = makeElement('option', '', label); option.value = value; severity.appendChild(option); });
            const category = makeElement('select'); category.id = 'auditCategory'; category.setAttribute('aria-label', 'Filtrar por categoría');
            const categories = [['', 'Todas las categorías'], ...Object.keys(report.categories).sort().map(value => [value, auditCategoryLabel(value)])];
            categories.forEach(([value, label]) => { const option = makeElement('option', '', label); option.value = value; category.appendChild(option); });
            const status = makeElement('select'); status.id = 'auditStatus'; status.setAttribute('aria-label', 'Filtrar por estado');
            [['issues', 'Solo hallazgos'], ['all', 'Todos los controles'], ['pass', 'Aprobados'], ['skipped', 'No verificados']].forEach(([value, label]) => { const option = makeElement('option', '', label); option.value = value; status.appendChild(option); });
            toolbar.append(search, severity, category, status); main.appendChild(toolbar);
            const count = makeElement('div', 'audit-result-count'); count.id = 'auditResultCount'; main.appendChild(count);
            const findings = makeElement('section', 'finding-list'); findings.id = 'auditFindingList'; main.appendChild(findings);
            [search, severity, category, status].forEach(control => control.addEventListener('input', renderAuditFindings));
            renderAuditFindings();
            renderAuditInventories(report, main);
            main.appendChild(makeElement('div', 'audit-disclaimer', (report.coverage_notes || []).join(' ')));
        }

        function renderAuditFindings() {
            const report = auditState.report;
            const list = document.getElementById('auditFindingList');
            if (!report || !list) return;
            const search = (document.getElementById('auditSearch').value || '').trim().toLowerCase();
            const severity = document.getElementById('auditSeverity').value;
            const category = document.getElementById('auditCategory').value;
            const status = document.getElementById('auditStatus').value;
            const weight = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
            const checks = report.checks.filter(check => {
                const statusMatch = status === 'all' || (status === 'issues' && (check.status === 'fail' || check.status === 'warn')) || check.status === status || (status === 'skipped' && check.status === 'error');
                const haystack = `${check.id} ${check.title} ${check.category} ${JSON.stringify(check.evidence)}`.toLowerCase();
                return statusMatch && (!severity || check.severity === severity) && (!category || check.category === category) && (!search || haystack.includes(search));
            }).sort((a, b) => (weight[b.severity] || 0) - (weight[a.severity] || 0));
            list.replaceChildren();
            checks.forEach(check => {
                const details = makeElement('details', 'finding');
                details.dataset.severity = check.severity;
                details.dataset.status = check.status;
                const summary = document.createElement('summary');
                summary.appendChild(makeElement('span', 'severity-pill', `${auditSeverityLabel(check.severity)} · ${auditStatusLabel(check.status)}`));
                summary.appendChild(makeElement('span', 'finding-title', check.title));
                summary.appendChild(makeElement('span', 'finding-id', check.id));
                const body = makeElement('div', 'finding-body');
                const evidenceBox = document.createElement('div'); evidenceBox.appendChild(makeElement('h4', '', `Evidencia redactada · ${auditCategoryLabel(check.category)}`));
                evidenceBox.appendChild(makeElement('pre', '', JSON.stringify(check.evidence, null, 2)));
                const remediationBox = document.createElement('div'); remediationBox.appendChild(makeElement('h4', '', `Remediación · confianza ${check.confidence}`));
                remediationBox.appendChild(makeElement('p', '', check.remediation || 'Revisión manual requerida.'));
                body.append(evidenceBox, remediationBox); details.append(summary, body); list.appendChild(details);
            });
            if (!checks.length) list.appendChild(makeElement('div', 'notice-box', 'No hay controles que coincidan con los filtros.'));
            document.getElementById('auditResultCount').textContent = `${checks.length} de ${report.checks.length} controles visibles`;
        }

        function renderAuditInventories(report, main) {
            const grid = makeElement('section', 'audit-data-grid');
            const accountsCard = makeElement('article', 'audit-data-card'); accountsCard.appendChild(makeElement('h2', '', `Cuentas rastreadas (${(report.inventory.accounts || []).length})`));
            const tableWrap = makeElement('div', 'audit-table-wrap'); const table = makeElement('table', 'audit-account-table');
            const head = document.createElement('thead'); const headRow = document.createElement('tr');
            ['Usuario', 'UID', 'Shell', 'Contraseña', 'Algoritmo', 'Máx. días', 'Claves SSH'].forEach(label => { const th = makeElement('th', '', label); th.scope = 'col'; headRow.appendChild(th); }); head.appendChild(headRow); table.appendChild(head);
            const body = document.createElement('tbody'); (report.inventory.accounts || []).forEach(account => {
                const row = document.createElement('tr'); [account.name, account.uid, account.shell, account.password_state, account.password_algorithm, account.password_max_days ?? '—', account.authorized_key_count ?? 0].forEach(value => row.appendChild(makeElement('td', '', value))); body.appendChild(row);
            }); table.appendChild(body); tableWrap.appendChild(table); accountsCard.appendChild(tableWrap); grid.appendChild(accountsCard);

            const activityCard = makeElement('article', 'audit-data-card'); activityCard.appendChild(makeElement('h2', '', `Actividad del panel (${(report.access.panel_events || []).length})`));
            const eventLines = (report.access.panel_events || []).map(event => `${event.time}  ${event.event}  ${event.ip}  ${event.principal || 'unknown'} (${event.role || 'none'})`);
            activityCard.appendChild(makeElement('pre', '', eventLines.length ? eventLines.join('\n') : 'Sin eventos locales disponibles.')); grid.appendChild(activityCard);
            [['Sesiones activas', report.access.active_sessions], ['Accesos recientes', report.access.recent_logins], ['Intentos fallidos', report.access.failed_logins]].forEach(([title, lines]) => {
                const card = makeElement('article', 'audit-data-card'); card.appendChild(makeElement('h2', '', `${title} (${(lines || []).length})`)); card.appendChild(makeElement('pre', '', (lines || []).join('\n') || 'Sin registros en la fuente disponible.')); grid.appendChild(card);
            });
            main.appendChild(grid);
        }

        function exportAuditReport() {
            if (!auditState.report) return;
            const blob = new Blob([JSON.stringify(auditState.report, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const link = document.createElement('a'); link.href = url; link.download = `sentinelops-audit-${auditState.report.scan.id}.json`; link.click();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        }

        async function loadCentos() {
            const [se, pkg, ver] = await Promise.all([
                apiFetch(`${API}?api=selinux`),
                apiFetch(`${API}?api=packages`),
                apiFetch(`${API}?api=centos_version`)
            ]);
            const seColor = se.enforce === 'Enforcing' ? 'var(--c1)' : (se.enforce === 'Permissive' ? 'var(--orange)' : 'var(--red)');
            document.querySelector('.main-content').innerHTML = `
                <div style="margin-bottom:12px;padding:10px 14px;background:var(--bg2);border:1px solid var(--border);border-radius:4px;">
                    <span style="color:var(--orange);font-weight:bold;">[CENTOS]</span>
                    <span style="opacity:.7;margin-left:10px;">${escapeHtml(ver.data || 'Red Hat / CentOS')}</span>
                </div>
                <div class="dash-grid">
                    <div class="panel">
                        <div class="panel-head"><div class="panel-title">[!] SELINUX</div><div class="panel-badge" style="background:${seColor};">${escapeHtml(se.enforce)}</div></div>
                        <div class="panel-body"><pre style="font-size:.78rem;white-space:pre-wrap;">${escapeHtml(se.status)}</pre></div>
                    </div>
                    <div class="panel">
                        <div class="panel-head"><div class="panel-title">[#] PAQUETES RPM</div><div class="panel-badge">${pkg.total} installed</div></div>
                        <div class="panel-body"><div class="log-viewer" style="max-height:250px;"><pre>${escapeHtml(pkg.recent)}</pre></div></div>
                    </div>
                </div>
            `;
        }

        // Initialize dashboard
        document.addEventListener('DOMContentLoaded', () => {
            document.querySelectorAll('.nav-btn[data-section]').forEach(btn => {
                btn.addEventListener('click', (e) => {
                    const target = e.currentTarget;
                    currentSection = target.dataset.section;
                    if (refreshTimer) clearInterval(refreshTimer);
                    loadSection(currentSection);
                });
            });
            const quickAudit = document.getElementById('quickAuditBtn');
            quickAudit.addEventListener('click', () => { loadSection('audit'); runAudit(); });
            const terminal = document.getElementById('terminalBtn');
            if (terminal) terminal.addEventListener('click', openNewTerminal);
            const updateClock = () => { document.getElementById('hud-clock').textContent = new Date().toLocaleTimeString('es-PE', { hour12: false }); };
            updateClock();
            setInterval(updateClock, 1000);
            loadSection('dashboard');
        });
    </script>
</body>
</html>
