<?php
/**
 * PHP Anti-Scanner
 *
 * Автоматически блокирует IP-адреса, которые обращаются к подозрительным URL.
 * Подходит для подключения в начале 404.php, особенно на WordPress-сайтах.
 */

$json_url = 'https://shell.seotools.workers.dev'; // URL к базе JSON-файла
$local_file = __DIR__ . '/suspicious-paths.json'; // Путь к локальному файлу
$cache_lifetime = 24 * 60 * 60; // 1 день в секундах

// Путь к корневому .htaccess
$htaccess_file = rtrim($_SERVER['DOCUMENT_ROOT'], '/') . '/.htaccess';
// Проверка, нужно ли обновить локальный файл
$need_update = !file_exists($local_file) || (time() - filemtime($local_file) > $cache_lifetime);

if ($need_update) {
// Скачиваем
    $json_data = @file_get_contents($json_url);

    if ($json_data !== false && !empty($json_data)) {
        file_put_contents($local_file, $json_data);
    } else {
        if (file_exists($local_file)) {
            $json_data = file_get_contents($local_file);
        } else {
            die('Error');
        }
    }
} else {
    $json_data = file_get_contents($local_file);
}

// Преобразовываем JSON в PHP-массив
$suspicious_paths = json_decode($json_data, true);

if (!is_array($suspicious_paths)) {
die('Ошибка декодирования JSON.');
}

// Получаем URI
$request_uri = $_SERVER['REQUEST_URI'];

if (in_array($request_uri, $suspicious_paths)) {
    // получаем IP хакера
    $ban = htmlspecialchars(trim($_SERVER['REMOTE_ADDR']), ENT_QUOTES);
    $ban_string = "deny from " . $ban;

    // Если .htaccess нет — создаем
    if (!file_exists($htaccess_file)) {
        file_put_contents($htaccess_file, "order allow,deny\nallow from all\n");
    }

    // Проверяем дубли IP
    $current_htaccess_content = file_get_contents($htaccess_file);

    if (strpos($current_htaccess_content, $ban_string) === false) {
        file_put_contents($htaccess_file, $ban_string . PHP_EOL, FILE_APPEND);
    }

    // Возвращаем 403
    header("HTTP/1.1 403 Forbidden");
    echo "Access forbidden. Your IP has been blocked.";
    exit;
} 
