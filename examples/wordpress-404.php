<?php
/**
 * Пример подключения PHP Anti-Scanner в WordPress 404.php.
 *
 * Поместите anti-scanner.php в папку текущей темы и подключите его
 * в самом начале 404.php, до get_header() и до любого HTML.
 */

require_once __DIR__ . '/anti-scanner.php';

get_header();
?>

<main id="primary" class="site-main">
    <h1>404</h1>
    <p>Страница не найдена.</p>
</main>

<?php
get_footer();
