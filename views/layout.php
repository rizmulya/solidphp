<?php

use SolidPHP\Section;
use SolidPHP\Debug;
use SolidPHP\Route;
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= Section::yield('title'); ?></title>
</head>

<body>
    <div>
        <nav>
            <ul>
                <li><a href="<?= Route::is('/') ?>">Home</a></li>
                <li><a href="<?= Route::is('/person') ?>">Person</a></li>
                <li><a href="<?= Route::is('/contact') ?>">Contact</a></li>
            </ul>
        </nav>

        <main class="content">
            <?php Section::yield('content'); ?>
        </main>
    </div>

    <?php Section::yield('script'); ?>

    <?= Debug::showResponseTime(microtime(true)) ?>
</body>

</html>