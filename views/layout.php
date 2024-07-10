<?php

use SolidPHP\Section;
use function SolidPHP\route;
use SolidPHP\Debug;
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
                <li><a href="<?= route('/') ?>">Home</a></li>
                <li><a href="<?= route('/person') ?>">Person</a></li>
                <li><a href="<?= route('/contact') ?>">Contact</a></li>
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