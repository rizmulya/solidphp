<?php

use SolidPHP\Section;
?>

<?php Section::extends(__DIR__ . '/../layout.php'); ?>

<?php Section::set('title', 'Home'); ?>


<?php Section::start('content'); ?>
<h1>Home</h1>
<p>Welcome to the home page!</p>
<?php Section::end('content'); ?>