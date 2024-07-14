<?php

use SolidPHP\Section;
use SolidPHP\Route;
?>

<?php Section::extends(__DIR__ . '/../layout.php'); ?>

<?php Section::set('title', 'Login'); ?>

<?php Section::start('content'); ?>
<h1>Login</h1>
<form id="loginForm">
    <input type="text" id="username" name="username" placeholder="Username" required>
    <input type="password" id="password" name="password" placeholder="Password" required>
    <button type="submit">Login</button>
</form>
<?php Section::end('content'); ?>

<?php Section::start('script') ?>
<script>
    document.getElementById('loginForm').addEventListener('submit', async function(event) {
        event.preventDefault();

        const formData = new FormData(this);
        const username = formData.get('username');
        const password = formData.get('password');

        try {
            const response = await fetch(`<?= Route::is('/login') ?>`, {
                method: 'POST',
                body: formData,
            });

            if (!response.ok) {
                throw new Error('Login failed.');
            }

            const data = await response.json();
            if (data.status == 'success') {
                location.href = '<?= Route::is('/person') ?>';
            };
        } catch (err) {
            console.error(err.message);
        }
    });
</script>
<?php Section::end('script') ?>