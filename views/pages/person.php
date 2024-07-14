<?php

use SolidPHP\Section;
use SolidPHP\Route;
use SolidPHP\CSRF;
use SolidPHP\Flash;
use SolidPHP\Filter;
?>

<?php Section::extends(__DIR__ . '/../layout.php'); ?>

<?php Section::set('title', 'Person'); ?>


<?php Section::start('content'); ?>
<button id="logout">logout</button>
<h1>Person</h1>
<p>Welcome to the Person page!
    <?php if (Flash::has('message')) : ?>
        <b><?= Flash::get('message'); ?></b>
    <?php endif; ?>
</p>
<div id="form">
    <form action="<?= Route::is('/person') ?>" method="POST">
        <?= CSRF::token() ?>
        <input type="text" placeholder="name" name="name">
        <input type="text" placeholder="age" name="age">
        <button type="submit">Add</button>
    </form>
</div>

<p>All persons:</p>
<table>
    <thead>
        <tr>
            <th>No</th>
            <th>Name</th>
            <th>Age</th>
            <th>Action</th>
        </tr>
    </thead>
    <tbody>
        <?php 
        $i = 1;
        foreach ($persons as $person) : ?>
            <tr>
                <td><?= $i++ ?></td>
                <td><?= Filter::out($person['name']) ?></td>
                <td><?= Filter::out($person['age']) ?></td>
                <td>
                    <button onclick="handleEdit('<?= $person['id'] ?>')">
                        Edit
                    </button>
                    <form action="<?= Route::is('/person/') . $person['id'] ?>" method="post">
                        <!-- method="DELETE" -->
                        <?= CSRF::token("DELETE")  ?>
                        <button type="submit">Delete</button>
                    </form>
                </td>
            </tr>
        <?php endforeach; ?>
    </tbody>
</table>
<?php Section::end('content'); ?>


<?php Section::start('script'); ?>
<script>
    const handleEdit = async (id) => {
        // const id = e.target.dataset.id;
        const res = await fetch(`<?= Route::is('/person/') ?>${id}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-TOKEN': '<?= CSRF::getToken() ?>', // send from header
            },
            body: JSON.stringify({
                // _token: '<?= CSRF::getToken() ?>', // or send from body
                id
            })
        });
        const data = await res.json();

        const html = `
        <form action="<?= Route::is('/person/') ?>${id}" method="POST" style="display: inline;">
            <!-- method="PUT" -->
            <?= CSRF::token("PUT") ?>
            <input type="text" placeholder="name" name="name" value="${data.name}">
            <input type="text" placeholder="age" name="age" value="${data.age}">
            <button type="submit">Edit</button>
        </form>
        <button onclick="location.reload()">Cancel</button>
        `;
        document.getElementById('form').innerHTML = html;
    }

    const handleLogout = (() => {
        document.getElementById('logout').addEventListener('click', () => {
            location.href = '<?= Route::is('logout') ?>';
        })
    })();
</script>

<?php Section::end('script'); ?>