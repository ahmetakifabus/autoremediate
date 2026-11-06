<?php
// Demo hedefi: kasıtlı olarak zafiyetli PHP. ÇALIŞTIRMAYIN.
$page = $_GET['page'];
include $page . '.php';

$cmd = 'ping -c 1 ' . $_POST['host'];
$out = shell_exec($cmd);

$prefs = unserialize($_COOKIE['prefs']);

$id = $_GET['id'];
$res = mysqli_query($db, "SELECT * FROM users WHERE id = $id");

move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);

echo "Merhaba " . $_GET['name'];

if ($_POST['token'] == $expected) { login(); }

// Güvenli kullanımlar (bulgu üretmemeli):
$safe = intval($_GET['n']);
system('ls ' . escapeshellarg($dir));
$o = unserialize($blob, ['allowed_classes' => false]);
