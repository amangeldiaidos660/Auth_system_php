<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
  <?php 
    require_once('db.php');

    $errors = array();

    if(!empty($_POST['username']) && !empty($_POST['email']) && !empty($_POST['password']) && !empty($_POST['confirm_password'])) {
        $username = $_POST['username'];
        $email = $_POST['email'];
        $password = $_POST['password'];

        // Prepare statement to prevent SQL injection
        $sql = $pdo->prepare("SELECT * FROM users WHERE username = ? OR email = ?");
        $sql->execute([$username, $email]);

        if ($sql->rowCount() > 0) {
            $errors[] = "Пользователь с таким логином или почты уже зарегистрирован";
        } else {
            if ($password !== $_POST['confirm_password']) {
                $errors[] = "Пароли не совпадают";
            } else {
                $password = password_hash($password, PASSWORD_DEFAULT);
                $sql = $pdo->prepare("INSERT INTO users (id, username, email, password) VALUES (NULL, ?, ?, ?)");
                if ($sql->execute([$username, $email, $password])) {
                    $errors[] = "Успешная регистрация!";
                } else {
                    $errors[] = "Ошибка: " . $sql->errorInfo()[2];
                }
            }
        }
    }
  ?>
  <?php
    require_once('db.php');

    session_start();

    if(!empty($_POST['username']) && !empty($_POST['password'])) {
        $username = $_POST['username'];
        $password = $_POST['password'];

        $stmt = $pdo->prepare("SELECT * FROM users WHERE username=:username");
        $stmt->bindValue(':username', $username);
        $stmt->execute();
        $user = $stmt->fetch();

        if ($user && password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            header("Location: index.php");
            exit;
        } else {
            $error = "Неправильный логин или пароль";
        }
    }
  ?>
  <div class="form-container">
    <h2>Регистрация</h2>
    <form method="POST" action="">
        <div>
            <label for="username">Логин:</label>
            <input type="text" name="username" id="username" value="<?php echo isset($_POST['username']) ? $_POST['username'] : ''; ?>">
        </div>
        <div>
            <label for="email">Email:</label>
            <input type="email" name="email" id="email" value="<?php echo isset($_POST['email']) ? $_POST['email'] : ''; ?>">
        </div>
        <div>
            <label for="password">Пароль:</label>
            <input type="password" name="password" id="password" value="">
        </div>
        <div>
            <label for="confirm_password">Подтвердите пароль:</label>
            <input type="password" name="confirm_password" id="confirm_password" value="">
        </div>
        <?php if (!empty($errors)) { ?>
            <div class="errors">
                <?php foreach ($errors as $error) { ?>
                    <p><?php echo $error; ?></p>
                <?php } ?>
            </div>
        <?php } ?>
        <div>
            <button type="submit">Зарегистрироваться</button>
        </div>
    </form>
    <h2>Авторизация</h2>
    <form method="POST" action="">
      <div>
        <label for="username">Логин:</label>
        <input type="text" name="username" id="username">
      </div>
      <div>
        <label for="password">Пароль:</label>
        <input type="password" name="password" id="password">
      </div>
      <div>
        <button type="submit">Войти</button>
      </div>
      <?php if (!empty($error)) { ?>
      <div class="error">
        <?php echo $error; ?>
      </div>
    <?php } ?>
    </form>
  </div>


</body>
</html>