<?php
$db = mysqli_connect("localhost", "dbuser", "dbpass", "dbname");
$result = $db->query('SELECT * FROM users WHERE username="'.safesql($_POST['user']).'" AND active=1');
// $db->query() replies True if there are at least a row (so a user), and False if there are no rows (so no users)
  if ($result) {
// retrieve a row. don't use this code if multiple rows are expected
  $row = mysqli_fetch_row($result);
// hash password using custom algorithm
  $cpass = hash_password($_POST['password']);
// check if received password matches with one stored in the database
  if ($cpass === $row['cpassword']) {
      echo "Welcome $row['username']";
  } else {
    echo "Invalid credentials.";
  } 
  } else {
    echo "Invalid credentials.";  
  }
?>
