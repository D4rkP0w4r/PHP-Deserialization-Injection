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
 * The function `is_admin()` and ` is_guest()` are same check attribute username and password 
