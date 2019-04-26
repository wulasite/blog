<html>
<?php
#error_reporting(0); 
$file = $_GET["file"]; 
$payload = $_GET["payload"];
if(!isset($file)){
	echo 'Missing parameter'.'<br>';
}
if(preg_match("/flag/",$file)){
	die('hack attacked!!!');
}
include($file);
if(isset($payload)){  
    $url = parse_url($_SERVER['REQUEST_URI']);
    parse_str($url['query'],$query);
    foreach($query as $value){
        if (preg_match("/flag/",$value)) { 
    	    die('stop hacking!');
    	    exit();
        }
    }
    $payload = unserialize($payload);
}else{ 
   echo "Missing parameters"; 
} 
?>
</html>
