#!/opt/php70/bin/php-cgi
<?php
// populating $_GET
//$_GET=parse_str(getenv('QUERY_STRING'));

//  --> this for php without cgi -->
//parse_str(implode('&', array_slice($argv, 1)), $_GET);
$h1=$_GET['hash'];
$p1=$_GET['pass'];

$h2=base64_decode($h1, true);
$p2=base64_decode($p1, true);


// do work

	/**
	 * Formats a password using the current encryption. If the user ID is given
	 * and the hash does not fit the current hashing algorithm, it automatically
	 * updates the hash.
	 *
	 * @param   string   $password  The plaintext password to check.
	 * @param   string   $hash      The hash to verify against.
	 *
	 * @return  boolean  True if the password and hash match, false otherwise
	 *
	 * @since   3.2.1
	 */
	function verifyPassword($password, $hash)
	{
		$match = false;
		// If we are using phpass
		if (strpos($hash, '$P$') === 0)
		{
			// Use PHPass's portable hashes with a cost of 10.
			$phpass = new PasswordHash(10, true);
			$match = $phpass->CheckPassword($password, $hash);
		}
		elseif ($hash[0] == '$')
		{
			// JCrypt::hasStrongPasswordSupport() includes a fallback for us in the worst case
//			JCrypt::hasStrongPasswordSupport();
			$match = password_verify($password, $hash);
		}
		elseif (substr($hash, 0, 8) == '{SHA256}')
		{
			// Check the password
			$parts     = explode(':', $hash);
			$crypt     = $parts[0];
			$salt      = @$parts[1];
			$testcrypt = getCryptedPassword($password, $salt, 'sha256', true);
			$match = $hash == $testcrypt;
		}
		else
		{
			// Check the password
			$parts = explode(':', $hash);
			$crypt = $parts[0];
			$salt  = @$parts[1];
			// Compile the hash to compare
			// If the salt is empty AND there is a ':' in the original hash, we must append ':' at the end
			$testcrypt = md5($password . $salt) . ($salt ? ':' . $salt : (strpos($hash, ':') !== false ? ':' : ''));
			$match = $hash == $testcrypt;
		}
		return $match;
	}

//echo $p1;
//echo "==";
//echo $h1;
//echo "\r\n";

//echo $p2;
//echo "==";
//echo $h2;

if (verifyPassword($p2, $h2))
{
echo "1";
}
else
{
echo "0";
}

?>