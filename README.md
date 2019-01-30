# PHPEncrypter
PHPEncrypter is an open source library utilising LibSodium to encrypt data between parties and sign data.

# Current Version
1.0.2 - Added base64 mutual translator to allow for encryption of arrays and objects.

# Installation
[LibSodium Installation](http://php.net/manual/en/sodium.installation.php) requries enabling the extension in your php.ini configuration or by compiling your PHP source with the LibSodium configuration option.

Once you have enabled the extension, you can now clone the repository. Simply create a class and use the Cipher.

```php
class MyFirstCipher
{
    use \Cipher\Cipher;
}
```

# Demo Scenario
Here is an example of a real life situation. Bob wants to send Alice a secret message, he encrypts and signs his message. Alice then reads the message.

```php
    public function demo()
    {
        # Issue keys (would be stored in the database and retrieved as needed)
        $bob   = $this->issueKeys();
        $alice = $this->issueKeys();

        # Encrypt a message from Bob to Alice
        $cipher = $this->encrypt($alice->public, $bob->private, 'This is a test message');

        # Sign the message and send
        $bobSig    = $this->issueSignatureKeys();
        $signature = $this->signMessage($cipher->cipher, $bobSig->private);

        # Alice now verifies the message using the signature sent
        if($this->verifySignature($signature, $bobSig->public))
        {
            # Decrypt the message that was also sent along with the signature and nonce
            echo $this->decrypt($alice->private, $bob->public, $cipher->cipher, $cipher->nonce);
        }
    }
```

# Generating your keys
In order to generate your key pair, you must use the `issueKeys()` method. Each user, or party, must have a key pair which is split down into public and private for ease of use.

```php
class MyFirstCipher
{
    use \Cipher\Cipher;
    
    private $userOne = [], $userTwo = [];
    
    public function __construct()
    {
        $this->userOne['kp'] = $this->issueKeys();
        $this->userTwo['kp'] = $this->issueKeys();
    }
}
```

# Encrypting messages
In order to encrypt a message, you must know which user, or party, the message is being sent too. We use the 3rd parties public key to encrypt the data and our own to sign. For example, if userOne wants to send userTwo a message, he can do so like so.

```php
class MyFirstCipher
{
    use \Cipher\Cipher;
    
    private $userOne = [], $userTwo = [];
    
    public function __construct()
    {
        $this->userOne['kp'] = $this->issueKeys();
        $this->userTwo['kp'] = $this->issueKeys();
    }
    
    public function sendMessage()
    {
        return $this->encrypt($this->userTwo['kp']->public, $this->userOne['kp']->private, 'User ones secret message to user two');
    }
}
```

# Decrypting the message
In order to decrypt the message that userOne has sent, we must know who sent the message. Using our private key and the 3rd parties public key, we are able to decrypt the message like so.

```php
class MyFirstCipher
{
    use \Cipher\Cipher;
    
    private $userOne = [], $userTwo = [];
    
    public function __construct()
    {
        $this->userOne['kp'] = $this->issueKeys();
        $this->userTwo['kp'] = $this->issueKeys();
    }
    
    public function sendMessage()
    {
        # Returns an object ->cipher & ->nonce
        return $this->encrypt($this->userTwo['kp']->public, $this->userOne['kp']->private, 'User ones secret message to user two');
    }
    
    public function readMessage($cipher, $nonce)
    {
        return $this->decrypt($this->userTwo['kp']->private, $this->userOne['kp']->public, $cipher, $nonce);
    }
}
```

# Signing the encrypted message
In order to verify that the message came from the user, we can sign the message before sending it.

```php
class MyFirstCipher
{
    use \Cipher\Cipher;
    
    private $userOne = [], $userTwo = [];
    
    public function __construct()
    {
        $this->userOne['kp'] = $this->issueKeys();
        $this->userTwo['kp'] = $this->issueKeys();
        
        # Lets issue signature keys
        $this->userOne['skp'] = $this->issueSignatureKeys();
    }
    
    public function sendMessageAndSign()
    {
        return (object) [
            'cipher'    => ($cipher = $this->encrypt($this->userTwo['kp']->public, $this->userOne['kp']->private, 'User ones secret message to user two')),
            'signature' => $this->signMessage($cipher->cipher, $this->userOne['skp']->private)
        ];
    }
}
```

# Verifying a signature
```php
class MyFirstCipher
{
    use \Cipher\Cipher;
    
    private $userOne = [], $userTwo = [];
    
    public function __construct()
    {
        $this->userOne['kp']  = $this->issueKeys();
        $this->userTwo['kp']  = $this->issueKeys();
        $this->userOne['skp'] = $this->issueSignatureKeys();
    }
    
    public function verifyEncryption($signature)
    {
        return $this->verifySignature($signature, $this->userOne['skp']->public);
    }
}
```
