<?php

namespace Cipher;

/**
 * @author: Kyle Jeynes @ Iezon Solutions <okaydots@gmail.com>
 * @copyright (c) 2019 Kyle Jeynes, All Rights Reserved.
 * @version 1.1.2
 * @description Container for LibSodium extension to allow for robust encryption and signing.
 */

use \Exception;

trait Cipher
{
    /*---------------------------------------------------------------------------*/
    /*                           ENCRYPTION PKI                                  */
    /*---------------------------------------------------------------------------*/

    /**
     * Issues a private and public key ready for encryption and decryption between two parties.
     * @return object
     * @throws Exception
     */
    protected function issueKeys()
    {
        return (object) [
            'private' => sodium_crypto_box_secretkey(($pki = sodium_crypto_box_keypair())),
            'public' => sodium_crypto_box_publickey($pki)
        ];
    }

    /**
     * Encrypts a message based on a 3rd parties public key and 1st party private key.
     * V2 uses base64 mutual translator for arrays and objects to be encrypted.
     * @param string $public
     * @param string $private
     * @param mixed $message
     * @return object
     * @throws Exception
     */
    protected function encrypt($public, $private, $message)
    {
        $cipher = sodium_crypto_box(base64_encode($message), ($nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES)), $this->keyPair($private, $public));

        return (object) [
            'cipher' => $cipher,
            'nonce'  => $nonce
        ];
    }


    /**
     * Decrypts a message based on 1st party private key and 3rd party public key and nonce.
     * V2 uses base64 decoding.
     * @param $private
     * @param $public
     * @param $cipher
     * @param $nonce
     * @return bool|string
     * @throws Exception
     */
    protected function decrypt($private, $public, $cipher, $nonce)
    {
        return base64_decode(sodium_crypto_box_open($cipher, $nonce, $this->keyPair($private, $public)));
    }

    /**
     * Generates a key pair based on private and public keys
     * @param $private
     * @param $public
     * @return string
     * @throws Exception
     */
    private function keyPair($private, $public)
    {
        return sodium_crypto_box_keypair_from_secretkey_and_publickey(
            $private,
            $public
        );
    }

    /*---------------------------------------------------------------------------*/
    /*                           SIGNATURE PKI                                   */
    /*---------------------------------------------------------------------------*/

    /**
     * Issues a set of signature keys.
     * @return object
     * @throws Exception
     */
    protected function issueSignatureKeys()
    {
        return (object) [
            'private' => sodium_crypto_sign_secretkey(($pki = sodium_crypto_sign_keypair())),
            'public'  => sodium_crypto_sign_publickey($pki),
        ];
    }

    /**
     * Sign a message using private key.
     * @param $message
     * @param $private
     * @return string
     * @throws Exception
     */
    protected function signMessage($message, $private)
    {
        return sodium_crypto_sign($message, $private);
    }

    /**
     * Verify that this come from a certain party.
     * @param $signature
     * @param $public
     * @return bool|string
     */
    protected function verifySignature($signature, $public)
    {
        return sodium_crypto_sign_open($signature, $public);
    }
}
