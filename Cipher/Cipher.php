<?php

/**
 * @author: Kyle Jeynes @ Iezon Solutions <okaydots@gmail.com>
 * @copyright (c) 2019 Kyle Jeynes, All Rights Reserved.
 */

namespace Cipher\Ciphers;

trait Ciphers
{
    /*---------------------------------------------------------------------------*/
    /*                           ENCRYPTION PKI                                  */
    /*---------------------------------------------------------------------------*/
    /**
     * Issues a private and public key ready for encryption and decryption between two parties.
     * @return object
     * @throws \SodiumException
     */
    protected function issueKeys()
    {
        $pki = sodium_crypto_box_keypair();
        return (object) [
            'private' => sodium_crypto_box_secretkey($pki),
            'public' => sodium_crypto_box_publickey($pki)
        ];
    }
    /**
     * Encrypts a message based on a 3rd parties public key and 1st party private key.
     * @param $public
     * @param $private
     * @param $message
     * @return object
     * @throws \SodiumException
     */
    protected function encrypt($public, $private, $message)
    {
        $cipher = sodium_crypto_box($message, ($nonce = random_bytes(SODIUM_CRYPTO_BOX_NONCEBYTES)), $this->keyPair($private, $public));
        return (object) [
            'cipher' => $cipher,
            'nonce'  => $nonce
        ];
    }
    /**
     * Decrypts a message based on 1st party private key and 3rd party public key and nonce.
     * @param $private
     * @param $public
     * @param $cipher
     * @param $nonce
     * @return bool|string
     * @throws \SodiumException
     */
    protected function decrypt($private, $public, $cipher, $nonce)
    {
        return sodium_crypto_box_open($cipher, $nonce, $this->keyPair($private, $public));
    }
    /**
     * Generates a key pair based on private and public keys
     * @param $private
     * @param $public
     * @return string
     * @throws \SodiumException
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
     * @throws \SodiumException
     */
    protected function issueSignatureKeys()
    {
        $pki = sodium_crypto_sign_keypair();
        return (object) [
            'private' => sodium_crypto_sign_secretkey($pki),
            'public'  => sodium_crypto_sign_publickey($pki),
        ];
    }
    /**
     * Sign a message using private key.
     * @param $message
     * @param $private
     * @return string
     * @throws \SodiumException
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
