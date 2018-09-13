<?php


/**
 * @file    RSAUtil.php
 * @date    2018/09/13 18:08:33
 * @version $Revision$
 * @brief
 **/
class RSAUtil{

    private $rsaPublicKey = null;
    private $rsaPrivateKey = null;
    private $bits = 0;

    /**
     * constructor.
     *
     * @param string $strPrivateKey 私钥Pem, E.g:
     *                              -----BEGIN RSA PRIVATE KEY-----
     *                              MIICXQIBAAKBgQDb9OqMULAs5oIYpbdq6AdYuA3Cp8HsmYloBEoOFpYB3g/ORwYk
     *                              pm87Jr+ayTAW3f0hOYBbFIpEZQpHz1KNwNedgEX96MVsyeiKB5KijtDqvCCgRL7U
     *                              v5Cbz8K3PD8MCxt2KHO9pw0VXQF4fX8dhZaudAL1T6jLSNcFy71MbWNfwQIDAQAB
     *                              AoGAEF5IegqjIaRBuC3U2WrM6ShBNeQgBUhjtk7jZ+r8XMU2reYRKfcMvf0jMxSX
     *                              tIvug2NxDtYXeAGA41klTpE0Okvu4uzzPBCN4WM2n1ci6aHYuRUG/RYG+Z2hZzxy
     *                              NpF+GIJ7snvaxzOdBGmlxTPlMuRpxxn/Us7K6L90oWgGIbUCQQD42K+BaO6NUm2q
     *                              MaCOunkKKIp1cWeI4w//t5Zw2/3+5O1JMLfA1mOJFUDql12qGY2lbeLf18i4Vgi6
     *                              IBArc5VfAkEA4kef+9nJ/h/nSoi281Gqm78iycmCk6MDnlVOJ6SdoHdPDH+Zhz5A
     *                              HHRF6+u/I9pqk9ykowaPtRrqyF52ioD+3wJBAORedzJcChDHxLycLqzNlKct7WM6
     *                              X7nQJ66V3QpV2hNCJEE25GukVFRJnPmtT9f6+3MGFV83uIzy569oHW7C9CECQG+n
     *                              TAfn1UXx1BzxDOVPPNIRJEdRiX70BwsPqLri/Wx6sqTGKamUS+o+bWoWL4Cve7tu
     *                              Oka/LBX/LC6mffOl5x0CQQCMmBrhpKlOFMt0ObDFfnmvU04+gTP/l5ShwC3n7Iok
     *                              hXVkVTBBA10YoPQgTwxeu0dFVUC3kT56NGUGWZ7ybIJu
     *                              -----END RSA PRIVATE KEY-----
     *
     * @param string $strPublicPem  公钥Pem, E.g:
     *                              -----BEGIN PUBLIC KEY-----
     *                              MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDb9OqMULAs5oIYpbdq6AdYuA3C
     *                              p8HsmYloBEoOFpYB3g/ORwYkpm87Jr+ayTAW3f0hOYBbFIpEZQpHz1KNwNedgEX9
     *                              6MVsyeiKB5KijtDqvCCgRL7Uv5Cbz8K3PD8MCxt2KHO9pw0VXQF4fX8dhZaudAL1
     *                              T6jLSNcFy71MbWNfwQIDAQAB
     *                              -----END PUBLIC KEY-----
     *
     */
    public function __construct($strPrivateKey = null, $strPublicPem = null) {
        if (is_string($strPrivateKey) && !empty($strPrivateKey)) {
            $this->rsaPrivateKey = openssl_get_privatekey($strPrivateKey);
            $this->bits = openssl_pkey_get_details($this->rsaPrivateKey)['bits'];
        }
        if (is_string($strPublicPem) && !empty($strPublicPem)) {
            $this->rsaPublicKey = openssl_get_publickey($strPublicPem);
            $this->bits = openssl_pkey_get_details($this->rsaPublicKey)['bits'];
        }
    }

    /**
     * @return float|int
     */
    private function _calc_encrypt_size() {
        return $this->bits / 8 - 28;

    }

    /**
     * @return float|int
     */
    private function _calc_decrypt_size() {
        return $this->bits / 8;
    }

    /**
     * @param $text
     *
     * @return bool|string
     */
    public function encrypt_with_public_key($text) {
        $tmp = array();
        foreach (str_split($text, $this->_calc_encrypt_size()) as $s) {
            $ok = openssl_public_encrypt($s, $out, $this->rsaPublicKey);
            if ($ok) {
                array_push($tmp, $out);
                continue;
            };
            return false;
        }
        return base64_encode(join('', $tmp));
    }


    /**
     * @param $cipher
     *
     * @return bool|string
     */
    public function decrypt_with_private_key($cipher) {
        $tmp = "";
        foreach (str_split(base64_decode($cipher), $this->_calc_decrypt_size()) as $v) {
            $ok = openssl_private_decrypt($v, $out, $this->rsaPrivateKey);
            if ($ok) {
                $tmp .= $out;
                continue;
            }
            return false;
        }
        return $tmp;
    }


    /**
     * @param int|string $appId
     * @param string     $encryptedBusinessParams
     *
     * @return bool|string
     */
    public function calc_signature($appId, $encryptedBusinessParams) {
        if (openssl_sign(sprintf("%s %s", $appId, $encryptedBusinessParams),
            $rawSignature,
            $this->rsaPrivateKey,
            $signature_alg = OPENSSL_ALGO_SHA1
        )) {
            return base64_encode($rawSignature);
        }
        return false;
    }

    /**
     * @param int|string $appId
     * @param string     $encryptedBusinessParams
     * @param string     $signature
     *
     * @return bool
     */
    public function verify_signature($appId, $encryptedBusinessParams, $signature) {
        $ok = openssl_verify(
            sprintf("%s %s", $appId, $encryptedBusinessParams),
            base64_decode($signature),
            $this->rsaPublicKey,
            $signature_alg = OPENSSL_ALGO_SHA1
        );

        return $ok ? true : false;
    }

}

/* vim: set ts=4 sw=4 sts=4 tw=100 */
