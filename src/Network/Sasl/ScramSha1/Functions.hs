{-# LANGUAGE OverloadedStrings #-}

module Network.Sasl.ScramSha1.Functions (
	xo, SHA1.hash,

	saltedPassword,
	clientKey,
	storedKey,
	serverKey,

	clientSignature,
	clientProof,
	serverSignature,
	) where

import Data.Bits

import qualified Data.ByteString as BS
import qualified Data.ByteString.Base64 as B64
import qualified Crypto.Hash.SHA1 as SHA1

import Network.Sasl.ScramSha1.Hmac

int1 :: BS.ByteString
int1 = "\0\0\0\1"

xo :: BS.ByteString -> BS.ByteString -> BS.ByteString
"" `xo` b2 = b2
b1 `xo` "" = b1
b1 `xo` b2 = BS.pack $ zipWith xor (BS.unpack b1) (BS.unpack b2)

hi :: BS.ByteString -> BS.ByteString -> Int -> BS.ByteString
hi str salt i =
	foldl1 xo . take i . tail . iterate (hmac SHA1.hash 64 str) $ salt `BS.append` int1

saltedPassword :: BS.ByteString -> BS.ByteString -> Int -> BS.ByteString
saltedPassword = hi

clientKey :: BS.ByteString -> BS.ByteString
clientKey sp = hmac SHA1.hash 64 sp "Client Key"

storedKey :: BS.ByteString -> BS.ByteString
storedKey = SHA1.hash . clientKey

clientSignature :: BS.ByteString -> BS.ByteString -> BS.ByteString
clientSignature = hmac SHA1.hash 64

clientProof :: BS.ByteString -> BS.ByteString -> BS.ByteString
clientProof ck am = B64.encode $ ck `xo` clientSignature (SHA1.hash ck) am

serverKey :: BS.ByteString -> BS.ByteString
serverKey sp = hmac SHA1.hash 64 sp "Server Key"

serverSignature :: BS.ByteString -> BS.ByteString -> BS.ByteString
serverSignature sk am = B64.encode $ hmac SHA1.hash 64 sk am
