{-# LANGUAGE OverloadedStrings, PackageImports #-}

module Network.Sasl.ScramSha1.Functions (
	storedKey,
	clientKey,
	serverKey,
	clientProof,
	serverSignature,
	clientFirstMessageBare,
	serverFirstMessage,
	clientFinalMessageWithoutProof,
	) where

import Data.Bits

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
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

clientKey :: BS.ByteString -> BS.ByteString -> Int -> BS.ByteString
clientKey ps salt i = hmac SHA1.hash 64 (saltedPassword ps salt i) "Client Key"

storedKey :: BS.ByteString -> BS.ByteString -> Int -> BS.ByteString
storedKey ps salt i = SHA1.hash $ clientKey ps salt i

clientFirstMessageBare :: BS.ByteString -> BS.ByteString -> BS.ByteString
clientFirstMessageBare un nnc = BS.concat ["n=", un, ",r=", nnc]

serverFirstMessage :: BS.ByteString -> BS.ByteString -> Int -> BS.ByteString
serverFirstMessage snnc slt i = BS.concat
	["r=", snnc, ",s=", B64.encode slt, ",i=", BSC.pack $ show i]

clientFinalMessageWithoutProof :: BS.ByteString -> BS.ByteString -> BS.ByteString
clientFinalMessageWithoutProof cb snnc =
	BS.concat ["c=", B64.encode cb, ",r=", snnc]

authMessage :: BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString
	-> BS.ByteString -> Int -> BS.ByteString
authMessage cb un cnnc snnc slt i = BS.concat [
	clientFirstMessageBare un cnnc, ",",
	serverFirstMessage snnc slt i, ",",
	clientFinalMessageWithoutProof cb snnc ]

clientSignature :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Int
	-> BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString
clientSignature un ps slt i cb cnnc snnc =
	hmac SHA1.hash 64 (storedKey ps slt i) (authMessage cb un cnnc snnc slt i)

clientProof :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Int
	-> BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString
clientProof un ps slt i cb cnnc snnc = B64.encode $
	clientKey ps slt i `xo` clientSignature un ps slt i cb cnnc snnc

serverKey :: BS.ByteString -> BS.ByteString -> Int -> BS.ByteString
serverKey ps salt i = hmac SHA1.hash 64 (saltedPassword ps salt i) "Server Key"

serverSignature :: BS.ByteString -> BS.ByteString -> BS.ByteString -> Int
	-> BS.ByteString -> BS.ByteString -> BS.ByteString -> BS.ByteString
serverSignature un ps slt i cb cnnc snnc = B64.encode $ hmac SHA1.hash 64
	(serverKey ps slt i)
	(authMessage cb un cnnc snnc slt i)
