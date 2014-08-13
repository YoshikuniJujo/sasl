{-# LANGUAGE OverloadedStrings, PackageImports #-}

module Network.Sasl.ScramSha1.ScramSha1 (
	clientFirstMessageBare,
	serverFirstMessage,
	clientFinalMessageWithoutProof,
	serverFinalMessage,

	readClientFirstMessage,
	readServerFirstMessage,
	readClientFinalMessage,
	readServerFinalMessage,

	saltedPassword, clientKey, storedKey, serverKey, clientProof,
	) where

import Control.Applicative

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC
import qualified Data.ByteString.Base64 as B64

import Network.Sasl.ScramSha1.Fields
import Network.Sasl.ScramSha1.Functions

clientFirstMessageBare :: BS.ByteString -> BS.ByteString -> BS.ByteString
clientFirstMessageBare un nnc = BS.concat ["n=", un, ",r=", nnc]

serverFirstMessage :: BS.ByteString -> BS.ByteString -> Int -> BS.ByteString
serverFirstMessage snnc slt i = BS.concat
	["r=", snnc, ",s=", B64.encode slt, ",i=", BSC.pack $ show i]

clientFinalMessageWithoutProof :: BS.ByteString -> BS.ByteString -> BS.ByteString
clientFinalMessageWithoutProof cb snnc =
	BS.concat ["c=", B64.encode cb, ",r=", snnc]

serverFinalMessage :: BS.ByteString -> BS.ByteString -> BS.ByteString
serverFinalMessage sk am = BS.concat ["v=", serverSignature sk am]
--	serverSignature (serverKey $ saltedPassword ps slt i) am ]

readClientFirstMessage :: BS.ByteString -> Maybe (BS.ByteString, BS.ByteString)
readClientFirstMessage rs = case BS.splitAt 3 rs of
	("n,,", rs') -> do
		let kv = readFields rs'
		(,) <$> lookup "n" kv <*> lookup "r" kv
	_ -> Nothing

readServerFirstMessage :: BS.ByteString -> Maybe (BS.ByteString, BS.ByteString, Int)
readServerFirstMessage ch = do
	let kv = readFields ch
	(,,)	<$> lookup "r" kv
		<*> ((\(Right r) -> r) . B64.decode <$> lookup "s" kv)
		<*> (read . BSC.unpack <$> lookup "i" kv)

readClientFinalMessage ::
 	BS.ByteString -> Maybe (BS.ByteString, BS.ByteString, BS.ByteString)
readClientFinalMessage rs = do
	let kv = readFields rs
	(,,)	<$> ((\(Right r) -> r) . B64.decode <$> lookup "c" kv)
		<*> lookup "r" kv
		<*> ((\(Right r) -> r) . B64.decode <$> lookup "p" kv)

readServerFinalMessage :: BS.ByteString -> Maybe BS.ByteString
readServerFinalMessage = lookup "v" . readFields
