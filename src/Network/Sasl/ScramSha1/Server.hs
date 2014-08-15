{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

module Network.Sasl.ScramSha1.Server (sasl, salt) where

import "monads-tf" Control.Monad.State
import "monads-tf" Control.Monad.Error
import "monads-tf" Control.Monad.Error.Class
import Data.Pipe

import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as BSC

import Network.Sasl
import Network.Sasl.ScramSha1.ScramSha1

sasl :: (
	MonadState m, SaslState (StateType m),
	MonadError m, SaslError (ErrorType m) ) =>
	(BS.ByteString -> m (BS.ByteString, BS.ByteString, BS.ByteString, Int)) -> (
		BSC.ByteString,
		(Bool, Pipe BS.ByteString (Either Success BS.ByteString) m ()) )
sasl rt = ("SCRAM-SHA-1", server $ scramSha1Server rt)

salt :: BSC.ByteString -> BSC.ByteString -> Int -> (BSC.ByteString, BSC.ByteString)
salt ps slt i = (storedKey sp, serverKey sp)
	where sp = saltedPassword ps slt i

scramSha1Server :: (
		MonadState m, SaslState (StateType m),
		MonadError m, Error (ErrorType m) ) =>
	(BSC.ByteString -> m (BSC.ByteString, BSC.ByteString, BSC.ByteString, Int))
		-> Server m
scramSha1Server rt = Server
	(Just clientFirst) [(serverFirst, clientFinal rt)] (Just $ serverFinal rt)

clientFirst :: (MonadState m, SaslState (StateType m)) => Receive m
clientFirst rs = do
	let Just (un, cnnc) = readClientFirstMessage rs
	st <- gets getSaslState
	modify . putSaslState $ [
		("client-first-message-bare", BSC.drop 3 rs),
		("username", un),
		("cnonce", cnnc) ] ++ st

serverFirst :: (MonadState m, SaslState (StateType m)) => Send m
serverFirst = do
	st <- gets getSaslState
	let	Just cnnc = lookup "cnonce" st
		Just snnc = lookup "snonce" st
		Just slt = lookup "salt" st
		Just i = lookup "i" st
		sfm = serverFirstMessage
			(cnnc `BSC.append` snnc) slt (read $ BSC.unpack i)
	modify . putSaslState $ ("server-first-message", sfm) : st
	return sfm

dropProof :: String -> String
dropProof "" = ""
dropProof (',' : 'p' : '=' : _) = ""
dropProof (c : cs) = c : dropProof cs

dropProofBS :: BSC.ByteString -> BSC.ByteString
dropProofBS = BSC.pack . dropProof . BSC.unpack

clientFinal :: (
		MonadState m, SaslState (StateType m),
		MonadError m, Error (ErrorType m) ) =>
	(BSC.ByteString -> m (BSC.ByteString, BSC.ByteString, BSC.ByteString, Int))
		-> Receive m
clientFinal rt rs = do
	st <- gets getSaslState
	let	Just ("n,,", nnc, prf) = readClientFinalMessage rs
		Just un = lookup "username" st
	(_, sk, _, _) <- rt un
	let	Just cfmb = lookup "client-first-message-bare" st
		Just sfm = lookup "server-first-message" st
		cfmwop = dropProofBS rs
		am = BSC.concat [cfmb, ",", sfm, ",", cfmwop]
		cs = clientSignature sk am
		ck = prf `xo` cs
		sk' = hash ck
	unless (sk == sk') . throwError $ strMsg "clientFinal: bad"
	modify . putSaslState $ [
		("client-final-message-without-proof", cfmwop),
		("nonce", nnc),
		("proof", prf),
		("StoredKey", sk),
		("StoredKey'", sk')
		] ++ st

serverFinal :: (MonadState m, SaslState (StateType m)) =>
	(BSC.ByteString -> m (BSC.ByteString, BSC.ByteString, BSC.ByteString, Int))
		-> Send m
serverFinal rt = do
	st <- gets getSaslState
	let	Just un = lookup "username" st
	(_, _, sk, _) <- rt un
	let	Just cfmb = lookup "client-first-message-bare" st
		Just sfm = lookup "server-first-message" st
		Just cfmwop = lookup "client-final-message-without-proof" st
		am = BSC.concat [cfmb, ",", sfm, ",", cfmwop]
	return $ serverFinalMessage sk am
