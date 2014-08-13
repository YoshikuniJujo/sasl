{-# LANGUAGE OverloadedStrings, FlexibleContexts, PackageImports #-}

module Network.Sasl.ScramSha1.Server (salt, scramSha1Server) where

import "monads-tf" Control.Monad.State

import qualified Data.ByteString.Char8 as BSC

import Network.Sasl
import Network.Sasl.ScramSha1.ScramSha1

salt :: BSC.ByteString -> BSC.ByteString -> Int -> (BSC.ByteString, BSC.ByteString)
salt ps slt i = (storedKey sp, serverKey sp)
	where sp = saltedPassword ps slt i

scramSha1Server :: (MonadState m, SaslState (StateType m)) =>
	(BSC.ByteString -> (BSC.ByteString, BSC.ByteString, BSC.ByteString, Int))
		-> Server m
scramSha1Server rt = Server
	(Just clientFirst) [(serverFirst, clientFinal)] (Just $ serverFinal rt)

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

clientFinal :: (MonadState m, SaslState (StateType m)) => Receive m
clientFinal rs = do
	let Just ("n,,", nnc, prf) = readClientFinalMessage rs
	st <- gets getSaslState
	modify . putSaslState $ [
		("client-final-message-without-proof", dropProofBS rs),
		("nonce", nnc),
		("proof", prf) ] ++ st

serverFinal :: (MonadState m, SaslState (StateType m)) =>
	(BSC.ByteString -> (BSC.ByteString, BSC.ByteString, BSC.ByteString, Int))
		-> Send m
serverFinal rt = do
	st <- gets getSaslState
	let	Just un = lookup "username" st
		(_, _, sk, _) = rt un
		Just cfmb = lookup "client-first-message-bare" st
		Just sfm = lookup "server-first-message" st
		Just cfmwop = lookup "client-final-message-without-proof" st
		am = BSC.concat [cfmb, ",", sfm, ",", cfmwop]
	return $ serverFinalMessage sk am
